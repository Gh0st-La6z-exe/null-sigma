// =============================================================================
// Sigma Rule Engine — Condition Compiler
// =============================================================================
// Compiles Sigma condition expressions into an evaluable boolean AST.
//
// The Sigma condition language supports:
//   - Identifier references: `selection`, `filter`
//   - Boolean operators: `and`, `or`, `not`
//   - Grouping: `(selection_a or selection_b) and not filter`
//   - Quantifiers: `1 of selection*`, `all of them`, `1 of (sel1, sel2)`
//   - Pipe aggregation: `selection | count() > 5` (parsed but not yet evaluated)
//
// COMPILATION PIPELINE:
//   1. Tokenize: condition string → Vec<Token>
//   2. Parse: tokens → ConditionNode (recursive descent parser)
//   3. The ConditionNode tree is then evaluated against identifier results
//      by the matcher at runtime.
//
// This is a classic expression parser: Pratt parser / recursive descent with
// operator precedence. NOT has highest precedence, then AND, then OR.
// =============================================================================

use crate::types::SearchIdentifier;
use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// AST — The compiled condition tree
// ─────────────────────────────────────────────────────────────────────────────

/// A node in the compiled condition expression tree.
///
/// After parsing, the condition becomes a tree of these nodes that can be
/// evaluated by checking search identifier results.
///
/// Example: `"(selection_a or selection_b) and not filter"`
/// Becomes:
/// ```text
///   And
///   ├── Or
///   │   ├── Identifier("selection_a")
///   │   └── Identifier("selection_b")
///   └── Not
///       └── Identifier("filter")
/// ```
#[derive(Debug, Clone)]
pub enum ConditionNode {
    /// Reference to a named search identifier. Evaluates to true if the
    /// identifier's field conditions match the event.
    Identifier(String),

    /// Boolean AND — both children must be true.
    And(Box<ConditionNode>, Box<ConditionNode>),

    /// Boolean OR — at least one child must be true.
    Or(Box<ConditionNode>, Box<ConditionNode>),

    /// Boolean NOT — child must be false.
    Not(Box<ConditionNode>),

    /// Quantifier: "N of pattern" — at least N identifiers matching the
    /// pattern must be true. `count = 0` means "all of".
    ///
    /// Examples:
    ///   - `1 of selection*` → `OneOf` { count: 1, pattern: "selection*" }
    ///   - `all of them` → `OneOf` { count: 0, identifiers: [all] }
    ///   - `all of selection*` → `OneOf` { count: 0, pattern: "selection*" }
    OneOf {
        /// How many must match. 0 = all.
        count: usize,
        /// Resolved identifier names that match the pattern.
        identifiers: Vec<String>,
    },
}

impl ConditionNode {
    /// Evaluate this condition tree against a set of identifier match results.
    ///
    /// `results` maps identifier name → did it match the event?
    #[must_use]
    pub fn evaluate(&self, results: &HashMap<String, bool>) -> bool {
        match self {
            ConditionNode::Identifier(name) => {
                *results.get(name).unwrap_or(&false)
            }

            ConditionNode::And(left, right) => {
                left.evaluate(results) && right.evaluate(results)
            }

            ConditionNode::Or(left, right) => {
                left.evaluate(results) || right.evaluate(results)
            }

            ConditionNode::Not(inner) => {
                !inner.evaluate(results)
            }

            ConditionNode::OneOf { count, identifiers } => {
                let matched = identifiers
                    .iter()
                    .filter(|name| *results.get(name.as_str()).unwrap_or(&false))
                    .count();

                if *count == 0 {
                    // "all of" — every identifier must match
                    matched == identifiers.len() && !identifiers.is_empty()
                } else {
                    matched >= *count
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tokens — Lexer output
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
enum Token {
    /// An identifier name (e.g., "selection", "filter").
    Ident(String),
    /// `and` keyword.
    And,
    /// `or` keyword.
    Or,
    /// `not` keyword.
    Not,
    /// `(` — open paren.
    LParen,
    /// `)` — close paren.
    RParen,
    /// A number (for "1 of ...", "3 of ...").
    Number(usize),
    /// `of` keyword (for quantifiers).
    Of,
    /// `all` keyword (for "all of ...").
    All,
    /// `them` keyword (for "all of them", "1 of them").
    Them,
    /// Pipe `|` for aggregation expressions (future).
    Pipe,
    /// End of input.
    Eof,
}

// ─────────────────────────────────────────────────────────────────────────────
// Tokenizer
// ─────────────────────────────────────────────────────────────────────────────

/// Tokenize a Sigma condition string.
fn tokenize(input: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut chars = input.chars().peekable();

    while let Some(&ch) = chars.peek() {
        match ch {
            ' ' | '\t' | '\n' | '\r' => {
                chars.next();
            }
            '(' => {
                tokens.push(Token::LParen);
                chars.next();
            }
            ')' => {
                tokens.push(Token::RParen);
                chars.next();
            }
            '|' => {
                tokens.push(Token::Pipe);
                chars.next();
            }
            _ => {
                // Collect a word (identifier or keyword)
                let mut word = String::new();
                while let Some(&c) = chars.peek() {
                    if c.is_alphanumeric() || c == '_' || c == '-' || c == '*' || c == '.' {
                        word.push(c);
                        chars.next();
                    } else {
                        break;
                    }
                }

                if word.is_empty() {
                    // Skip unknown characters
                    chars.next();
                    continue;
                }

                let token = match word.to_lowercase().as_str() {
                    "and" => Token::And,
                    "or" => Token::Or,
                    "not" => Token::Not,
                    "of" => Token::Of,
                    "all" => Token::All,
                    "them" => Token::Them,
                    _ => {
                        // Try to parse as number (for "1 of selection*")
                        if let Ok(n) = word.parse::<usize>() {
                            Token::Number(n)
                        } else {
                            Token::Ident(word)
                        }
                    }
                };
                tokens.push(token);
            }
        }
    }

    tokens.push(Token::Eof);
    tokens
}

// ─────────────────────────────────────────────────────────────────────────────
// Parser — Recursive descent with operator precedence
// ─────────────────────────────────────────────────────────────────────────────

/// Parser state for recursive descent parsing.
struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    /// All known identifier names (for resolving "them" and wildcard patterns).
    known_identifiers: Vec<String>,
}

impl Parser {
    fn new(tokens: Vec<Token>, known_identifiers: Vec<String>) -> Self {
        Parser { tokens, pos: 0, known_identifiers }
    }

    fn peek(&self) -> &Token {
        self.tokens.get(self.pos).unwrap_or(&Token::Eof)
    }

    fn advance(&mut self) -> Token {
        let token = self.tokens.get(self.pos).cloned().unwrap_or(Token::Eof);
        self.pos += 1;
        token
    }

    fn expect(&mut self, expected: &Token) -> Result<(), CompileError> {
        let actual = self.advance();
        if &actual == expected {
            Ok(())
        } else {
            Err(CompileError::UnexpectedToken {
                expected: format!("{expected:?}"),
                got: format!("{actual:?}"),
            })
        }
    }

    /// Parse a complete condition expression.
    /// Entry point — handles the lowest precedence (OR).
    fn parse_expr(&mut self) -> Result<ConditionNode, CompileError> {
        self.parse_or()
    }

    /// OR expression — lowest precedence.
    /// `expr := and_expr ('or' and_expr)*`
    fn parse_or(&mut self) -> Result<ConditionNode, CompileError> {
        let mut left = self.parse_and()?;

        while *self.peek() == Token::Or {
            self.advance(); // consume 'or'
            let right = self.parse_and()?;
            left = ConditionNode::Or(Box::new(left), Box::new(right));
        }

        Ok(left)
    }

    /// AND expression — middle precedence.
    /// `and_expr := not_expr ('and' not_expr)*`
    fn parse_and(&mut self) -> Result<ConditionNode, CompileError> {
        let mut left = self.parse_not()?;

        while *self.peek() == Token::And {
            self.advance(); // consume 'and'
            let right = self.parse_not()?;
            left = ConditionNode::And(Box::new(left), Box::new(right));
        }

        Ok(left)
    }

    /// NOT expression — higher precedence than AND/OR.
    /// `not_expr := 'not' not_expr | primary`
    fn parse_not(&mut self) -> Result<ConditionNode, CompileError> {
        if *self.peek() == Token::Not {
            self.advance(); // consume 'not'
            let inner = self.parse_not()?;
            Ok(ConditionNode::Not(Box::new(inner)))
        } else {
            self.parse_primary()
        }
    }

    /// Primary expression — highest precedence.
    /// `primary := '(' expr ')' | quantifier | identifier`
    fn parse_primary(&mut self) -> Result<ConditionNode, CompileError> {
        match self.peek().clone() {
            Token::LParen => {
                self.advance(); // consume '('
                let expr = self.parse_expr()?;
                self.expect(&Token::RParen)?;
                Ok(expr)
            }

            // "1 of selection*" / "1 of them" / "1 of (sel1, sel2)"
            Token::Number(n) => {
                self.advance(); // consume number
                if *self.peek() == Token::Of {
                    self.advance(); // consume 'of'
                    let identifiers = self.parse_of_target()?;
                    Ok(ConditionNode::OneOf { count: n, identifiers })
                } else {
                    // Just a number as identifier? Shouldn't happen but handle gracefully
                    Err(CompileError::UnexpectedToken {
                        expected: "'of' after number".to_string(),
                        got: format!("{:?}", self.peek()),
                    })
                }
            }

            // "all of them" / "all of selection*"
            Token::All => {
                self.advance(); // consume 'all'
                if *self.peek() == Token::Of {
                    self.advance(); // consume 'of'
                    let identifiers = self.parse_of_target()?;
                    Ok(ConditionNode::OneOf { count: 0, identifiers })
                } else {
                    Err(CompileError::UnexpectedToken {
                        expected: "'of' after 'all'".to_string(),
                        got: format!("{:?}", self.peek()),
                    })
                }
            }

            // Plain identifier: "selection", "filter"
            Token::Ident(name) => {
                self.advance();
                Ok(ConditionNode::Identifier(name))
            }

            ref other => {
                Err(CompileError::UnexpectedToken {
                    expected: "identifier, '(', number, or 'all'".to_string(),
                    got: format!("{other:?}"),
                })
            }
        }
    }

    /// Parse the target of an "of" expression.
    /// Can be: `them`, `selection*`, `(sel1, sel2, sel3)`
    fn parse_of_target(&mut self) -> Result<Vec<String>, CompileError> {
        match self.peek().clone() {
            // "all of them" / "1 of them" — matches ALL identifiers
            Token::Them => {
                self.advance();
                Ok(self.known_identifiers.clone())
            }

            // "1 of selection*" — wildcard pattern
            Token::Ident(pattern) => {
                self.advance();
                Ok(self.resolve_wildcard(&pattern))
            }

            // "1 of (sel1, sel2)" — explicit list
            Token::LParen => {
                self.advance(); // consume '('
                let mut names = Vec::new();
                loop {
                    match self.peek().clone() {
                        Token::Ident(name) => {
                            self.advance();
                            // Resolve wildcards in list items too
                            if name.contains('*') {
                                names.extend(self.resolve_wildcard(&name));
                            } else {
                                names.push(name);
                            }
                        }
                        Token::RParen => {
                            self.advance();
                            break;
                        }
                        Token::Eof => {
                            return Err(CompileError::UnexpectedToken {
                                expected: "')' or identifier".to_string(),
                                got: "end of input".to_string(),
                            });
                        }
                        _ => {
                            // Skip commas and other separators
                            self.advance();
                        }
                    }
                }
                Ok(names)
            }

            ref other => {
                Err(CompileError::UnexpectedToken {
                    expected: "'them', identifier pattern, or '('".to_string(),
                    got: format!("{other:?}"),
                })
            }
        }
    }

    /// Resolve a wildcard pattern against known identifiers.
    /// "selection*" matches "`selection_process`", "`selection_cmdline`", etc.
    fn resolve_wildcard(&self, pattern: &str) -> Vec<String> {
        if !pattern.contains('*') {
            return vec![pattern.to_string()];
        }

        let prefix = pattern.trim_end_matches('*');
        self.known_identifiers
            .iter()
            .filter(|name| name.starts_with(prefix))
            .cloned()
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Compile Errors
// ─────────────────────────────────────────────────────────────────────────────

/// Errors that can occur when compiling a Sigma condition string into an AST.
#[derive(Debug, Clone)]
pub enum CompileError {
    /// The condition parser encountered a token it didn't expect at this position.
    UnexpectedToken {
        /// Description of what the parser expected at this position.
        expected: String,
        /// The token that was actually encountered.
        got: String,
    },
    /// The condition string was empty or contained only whitespace.
    EmptyCondition,
}

impl std::fmt::Display for CompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompileError::UnexpectedToken { expected, got } => {
                write!(f, "Expected {expected}, got {got}")
            }
            CompileError::EmptyCondition => write!(f, "Empty condition expression"),
        }
    }
}

impl std::error::Error for CompileError {}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Compile a Sigma condition expression string into an evaluable AST.
///
/// `identifiers` is the list of search identifiers defined in the detection
/// block — needed to resolve "them" and wildcard patterns.
///
/// # Errors
///
/// Returns [`CompileError::EmptyCondition`] if `condition` is empty or
/// contains only whitespace.
///
/// Returns [`CompileError::UnexpectedToken`] if the condition expression
/// contains a syntax error or references an unknown construct.
pub fn compile_condition(
    condition: &str,
    identifiers: &[SearchIdentifier],
) -> Result<ConditionNode, CompileError> {
    let condition = condition.trim();
    if condition.is_empty() {
        return Err(CompileError::EmptyCondition);
    }

    // Handle pipe aggregation by taking only the pre-pipe part for now.
    // Full aggregation support is tracked for a future release.
    let condition_part = if let Some(pipe_idx) = condition.find('|') {
        // Check if this pipe is inside a quantifier or is a real aggregation pipe
        let before_pipe = &condition[..pipe_idx].trim();
        if before_pipe.is_empty() {
            condition
        } else {
            before_pipe
        }
    } else {
        condition
    };

    let tokens = tokenize(condition_part);
    let known_names: Vec<String> = identifiers.iter().map(|id| id.name.clone()).collect();
    let mut parser = Parser::new(tokens, known_names);
    parser.parse_expr()
}
