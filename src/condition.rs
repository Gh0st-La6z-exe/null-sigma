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
//   - Pipe aggregation (`selection | count() > 5`) is NOT supported — the
//     parser rejects it with a clear error before compilation.
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
    ///   - `all of them` → `OneOf` { count: 0, identifiers: \[all\] }
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
            ConditionNode::Identifier(name) => *results.get(name).unwrap_or(&false),

            ConditionNode::And(left, right) => left.evaluate(results) && right.evaluate(results),

            ConditionNode::Or(left, right) => left.evaluate(results) || right.evaluate(results),

            ConditionNode::Not(inner) => !inner.evaluate(results),

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

    /// Evaluate against a dense `results` slice indexed by identifier position.
    ///
    /// `index` maps identifier name → position in `results`. Used by the engine
    /// hot path to avoid per-rule `HashMap` allocation.
    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn evaluate_vec(&self, results: &[bool], index: &HashMap<String, usize>) -> bool {
        match self {
            ConditionNode::Identifier(name) => index
                .get(name)
                .and_then(|&i| results.get(i))
                .copied()
                .unwrap_or(false),

            ConditionNode::And(left, right) => {
                left.evaluate_vec(results, index) && right.evaluate_vec(results, index)
            }

            ConditionNode::Or(left, right) => {
                left.evaluate_vec(results, index) || right.evaluate_vec(results, index)
            }

            ConditionNode::Not(inner) => !inner.evaluate_vec(results, index),

            ConditionNode::OneOf { count, identifiers } => {
                let matched = identifiers
                    .iter()
                    .filter(|name| {
                        index
                            .get(name.as_str())
                            .and_then(|&i| results.get(i))
                            .copied()
                            .unwrap_or(false)
                    })
                    .count();

                if *count == 0 {
                    matched == identifiers.len() && !identifiers.is_empty()
                } else {
                    matched >= *count
                }
            }
        }
    }

    /// Resolve all identifier names in this condition AST to dense indices in `ident_index`.
    #[must_use]
    pub(crate) fn resolve_indices(
        &self,
        ident_index: &HashMap<String, usize>,
    ) -> Option<ResolvedConditionNode> {
        match self {
            ConditionNode::Identifier(name) => {
                let idx = ident_index.get(name.as_str()).copied()?;
                Some(ResolvedConditionNode::Identifier(idx))
            }
            ConditionNode::And(left, right) => {
                let l = left.resolve_indices(ident_index)?;
                let r = right.resolve_indices(ident_index)?;
                Some(ResolvedConditionNode::And(Box::new(l), Box::new(r)))
            }
            ConditionNode::Or(left, right) => {
                let l = left.resolve_indices(ident_index)?;
                let r = right.resolve_indices(ident_index)?;
                Some(ResolvedConditionNode::Or(Box::new(l), Box::new(r)))
            }
            ConditionNode::Not(inner) => {
                let i = inner.resolve_indices(ident_index)?;
                Some(ResolvedConditionNode::Not(Box::new(i)))
            }
            ConditionNode::OneOf { count, identifiers } => {
                let mut resolved = Vec::with_capacity(identifiers.len());
                for name in identifiers {
                    let idx = ident_index.get(name.as_str()).copied()?;
                    resolved.push(idx);
                }
                Some(ResolvedConditionNode::OneOf {
                    count: *count,
                    identifiers: resolved,
                })
            }
        }
    }
}

/// A condition expression node with identifier names resolved to dense `usize` indices.
///
/// Eliminates runtime `HashMap` lookups and enables lazy short-circuiting:
/// in `A and B`, `B` is never evaluated if `A` is false.
#[derive(Debug, Clone)]
pub(crate) enum ResolvedConditionNode {
    /// Reference to a search identifier by dense index in `CompiledRule::identifiers`.
    Identifier(usize),
    /// Boolean AND — short-circuits if left is false.
    And(Box<ResolvedConditionNode>, Box<ResolvedConditionNode>),
    /// Boolean OR — short-circuits if left is true.
    Or(Box<ResolvedConditionNode>, Box<ResolvedConditionNode>),
    /// Boolean NOT — inverts child result.
    Not(Box<ResolvedConditionNode>),
    /// Quantifier: "N of pattern" with resolved identifier indices.
    OneOf {
        /// How many must match. 0 = all.
        count: usize,
        /// Resolved identifier indices.
        identifiers: Vec<usize>,
    },
}

impl ResolvedConditionNode {
    /// Evaluate this condition tree lazily on demand.
    ///
    /// Identifiers are evaluated via `eval_ident` only when reached by boolean
    /// short-circuiting.
    #[cfg(test)]
    #[inline]
    pub(crate) fn evaluate_lazy<F>(&self, eval_ident: &mut F) -> bool
    where
        F: FnMut(usize) -> bool,
    {
        match self {
            ResolvedConditionNode::Identifier(idx) => eval_ident(*idx),
            ResolvedConditionNode::And(left, right) => {
                left.evaluate_lazy(eval_ident) && right.evaluate_lazy(eval_ident)
            }
            ResolvedConditionNode::Or(left, right) => {
                left.evaluate_lazy(eval_ident) || right.evaluate_lazy(eval_ident)
            }
            ResolvedConditionNode::Not(inner) => !inner.evaluate_lazy(eval_ident),
            ResolvedConditionNode::OneOf { count, identifiers } => {
                if *count == 0 {
                    !identifiers.is_empty() && identifiers.iter().all(|&idx| eval_ident(idx))
                } else {
                    let mut matched = 0usize;
                    let needed = *count;
                    let total = identifiers.len();
                    for (i, &idx) in identifiers.iter().enumerate() {
                        if eval_ident(idx) {
                            matched += 1;
                            if matched >= needed {
                                return true;
                            }
                        }
                        let remaining = total - 1 - i;
                        if matched + remaining < needed {
                            return false;
                        }
                    }
                    false
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Flat Register Decision Tape — Linear Bytecode Condition Representation
// ─────────────────────────────────────────────────────────────────────────────

/// Single instruction in a flat linear decision tape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DecisionOp {
    /// If `eval_ident(ident_idx)` is false, jump to `target`.
    /// Otherwise fall through to `pc + 1`.
    JumpIfFalse { ident_idx: u16, target: u16 },

    /// Quantifier: evaluate identifiers in `quantifier_lists[list_idx]`.
    /// If quantifier condition failed, jump to `target`.
    /// Otherwise fall through to `pc + 1`.
    Quantifier {
        list_idx: u16,
        min_matches: u16,
        target: u16,
    },

    /// Unconditional jump to `target`.
    Jump(u16),

    /// Return match result immediately.
    Return(bool),
}

/// Contiguous linear decision bytecode for rule condition evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DecisionTape {
    pub(crate) ops: Box<[DecisionOp]>,
    pub(crate) quantifier_lists: Box<[Box<[u16]>]>,
}

impl DecisionTape {
    /// Evaluate the decision tape.
    ///
    /// Identifiers are evaluated lazily via `eval_ident` only when reached.
    /// Returns `true` if condition evaluates to true, `false` otherwise.
    #[inline(always)]
    pub(crate) fn evaluate<F>(&self, mut eval_ident: F) -> bool
    where
        F: FnMut(usize) -> bool,
    {
        let ops = &self.ops;
        let mut pc = 0usize;

        while pc < ops.len() {
            match ops[pc] {
                DecisionOp::JumpIfFalse { ident_idx, target } => {
                    if !eval_ident(ident_idx as usize) {
                        pc = target as usize;
                    } else {
                        pc += 1;
                    }
                }
                DecisionOp::Quantifier {
                    list_idx,
                    min_matches,
                    target,
                } => {
                    if !Self::eval_quantifier(
                        &self.quantifier_lists,
                        list_idx,
                        min_matches,
                        &mut eval_ident,
                    ) {
                        pc = target as usize;
                    } else {
                        pc += 1;
                    }
                }
                DecisionOp::Jump(target) => {
                    pc = target as usize;
                }
                DecisionOp::Return(result) => return result,
            }
        }

        false
    }

    #[inline(always)]
    fn eval_quantifier<F>(
        quantifier_lists: &[Box<[u16]>],
        list_idx: u16,
        min_matches: u16,
        eval_ident: &mut F,
    ) -> bool
    where
        F: FnMut(usize) -> bool,
    {
        let list = &quantifier_lists[list_idx as usize];
        if min_matches == 0 {
            if list.is_empty() {
                return false;
            }
            for &id in list.iter() {
                if !eval_ident(id as usize) {
                    return false;
                }
            }
            true
        } else {
            let mut hits = 0u16;
            let total = list.len();
            for (i, &id) in list.iter().enumerate() {
                if eval_ident(id as usize) {
                    hits += 1;
                    if hits >= min_matches {
                        return true;
                    }
                }
                let remaining = (total - 1 - i) as u16;
                if hits + remaining < min_matches {
                    return false;
                }
            }
            false
        }
    }

    /// Compile a resolved condition AST into a flat decision tape.
    #[must_use]
    pub(crate) fn compile(node: &ResolvedConditionNode) -> Self {
        let mut builder = TapeBuilder::new();
        let (truelist, falselist) = builder.compile_node(node);

        let ret_true = builder.emit(DecisionOp::Return(true));
        for jmp in truelist {
            builder.patch(jmp, ret_true);
        }

        let ret_false = builder.emit(DecisionOp::Return(false));
        for jmp in falselist {
            builder.patch(jmp, ret_false);
        }

        builder.optimize();

        Self {
            ops: builder.ops.into_boxed_slice(),
            quantifier_lists: builder.quantifier_lists.into_boxed_slice(),
        }
    }
}

struct TapeBuilder {
    ops: Vec<DecisionOp>,
    quantifier_lists: Vec<Box<[u16]>>,
}

impl TapeBuilder {
    fn new() -> Self {
        Self {
            ops: Vec::new(),
            quantifier_lists: Vec::new(),
        }
    }

    fn emit(&mut self, op: DecisionOp) -> usize {
        let idx = self.ops.len();
        self.ops.push(op);
        idx
    }

    fn patch(&mut self, op_idx: usize, target_idx: usize) {
        let target = target_idx as u16;
        match &mut self.ops[op_idx] {
            DecisionOp::JumpIfFalse { target: t, .. }
            | DecisionOp::Quantifier { target: t, .. }
            | DecisionOp::Jump(t) => *t = target,
            DecisionOp::Return(_) => panic!("Cannot patch return instruction"),
        }
    }

    fn compile_node(&mut self, node: &ResolvedConditionNode) -> (Vec<usize>, Vec<usize>) {
        match node {
            ResolvedConditionNode::Identifier(idx) => {
                let op = self.emit(DecisionOp::JumpIfFalse {
                    ident_idx: *idx as u16,
                    target: 0,
                });
                let jmp = self.emit(DecisionOp::Jump(0));
                (vec![jmp], vec![op])
            }
            ResolvedConditionNode::Not(inner) => {
                let (inner_t, inner_f) = self.compile_node(inner);
                // Swapping truelist and falselist implements boolean NOT
                (inner_f, inner_t)
            }
            ResolvedConditionNode::And(left, right) => {
                let (left_t, mut left_f) = self.compile_node(left);
                let right_start = self.ops.len();
                for jmp in left_t {
                    self.patch(jmp, right_start);
                }
                let (right_t, right_f) = self.compile_node(right);
                left_f.extend(right_f);
                (right_t, left_f)
            }
            ResolvedConditionNode::Or(left, right) => {
                let (mut left_t, left_f) = self.compile_node(left);
                let right_start = self.ops.len();
                for jmp in left_f {
                    self.patch(jmp, right_start);
                }
                let (right_t, right_f) = self.compile_node(right);
                left_t.extend(right_t);
                (left_t, right_f)
            }
            ResolvedConditionNode::OneOf { count, identifiers } => {
                let list: Box<[u16]> = identifiers.iter().map(|&id| id as u16).collect();
                self.quantifier_lists.push(list);
                let list_idx = (self.quantifier_lists.len() - 1) as u16;
                let op = self.emit(DecisionOp::Quantifier {
                    list_idx,
                    min_matches: *count as u16,
                    target: 0,
                });
                let jmp = self.emit(DecisionOp::Jump(0));
                (vec![jmp], vec![op])
            }
        }
    }

    fn optimize(&mut self) {
        // Jump threading: eliminate jumps to jumps and jumps to returns
        let n = self.ops.len();
        for i in 0..n {
            let initial_target = match self.ops[i] {
                DecisionOp::JumpIfFalse { target, .. }
                | DecisionOp::Quantifier { target, .. }
                | DecisionOp::Jump(target) => target,
                DecisionOp::Return(_) => continue,
            };

            let mut dest = initial_target as usize;
            let mut visited = 0;
            while dest < n && visited < n {
                if let DecisionOp::Jump(next_dest) = self.ops[dest] {
                    dest = next_dest as usize;
                    visited += 1;
                } else {
                    break;
                }
            }

            let new_target = dest as u16;
            match &mut self.ops[i] {
                DecisionOp::JumpIfFalse { target, .. }
                | DecisionOp::Quantifier { target, .. }
                | DecisionOp::Jump(target) => *target = new_target,
                DecisionOp::Return(_) => {}
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
    /// `,` — separator in an explicit quantifier list.
    Comma,
    /// A number (for "1 of ...", "3 of ...").
    Number(usize),
    /// `of` keyword (for quantifiers).
    Of,
    /// `all` keyword (for "all of ...").
    All,
    /// `them` keyword (for "all of them", "1 of them").
    Them,
    /// Pipe `|` token — recognised by the tokenizer but rejected by the parser;
    /// pipe aggregation (`selection | count() > 5`) is not supported.
    Pipe,
    /// A character that is not valid condition syntax.
    Invalid(char),
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
            ',' => {
                tokens.push(Token::Comma);
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
                    tokens.push(Token::Invalid(ch));
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

/// Maximum nesting depth for condition expressions before rejection.
pub const MAX_CONDITION_DEPTH: usize = 128;

/// Parser state for recursive descent parsing.
struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    depth: usize,
    /// All known identifier names (for resolving "them" and wildcard patterns).
    known_identifiers: Vec<String>,
}

impl Parser {
    fn new(tokens: Vec<Token>, known_identifiers: Vec<String>) -> Self {
        Parser {
            tokens,
            pos: 0,
            depth: 0,
            known_identifiers,
        }
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
            self.depth += 1;
            if self.depth > MAX_CONDITION_DEPTH {
                return Err(CompileError::ConditionDepthExceeded {
                    max_depth: MAX_CONDITION_DEPTH,
                });
            }
            let inner = self.parse_not();
            self.depth -= 1;
            let inner = inner?;
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
                self.depth += 1;
                if self.depth > MAX_CONDITION_DEPTH {
                    return Err(CompileError::ConditionDepthExceeded {
                        max_depth: MAX_CONDITION_DEPTH,
                    });
                }
                let expr = self.parse_expr();
                self.depth -= 1;
                let expr = expr?;
                self.expect(&Token::RParen)?;
                Ok(expr)
            }

            // "1 of selection*" / "1 of them" / "1 of (sel1, sel2)"
            Token::Number(n) => {
                self.advance(); // consume number
                if *self.peek() == Token::Of {
                    self.advance(); // consume 'of'
                    let identifiers = self.parse_of_target()?;
                    Ok(ConditionNode::OneOf {
                        count: n,
                        identifiers,
                    })
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
                    Ok(ConditionNode::OneOf {
                        count: 0,
                        identifiers,
                    })
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

            ref other => Err(CompileError::UnexpectedToken {
                expected: "identifier, '(', number, or 'all'".to_string(),
                got: format!("{other:?}"),
            }),
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
                    let Token::Ident(name) = self.peek().clone() else {
                        return Err(CompileError::UnexpectedToken {
                            expected: "identifier in explicit quantifier list".to_string(),
                            got: format!("{:?}", self.peek()),
                        });
                    };
                    self.advance();
                    // Resolve wildcards in list items too
                    if name.contains('*') {
                        for resolved in self.resolve_wildcard(&name) {
                            if names.iter().any(|existing| existing == &resolved) {
                                return Err(CompileError::DuplicateQuantifierIdentifier {
                                    name: resolved,
                                });
                            }
                            names.push(resolved);
                        }
                    } else {
                        if names.iter().any(|existing| existing == &name) {
                            return Err(CompileError::DuplicateQuantifierIdentifier { name });
                        }
                        names.push(name);
                    }

                    match self.peek().clone() {
                        Token::RParen => {
                            self.advance();
                            break;
                        }
                        Token::Comma => {
                            self.advance();
                        }
                        ref other => {
                            return Err(CompileError::UnexpectedToken {
                                expected: "',' or ')' after quantifier identifier".to_string(),
                                got: format!("{other:?}"),
                            });
                        }
                    }
                }
                Ok(names)
            }

            ref other => Err(CompileError::UnexpectedToken {
                expected: "'them', identifier pattern, or '('".to_string(),
                got: format!("{other:?}"),
            }),
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// An explicit quantifier list contains the same identifier more than once.
    DuplicateQuantifierIdentifier {
        /// The duplicated identifier name.
        name: String,
    },
    /// The condition nesting depth exceeded [`MAX_CONDITION_DEPTH`].
    ConditionDepthExceeded {
        /// The maximum allowed nesting depth.
        max_depth: usize,
    },
}

impl std::fmt::Display for CompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompileError::UnexpectedToken { expected, got } => {
                write!(f, "Expected {expected}, got {got}")
            }
            CompileError::EmptyCondition => write!(f, "Empty condition expression"),
            CompileError::DuplicateQuantifierIdentifier { name } => {
                write!(f, "Duplicate identifier in quantifier list: {name}")
            }
            CompileError::ConditionDepthExceeded { max_depth } => {
                write!(f, "Condition nesting exceeds maximum depth of {max_depth}")
            }
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

    let tokens = tokenize(condition);
    let known_names: Vec<String> = identifiers.iter().map(|id| id.name.clone()).collect();
    let mut parser = Parser::new(tokens, known_names);
    let node = parser.parse_expr()?;
    if *parser.peek() != Token::Eof {
        return Err(CompileError::UnexpectedToken {
            expected: "end of condition".to_string(),
            got: format!("{:?}", parser.peek()),
        });
    }
    Ok(node)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decision_tape_single_identifier() {
        let node = ResolvedConditionNode::Identifier(0);
        let tape = DecisionTape::compile(&node);

        assert!(tape.evaluate(|idx| idx == 0));
        assert!(!tape.evaluate(|_| false));
    }

    #[test]
    fn test_decision_tape_and() {
        let node = ResolvedConditionNode::And(
            Box::new(ResolvedConditionNode::Identifier(0)),
            Box::new(ResolvedConditionNode::Identifier(1)),
        );
        let tape = DecisionTape::compile(&node);

        // Truth table for A and B:
        for a in [false, true] {
            for b in [false, true] {
                let expected = a && b;
                let actual = tape.evaluate(|idx| if idx == 0 { a } else { b });
                assert_eq!(actual, expected, "Failed for A={a}, B={b}");
            }
        }
    }

    #[test]
    fn test_decision_tape_or() {
        let node = ResolvedConditionNode::Or(
            Box::new(ResolvedConditionNode::Identifier(0)),
            Box::new(ResolvedConditionNode::Identifier(1)),
        );
        let tape = DecisionTape::compile(&node);

        // Truth table for A or B:
        for a in [false, true] {
            for b in [false, true] {
                let expected = a || b;
                let actual = tape.evaluate(|idx| if idx == 0 { a } else { b });
                assert_eq!(actual, expected, "Failed for A={a}, B={b}");
            }
        }
    }

    #[test]
    fn test_decision_tape_not() {
        let node = ResolvedConditionNode::Not(Box::new(ResolvedConditionNode::Identifier(0)));
        let tape = DecisionTape::compile(&node);

        assert!(!tape.evaluate(|idx| idx == 0));
        assert!(tape.evaluate(|_| false));
    }

    #[test]
    fn test_decision_tape_and_not() {
        // selection and not filter
        let node = ResolvedConditionNode::And(
            Box::new(ResolvedConditionNode::Identifier(0)),
            Box::new(ResolvedConditionNode::Not(Box::new(
                ResolvedConditionNode::Identifier(1),
            ))),
        );
        let tape = DecisionTape::compile(&node);

        for a in [false, true] {
            for b in [false, true] {
                let expected = a && !b;
                let actual = tape.evaluate(|idx| if idx == 0 { a } else { b });
                assert_eq!(actual, expected, "Failed for A={a}, B={b}");
            }
        }
    }

    #[test]
    fn test_decision_tape_compound() {
        // (A or B) and not C
        let node = ResolvedConditionNode::And(
            Box::new(ResolvedConditionNode::Or(
                Box::new(ResolvedConditionNode::Identifier(0)),
                Box::new(ResolvedConditionNode::Identifier(1)),
            )),
            Box::new(ResolvedConditionNode::Not(Box::new(
                ResolvedConditionNode::Identifier(2),
            ))),
        );
        let tape = DecisionTape::compile(&node);

        for a in [false, true] {
            for b in [false, true] {
                for c in [false, true] {
                    let expected = (a || b) && !c;
                    let actual = tape.evaluate(|idx| match idx {
                        0 => a,
                        1 => b,
                        2 => c,
                        _ => false,
                    });
                    assert_eq!(actual, expected, "Failed for A={a}, B={b}, C={c}");
                }
            }
        }
    }

    #[test]
    fn test_decision_tape_quantifiers() {
        // 1 of [0, 1, 2]
        let one_of = ResolvedConditionNode::OneOf {
            count: 1,
            identifiers: vec![0, 1, 2],
        };
        let tape_one = DecisionTape::compile(&one_of);

        assert!(!tape_one.evaluate(|_| false));
        assert!(tape_one.evaluate(|idx| idx == 1));
        assert!(tape_one.evaluate(|idx| idx == 0 || idx == 2));

        // all of [0, 1, 2] (count == 0)
        let all_of = ResolvedConditionNode::OneOf {
            count: 0,
            identifiers: vec![0, 1, 2],
        };
        let tape_all = DecisionTape::compile(&all_of);

        assert!(!tape_all.evaluate(|idx| idx == 0 || idx == 1));
        assert!(tape_all.evaluate(|idx| idx < 3));

        // 2 of [0, 1, 2]
        let two_of = ResolvedConditionNode::OneOf {
            count: 2,
            identifiers: vec![0, 1, 2],
        };
        let tape_two = DecisionTape::compile(&two_of);

        assert!(!tape_two.evaluate(|idx| idx == 0));
        assert!(tape_two.evaluate(|idx| idx == 0 || idx == 2));
    }

    #[test]
    fn test_decision_tape_short_circuit() {
        // A and B: if A is false, B MUST NOT be evaluated
        let node = ResolvedConditionNode::And(
            Box::new(ResolvedConditionNode::Identifier(0)),
            Box::new(ResolvedConditionNode::Identifier(1)),
        );
        let tape = DecisionTape::compile(&node);

        let mut b_evaluated = false;
        let res = tape.evaluate(|idx| {
            if idx == 0 {
                false
            } else {
                b_evaluated = true;
                true
            }
        });
        assert!(!res);
        assert!(!b_evaluated, "B was evaluated despite A being false!");

        // A or B: if A is true, B MUST NOT be evaluated
        let node_or = ResolvedConditionNode::Or(
            Box::new(ResolvedConditionNode::Identifier(0)),
            Box::new(ResolvedConditionNode::Identifier(1)),
        );
        let tape_or = DecisionTape::compile(&node_or);

        let mut b_or_evaluated = false;
        let res_or = tape_or.evaluate(|idx| {
            if idx == 0 {
                true
            } else {
                b_or_evaluated = true;
                false
            }
        });
        assert!(res_or);
        assert!(!b_or_or_evaluated(&mut b_or_evaluated));
    }

    fn b_or_or_evaluated(b: &mut bool) -> bool {
        *b
    }

    #[test]
    fn test_decision_tape_matches_ast_lazy() {
        // (A and B) or (C and not D)
        let node = ResolvedConditionNode::Or(
            Box::new(ResolvedConditionNode::And(
                Box::new(ResolvedConditionNode::Identifier(0)),
                Box::new(ResolvedConditionNode::Identifier(1)),
            )),
            Box::new(ResolvedConditionNode::And(
                Box::new(ResolvedConditionNode::Identifier(2)),
                Box::new(ResolvedConditionNode::Not(Box::new(
                    ResolvedConditionNode::Identifier(3),
                ))),
            )),
        );
        let tape = DecisionTape::compile(&node);

        for a in [false, true] {
            for b in [false, true] {
                for c in [false, true] {
                    for d in [false, true] {
                        let eval_fn = |idx: usize| match idx {
                            0 => a,
                            1 => b,
                            2 => c,
                            3 => d,
                            _ => false,
                        };
                        let ast_res = node.evaluate_lazy(&mut eval_fn.clone());
                        let tape_res = tape.evaluate(eval_fn);
                        assert_eq!(
                            tape_res, ast_res,
                            "Disagreement for A={a},B={b},C={c},D={d}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn test_condition_depth_guard() {
        let mut deep_cond = String::from("a");
        for _ in 0..150 {
            deep_cond = format!("({deep_cond})");
        }
        let idents = vec![SearchIdentifier {
            name: "a".to_string(),
            groups: vec![],
        }];
        let res = compile_condition(&deep_cond, &idents);
        assert_eq!(
            res.unwrap_err(),
            CompileError::ConditionDepthExceeded {
                max_depth: MAX_CONDITION_DEPTH
            }
        );
    }
}
