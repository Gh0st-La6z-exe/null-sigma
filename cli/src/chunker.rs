//! Sequential byte chunker for JSONL — buffered `Read` only (no mmap).
//!
//! Cuts on the last safe `\n`. If a line exceeds `max_line_bytes` without a
//! delimiter, yields [`ChunkItem::LineTooLarge`] after draining to the next
//! newline (or EOF). Grows the buffer for lines that span the initial fill.

use std::io::Read;

/// Default initial fill size (1 MiB).
pub const DEFAULT_CHUNK_BYTES: usize = 1024 * 1024;

/// One ordered unit for the sequencing sink.
#[derive(Debug)]
pub enum ChunkItem {
    /// Complete line bytes (each line ends with `\n`, except a final EOF line).
    Data {
        id: u64,
        /// 1-based line number of the first line in `bytes`.
        start_line: u64,
        bytes: Vec<u8>,
    },
    /// A single line exceeded `--max-line-bytes` (payload discarded).
    LineTooLarge { id: u64, line_number: u64 },
}

/// Sequential chunker with monotonic chunk IDs.
pub struct Chunker<R> {
    reader: R,
    buf: Vec<u8>,
    len: usize,
    /// Start of unconsumed data (always ≤ `len`).
    pos: usize,
    next_chunk_id: u64,
    next_line: u64,
    max_line_bytes: usize,
    target_chunk_bytes: usize,
    eof: bool,
}

impl<R: Read> Chunker<R> {
    pub fn new(reader: R, max_line_bytes: usize) -> Self {
        let target = DEFAULT_CHUNK_BYTES.min(max_line_bytes.max(1));
        Self {
            reader,
            buf: vec![0u8; target],
            len: 0,
            pos: 0,
            next_chunk_id: 0,
            next_line: 1,
            max_line_bytes,
            target_chunk_bytes: target,
            eof: false,
        }
    }

    fn take_id(&mut self) -> u64 {
        let id = self.next_chunk_id;
        self.next_chunk_id += 1;
        id
    }

    fn compact(&mut self) {
        if self.pos == 0 {
            return;
        }
        self.buf.copy_within(self.pos..self.len, 0);
        self.len -= self.pos;
        self.pos = 0;
    }

    fn fill(&mut self) -> Result<usize, String> {
        if self.eof {
            return Ok(0);
        }
        self.compact();
        if self.len == self.buf.len() {
            let grow_to = (self.buf.len() * 2)
                .max(self.buf.len() + self.target_chunk_bytes)
                .min(self.max_line_bytes.saturating_add(64));
            if grow_to <= self.buf.len() {
                return Ok(0);
            }
            self.buf.resize(grow_to, 0);
        }
        let n = self
            .reader
            .read(&mut self.buf[self.len..])
            .map_err(|e| format!("read error: {e}"))?;
        if n == 0 {
            self.eof = true;
        } else {
            self.len += n;
        }
        Ok(n)
    }

    fn available(&self) -> &[u8] {
        &self.buf[self.pos..self.len]
    }

    /// Next ordered chunk item, or `Ok(None)` at clean EOF.
    pub fn next_item(&mut self) -> Result<Option<ChunkItem>, String> {
        loop {
            debug_assert!(self.pos <= self.len);

            // Incomplete current line (no newline yet) longer than max?
            let avail = self.available();
            let nl_in_avail = avail.iter().position(|&b| b == b'\n');
            if nl_in_avail.is_none() && avail.len() > self.max_line_bytes {
                return self.drain_oversize_line();
            }

            if let Some(first_nl) = avail.iter().rposition(|&b| b == b'\n') {
                let complete_len = first_nl + 1;
                if complete_len >= self.target_chunk_bytes || self.eof {
                    return Ok(Some(self.take_data_chunk(complete_len)));
                }
                // Try to accumulate a larger chunk.
                let n = self.fill()?;
                if n == 0 {
                    // Recompute after possible compact inside fill.
                    let avail = self.available();
                    if let Some(rel) = avail.iter().rposition(|&b| b == b'\n') {
                        return Ok(Some(self.take_data_chunk(rel + 1)));
                    }
                    // Fall through to eof / more logic.
                } else {
                    continue;
                }
            }

            if self.eof {
                let avail = self.available();
                if avail.is_empty() {
                    return Ok(None);
                }
                if avail.iter().position(|&b| b == b'\n').is_none()
                    && avail.len() > self.max_line_bytes
                {
                    return self.drain_oversize_line();
                }
                if let Some(rel) = avail.iter().rposition(|&b| b == b'\n') {
                    return Ok(Some(self.take_data_chunk(rel + 1)));
                }
                // Final unterminated line.
                if avail.len() > self.max_line_bytes {
                    return self.drain_oversize_line();
                }
                let n = avail.len();
                return Ok(Some(self.take_data_chunk(n)));
            }

            let before = self.len - self.pos;
            let n = self.fill()?;
            if n == 0 && (self.len - self.pos) == before && !self.eof {
                self.eof = true;
            }
        }
    }

    /// Emit `nbytes` from `pos` forward (must be ≤ available).
    fn take_data_chunk(&mut self, nbytes: usize) -> ChunkItem {
        let end = self.pos + nbytes;
        debug_assert!(end <= self.len);
        let bytes = self.buf[self.pos..end].to_vec();
        let start_line = self.next_line;
        self.next_line += count_lines(&bytes);
        self.pos = end;
        ChunkItem::Data {
            id: self.take_id(),
            start_line,
            bytes,
        }
    }

    fn drain_oversize_line(&mut self) -> Result<Option<ChunkItem>, String> {
        let line_number = self.next_line;
        self.next_line += 1;
        let id = self.take_id();

        loop {
            let avail = self.available();
            if let Some(rel) = avail.iter().position(|&b| b == b'\n') {
                self.pos += rel + 1;
                return Ok(Some(ChunkItem::LineTooLarge { id, line_number }));
            }
            // Drop everything held for this line and read more.
            self.pos = 0;
            self.len = 0;
            if self.eof {
                return Ok(Some(ChunkItem::LineTooLarge { id, line_number }));
            }
            let n = self.fill()?;
            if n == 0 && self.eof {
                return Ok(Some(ChunkItem::LineTooLarge { id, line_number }));
            }
            // Still one giant line with no newline — discard buffer and continue.
            if self.available().len() > self.max_line_bytes
                && self.available().iter().all(|&b| b != b'\n')
            {
                self.pos = 0;
                self.len = 0;
            }
        }
    }
}

fn count_lines(bytes: &[u8]) -> u64 {
    if bytes.is_empty() {
        return 0;
    }
    let nls = bytes.iter().filter(|&&b| b == b'\n').count() as u64;
    if bytes.last() == Some(&b'\n') {
        nls
    } else {
        nls + 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn splits_on_newlines_preserves_order() {
        let input = b"{\"a\":1}\n{\"b\":2}\n";
        let mut c = Chunker::new(Cursor::new(&input[..]), 8 * 1024 * 1024);
        match c.next_item().unwrap() {
            Some(ChunkItem::Data {
                id: 0,
                start_line: 1,
                bytes,
            }) => {
                assert_eq!(bytes, input);
            }
            other => panic!("expected data chunk, got {other:?}"),
        }
        assert!(c.next_item().unwrap().is_none());
    }

    #[test]
    fn grows_for_line_longer_than_initial_buffer() {
        let mut line = vec![b'x'; 2 * 1024 * 1024];
        line.push(b'\n');
        let mut c = Chunker::new(Cursor::new(line), 8 * 1024 * 1024);
        match c.next_item().unwrap() {
            Some(ChunkItem::Data { bytes, .. }) => {
                assert!(bytes.len() > DEFAULT_CHUNK_BYTES);
                assert_eq!(*bytes.last().unwrap(), b'\n');
            }
            other => panic!("expected data chunk, got {other:?}"),
        }
        assert!(c.next_item().unwrap().is_none());
    }

    #[test]
    fn oversize_line_yields_marker_then_next_line() {
        let mut data = vec![b'y'; 100];
        data.push(b'\n');
        data.extend_from_slice(br#"{"Image":"C:\\Windows\\System32\\whoami.exe"}"#);
        data.push(b'\n');
        let mut c = Chunker::new(Cursor::new(data), 50);
        match c.next_item().unwrap() {
            Some(ChunkItem::LineTooLarge {
                id: 0,
                line_number: 1,
            }) => {}
            other => panic!("expected oversize, got {other:?}"),
        }
        match c.next_item().unwrap() {
            Some(ChunkItem::Data {
                start_line: 2,
                bytes,
                ..
            }) => {
                assert!(bytes.starts_with(b"{\"Image\""));
            }
            other => panic!("expected data after oversize, got {other:?}"),
        }
        assert!(c.next_item().unwrap().is_none());
    }
}
