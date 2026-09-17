use std::str;

use serde::{Deserialize, Serialize};
use thiserror::Error;

const DEFAULT_MAX_EVENT_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SseEvent {
    pub raw: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_ms: Option<u64>,
    pub data: Vec<u8>,
    pub valid_utf8: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SseError {
    #[error("SSE event exceeded the configured {limit}-byte limit")]
    EventTooLarge { limit: usize },
}

#[derive(Debug)]
pub struct SseParser {
    buffer: Vec<u8>,
    max_event_bytes: usize,
}

impl Default for SseParser {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_EVENT_BYTES)
    }
}

impl SseParser {
    #[must_use]
    pub const fn new(max_event_bytes: usize) -> Self {
        Self {
            buffer: Vec::new(),
            max_event_bytes,
        }
    }

    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<SseEvent>, SseError> {
        self.buffer.extend_from_slice(bytes);
        let mut output = Vec::new();

        while let Some(end) = find_event_end(&self.buffer) {
            if end > self.max_event_bytes {
                self.buffer.clear();
                return Err(SseError::EventTooLarge {
                    limit: self.max_event_bytes,
                });
            }
            let raw: Vec<u8> = self.buffer.drain(..end).collect();
            output.push(parse_event(raw));
        }

        if self.buffer.len() > self.max_event_bytes {
            self.buffer.clear();
            return Err(SseError::EventTooLarge {
                limit: self.max_event_bytes,
            });
        }
        Ok(output)
    }

    /// Return an unterminated final fragment. It is evidence, but not a valid
    /// completed SSE event and must not be normalized as one.
    #[must_use]
    pub fn finish(self) -> Option<Vec<u8>> {
        (!self.buffer.is_empty()).then_some(self.buffer)
    }
}

fn find_event_end(bytes: &[u8]) -> Option<usize> {
    let mut index = 0;
    let mut consecutive_line_ends = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'\r' => {
                if bytes.get(index + 1) == Some(&b'\n') {
                    index += 2;
                } else {
                    index += 1;
                }
                consecutive_line_ends += 1;
            }
            b'\n' => {
                index += 1;
                consecutive_line_ends += 1;
            }
            _ => {
                index += 1;
                consecutive_line_ends = 0;
            }
        }
        if consecutive_line_ends >= 2 {
            return Some(index);
        }
    }
    None
}

fn parse_event(raw: Vec<u8>) -> SseEvent {
    let mut event = None;
    let mut id = None;
    let mut retry_ms = None;
    let mut data_lines: Vec<&[u8]> = Vec::new();
    let mut valid_utf8 = true;

    for line in raw.split(|byte| *byte == b'\n' || *byte == b'\r') {
        if line.is_empty() || line.first() == Some(&b':') {
            continue;
        }
        let (field, value) = match line.iter().position(|byte| *byte == b':') {
            Some(separator) => {
                let mut value = &line[separator + 1..];
                if value.first() == Some(&b' ') {
                    value = &value[1..];
                }
                (&line[..separator], value)
            }
            None => (line, &[][..]),
        };

        match field {
            b"event" => match str::from_utf8(value) {
                Ok(text) => event = Some(text.to_owned()),
                Err(_) => valid_utf8 = false,
            },
            b"id" => match str::from_utf8(value) {
                Ok(text) if !text.contains('\0') => id = Some(text.to_owned()),
                Ok(_) | Err(_) => valid_utf8 = false,
            },
            b"retry" => {
                retry_ms = str::from_utf8(value)
                    .ok()
                    .and_then(|text| text.parse().ok());
            }
            b"data" => {
                if str::from_utf8(value).is_err() {
                    valid_utf8 = false;
                }
                data_lines.push(value);
            }
            _ => {}
        }
    }

    let mut data = Vec::new();
    for (index, line) in data_lines.iter().enumerate() {
        if index > 0 {
            data.push(b'\n');
        }
        data.extend_from_slice(line);
    }

    SseEvent {
        raw,
        event,
        id,
        retry_ms,
        data,
        valid_utf8,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handles_boundaries_and_multiline_data() {
        let mut parser = SseParser::default();
        assert!(
            parser
                .push(b"event: delta\r\ndata: first\r")
                .unwrap()
                .is_empty()
        );
        let parsed = parser.push(b"\ndata: second\r\n\r\n").unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].event.as_deref(), Some("delta"));
        assert_eq!(parsed[0].data, b"first\nsecond");
        assert!(parsed[0].valid_utf8);
    }

    #[test]
    fn emits_multiple_events_from_one_chunk() {
        let mut parser = SseParser::default();
        let parsed = parser.push(b"data: one\n\ndata: two\n\n").unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].data, b"one");
        assert_eq!(parsed[1].data, b"two");
    }

    #[test]
    fn rejects_unbounded_event() {
        let mut parser = SseParser::new(4);
        assert_eq!(
            parser.push(b"12345"),
            Err(SseError::EventTooLarge { limit: 4 })
        );
        assert_eq!(
            parser.push(b"data: oversized\n\n"),
            Err(SseError::EventTooLarge { limit: 4 })
        );
    }
}
