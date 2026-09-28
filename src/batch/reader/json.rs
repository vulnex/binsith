//! Streaming JSON syntax guard. Arrays are never accumulated. All objects,
//! including ignored extensions, enforce bounded member names and reject duplicates.
use super::{invalid, Result};
use serde_json::Value;
use std::{collections::BTreeSet, io::BufRead};

#[derive(Clone, Debug)]
pub(super) enum Event {
    ObjectStart,
    ObjectEnd,
    ArrayStart,
    ArrayEnd,
    Scalar(Value),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Segment {
    Key(String),
    Index(u64),
}

pub(super) struct Parser<R> {
    input: R,
    pub scalar_limit: usize,
    pub string_limit: usize,
}
impl<R: BufRead> Parser<R> {
    pub fn new(input: R) -> Self {
        Self {
            input,
            scalar_limit: 16 * 1024 * 1024,
            string_limit: 4 * 1024 * 1024,
        }
    }
    fn peek(&mut self) -> Result<Option<u8>> {
        Ok(self.input.fill_buf()?.first().copied())
    }
    fn take(&mut self) -> Result<Option<u8>> {
        let byte = self.peek()?;
        if byte.is_some() {
            self.input.consume(1);
        }
        Ok(byte)
    }
    fn space(&mut self) -> Result<()> {
        while matches!(self.peek()?, Some(b' ' | b'\r' | b'\n' | b'\t')) {
            self.take()?;
        }
        Ok(())
    }
    fn expect(&mut self, byte: u8) -> Result<()> {
        self.space()?;
        if self.take()? != Some(byte) {
            return Err(invalid("invalid JSON syntax"));
        }
        Ok(())
    }
    fn scalar(&mut self, cap: usize) -> Result<Value> {
        self.space()?;
        let quoted = self.peek()? == Some(b'"');
        let mut bytes = Vec::new();
        let mut escaped = false;
        while let Some(byte) = self.peek()? {
            if !quoted
                && matches!(
                    byte,
                    b' ' | b'\n' | b'\r' | b'\t' | b',' | b':' | b'[' | b']' | b'{' | b'}'
                )
            {
                break;
            }
            if bytes.len() == cap {
                return Err(invalid("JSON scalar limit exceeded"));
            }
            self.take()?;
            bytes.push(byte);
            if quoted {
                if bytes.len() > 1 && byte == b'"' && !escaped {
                    break;
                }
                escaped = byte == b'\\' && !escaped;
            }
        }
        let value: Value =
            serde_json::from_slice(&bytes).map_err(|_| invalid("invalid JSON scalar"))?;
        if value.as_str().is_some_and(|s| s.len() > self.string_limit) {
            return Err(invalid("decoded JSON string limit exceeded"));
        }
        Ok(value)
    }
    pub fn parse(
        &mut self,
        mut visitor: impl FnMut(&[Segment], Event) -> Result<()>,
    ) -> Result<()> {
        self.value(&mut Vec::new(), &mut visitor)?;
        self.space()?;
        if self.peek()?.is_some() {
            return Err(invalid("trailing JSON data"));
        }
        Ok(())
    }
    fn value(
        &mut self,
        path: &mut Vec<Segment>,
        visitor: &mut impl FnMut(&[Segment], Event) -> Result<()>,
    ) -> Result<()> {
        if path.len() > 64 {
            return Err(invalid("JSON depth limit exceeded"));
        }
        self.space()?;
        match self.peek()? {
            Some(b'{') => {
                self.take()?;
                visitor(path, Event::ObjectStart)?;
                let mut keys = BTreeSet::new();
                self.space()?;
                if self.peek()? != Some(b'}') {
                    loop {
                        if keys.len() == 256 {
                            return Err(invalid("JSON object member limit exceeded"));
                        }
                        let key = self
                            .scalar(256)?
                            .as_str()
                            .ok_or_else(|| invalid("JSON object key is not a string"))?
                            .to_owned();
                        if !keys.insert(key.clone()) {
                            return Err(invalid("duplicate JSON object key"));
                        }
                        self.expect(b':')?;
                        path.push(Segment::Key(key));
                        self.value(path, visitor)?;
                        path.pop();
                        self.space()?;
                        if self.peek()? != Some(b',') {
                            break;
                        }
                        self.take()?;
                    }
                }
                self.expect(b'}')?;
                visitor(path, Event::ObjectEnd)?;
            }
            Some(b'[') => {
                self.take()?;
                visitor(path, Event::ArrayStart)?;
                self.space()?;
                let mut index = 0_u64;
                if self.peek()? != Some(b']') {
                    loop {
                        path.push(Segment::Index(index));
                        self.value(path, visitor)?;
                        path.pop();
                        index = index
                            .checked_add(1)
                            .ok_or_else(|| invalid("JSON array index overflow"))?;
                        self.space()?;
                        if self.peek()? != Some(b',') {
                            break;
                        }
                        self.take()?;
                    }
                }
                self.expect(b']')?;
                visitor(path, Event::ArrayEnd)?;
            }
            _ => {
                let value = self.scalar(self.scalar_limit)?;
                visitor(path, Event::Scalar(value))?;
            }
        }
        Ok(())
    }
}

/// Only small, byte-capped manifest/journal objects use tree deserialization.
/// The syntax pass catches duplicate keys even in unknown extension fields.
pub(super) fn document<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    Parser::new(bytes).parse(|_, _| Ok(()))?;
    serde_json::from_slice(bytes).map_err(|_| invalid("invalid artifact fields or schema"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufReader, Cursor};

    #[test]
    fn chunk_boundaries_limits_and_duplicate_keys() {
        let valid = br#"{"x":["a\"b\\c\n\u2603",true,null,-12.5e+1],"empty":{}}"#;
        for chunk in 1..=16 {
            Parser::new(BufReader::with_capacity(chunk, Cursor::new(valid)))
                .parse(|_, _| Ok(()))
                .unwrap();
        }
        for data in [
            br#"{"x":0,"\u0078":1}"#.as_slice(),
            b"[1,]",
            b"{}{}",
            b"{1:0}",
            b"[01]",
            br#""\uD800""#,
        ] {
            assert!(Parser::new(data).parse(|_, _| Ok(())).is_err());
        }
        let mut parser = Parser::new(br#""1234""#.as_slice());
        parser.scalar_limit = 5;
        assert!(parser.parse(|_, _| Ok(())).is_err());
        let mut parser = Parser::new(br#""\u0061\u0062""#.as_slice());
        parser.string_limit = 1;
        assert!(parser.parse(|_, _| Ok(())).is_err());
        let deep = format!("{}0{}", "[".repeat(66), "]".repeat(66));
        assert!(Parser::new(deep.as_bytes()).parse(|_, _| Ok(())).is_err());
        let members = format!(
            "{{{}}}",
            (0..257)
                .map(|n| format!("\"k{n}\":0"))
                .collect::<Vec<_>>()
                .join(",")
        );
        assert!(Parser::new(members.as_bytes())
            .parse(|_, _| Ok(()))
            .is_err());
    }

    #[test]
    fn mutated_json_never_accepts_invalid_syntax() {
        let seeds = [
            br#"{"a":[1,2,null],"b":"unicode \u2603"}"#.as_slice(),
            b"[true,false,-12.5e3]",
            br#"{"escaped":"a\\b\"c"}"#,
        ];
        for seed in seeds {
            for i in 0..seed.len() {
                for byte in [0, b'"', b'\\', b'[', b'}', b',', b':', b'9', 255] {
                    let mut data = seed.to_vec();
                    data[i] = byte;
                    if Parser::new(data.as_slice()).parse(|_, _| Ok(())).is_ok() {
                        assert!(serde_json::from_slice::<Value>(&data).is_ok(), "{data:?}");
                    }
                }
            }
        }
    }
}
