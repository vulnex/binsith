use std::borrow::Cow;
use std::io::{self, Read, Seek, SeekFrom};

/// Seek regular files to avoid reading the discarded prefix. Streams still
/// consume that prefix, retaining the same beyond-EOF and length semantics.
pub fn ranged_input(path: &str, offset: u64, length: Option<u64>) -> io::Result<Box<dyn Read>> {
    let mut input: Box<dyn Read> = if path == "-" {
        Box::new(io::stdin())
    } else {
        let mut file = std::fs::File::open(path)?;
        let metadata = file.metadata()?;
        // Virtual files can report zero length while providing readable data.
        // Keep those on the streaming path, along with pipes and devices.
        if metadata.is_file() && metadata.len() > 0 {
            if offset > metadata.len() {
                return Err(offset_past_end());
            }
            file.seek(SeekFrom::Start(offset))?;
            return Ok(Box::new(file.take(length.unwrap_or(u64::MAX))));
        }
        Box::new(file)
    };
    skip_prefix(&mut input, offset)?;
    Ok(Box::new(input.take(length.unwrap_or(u64::MAX))))
}

fn offset_past_end() -> io::Error {
    io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "offset is beyond end of input",
    )
}
fn skip_prefix(input: &mut impl Read, offset: u64) -> io::Result<()> {
    let skipped = io::copy(&mut input.take(offset), &mut io::sink())?;
    if skipped != offset {
        return Err(offset_past_end());
    }
    Ok(())
}

pub fn escape_string(text: &str) -> Cow<'_, str> {
    let Some((first, _)) = text.char_indices().find(|(_, c)| c.is_control()) else {
        return Cow::Borrowed(text);
    };
    let mut escaped = String::with_capacity(text.len());
    escaped.push_str(&text[..first]);
    for c in text[first..].chars() {
        if c.is_control() {
            escaped.extend(c.escape_default());
        } else {
            escaped.push(c);
        }
    }
    Cow::Owned(escaped)
}

/// A requested report can finish even when the terminal stops accepting output.
pub struct Terminal<W: io::Write> {
    writer: W,
    defer_errors: bool,
    error: Option<io::Error>,
}
impl<W: io::Write> Terminal<W> {
    pub fn new(writer: W, defer_errors: bool) -> Self {
        Self {
            writer,
            defer_errors,
            error: None,
        }
    }
    pub fn finish(self) -> io::Result<()> {
        match self.error {
            Some(e) if e.kind() != io::ErrorKind::BrokenPipe => Err(e),
            _ => Ok(()),
        }
    }
}
impl<W: io::Write> io::Write for Terminal<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.error.is_some() {
            return Ok(bytes.len());
        }
        match self.writer.write(bytes) {
            Err(e) if self.defer_errors => {
                self.error = Some(e);
                Ok(bytes.len())
            }
            result => result,
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.error.is_some() {
            return Ok(());
        }
        match self.writer.flush() {
            Err(e) if self.defer_errors => {
                self.error = Some(e);
                Ok(())
            }
            result => result,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    #[test]
    fn escaping_preserves_unicode_and_borrows_plain_text() {
        assert!(matches!(
            escape_string("Unicode: café 😀"),
            Cow::Borrowed(_)
        ));
        assert!(matches!(escape_string(""), Cow::Borrowed(_)));
        assert_eq!(
            escape_string("café\n\t\r\0\u{1b}\u{85}😀"),
            "café\\n\\t\\r\\u{0}\\u{1b}\\u{85}😀"
        );
    }
    #[test]
    fn prefix_skipping_stops_exactly_and_propagates_errors() {
        let mut bytes = &b"abcdef"[..];
        skip_prefix(&mut bytes, 3).unwrap();
        assert_eq!(bytes, b"def");
        skip_prefix(&mut bytes, 0).unwrap();
        assert_eq!(bytes, b"def");
        assert_eq!(
            skip_prefix(&mut bytes, 4).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        struct Fail;
        impl Read for Fail {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("read failed"))
            }
        }
        assert_eq!(
            skip_prefix(&mut Fail, 1).unwrap_err().to_string(),
            "read failed"
        );
    }
    #[test]
    fn report_terminal_errors_are_deferred_but_not_hidden() {
        struct Fail(io::ErrorKind);
        impl Write for Fail {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::new(self.0, "terminal failed"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        for kind in [io::ErrorKind::BrokenPipe, io::ErrorKind::Other] {
            let mut terminal = Terminal::new(Fail(kind), true);
            terminal.write_all(b"hello").unwrap();
            terminal.flush().unwrap();
            assert_eq!(terminal.finish().is_ok(), kind == io::ErrorKind::BrokenPipe);
        }
        let mut terminal = Terminal::new(Fail(io::ErrorKind::BrokenPipe), false);
        assert_eq!(
            terminal.write_all(b"hello").unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
    }
}
