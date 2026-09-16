use std::io::{self, Read};

pub fn open_input(path: &str) -> io::Result<Box<dyn Read>> {
    if path == "-" {
        Ok(Box::new(io::stdin()))
    } else {
        Ok(Box::new(std::fs::File::open(path)?))
    }
}

/// Select a byte range without seeking, so files and stdin have identical semantics.
pub fn ranged_input(path: &str, offset: u64, length: Option<u64>) -> io::Result<Box<dyn Read>> {
    let mut input = open_input(path)?;
    let skipped = io::copy(&mut input.by_ref().take(offset), &mut io::sink())?;
    if skipped != offset {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "offset is beyond end of input",
        ));
    }
    Ok(Box::new(input.take(length.unwrap_or(u64::MAX))))
}

pub fn escape_string(text: &str) -> String {
    text.chars()
        .flat_map(|c| {
            if c.is_control() {
                c.escape_default().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
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
