//! Bounded external sort. Scratch accounting includes both merge generations.
use super::{invalid, Error, Result};
use std::{
    cell::Cell,
    cmp::Reverse,
    collections::BinaryHeap,
    fs::File,
    io::{BufReader, BufWriter, Read, Write},
    rc::Rc,
};

pub(super) type Row = (Vec<u8>, Vec<u8>);
#[derive(Clone)]
pub(super) struct Scratch {
    used: Rc<Cell<u64>>,
    high: Rc<Cell<u64>>,
    cap: u64,
    token: crate::scanner::CancellationToken,
}
impl Scratch {
    pub fn new(cap: u64) -> Self {
        Self {
            used: Rc::new(Cell::new(0)),
            high: Rc::new(Cell::new(0)),
            cap,
            token: crate::scanner::CancellationToken::default(),
        }
    }
    pub fn with_cancellation(mut self, token: crate::scanner::CancellationToken) -> Self {
        self.token = token;
        self
    }
    pub fn high_water(&self) -> u64 {
        self.high.get()
    }
}
pub(super) struct Run {
    path: tempfile::TempPath,
    bytes: u64,
    scratch: Scratch,
}
impl Drop for Run {
    fn drop(&mut self) {
        self.scratch.used.set(self.scratch.used.get() - self.bytes);
    }
}
impl Run {
    pub fn reader(&self) -> Result<BufReader<File>> {
        Ok(BufReader::new(File::open(&self.path)?))
    }
}
struct Writer {
    file: BufWriter<File>,
    path: Option<tempfile::TempPath>,
    bytes: u64,
    scratch: Scratch,
}
impl Drop for Writer {
    fn drop(&mut self) {
        self.scratch.used.set(self.scratch.used.get() - self.bytes);
    }
}
impl Writer {
    fn new(scratch: Scratch) -> Result<Self> {
        let (file, path) = tempfile::NamedTempFile::new()?.into_parts();
        Ok(Self {
            file: BufWriter::new(file),
            path: Some(path),
            bytes: 0,
            scratch,
        })
    }
    fn row(&mut self, row: &Row) -> Result<()> {
        if self.scratch.token.is_cancelled() {
            return Err(Error::Interrupted);
        }
        let size = 8 + row.0.len() as u64 + row.1.len() as u64;
        if size > self.scratch.cap.saturating_sub(self.scratch.used.get()) {
            return Err(Error::Resource("scratch byte limit exceeded"));
        }
        self.scratch.used.set(self.scratch.used.get() + size);
        self.scratch
            .high
            .set(self.scratch.high.get().max(self.scratch.used.get()));
        self.bytes += size;
        self.file.write_all(&(row.0.len() as u32).to_le_bytes())?;
        self.file.write_all(&(row.1.len() as u32).to_le_bytes())?;
        self.file.write_all(&row.0)?;
        self.file.write_all(&row.1)?;
        Ok(())
    }
    fn finish(mut self) -> Result<Run> {
        self.file.flush()?;
        Ok(Run {
            path: self.path.take().unwrap(),
            bytes: std::mem::take(&mut self.bytes),
            scratch: self.scratch.clone(),
        })
    }
}
pub(super) fn next(reader: &mut impl Read) -> Result<Option<Row>> {
    let mut lengths = [0; 8];
    match reader.read(&mut lengths[..1])? {
        0 => return Ok(None),
        1 => (),
        _ => unreachable!(),
    }
    reader.read_exact(&mut lengths[1..])?;
    let key = u32::from_le_bytes(lengths[..4].try_into().unwrap()) as usize;
    let value = u32::from_le_bytes(lengths[4..].try_into().unwrap()) as usize;
    if key > 65536 || value > 1024 * 1024 {
        return Err(invalid("invalid scratch record size"));
    }
    let mut k = vec![0; key];
    let mut v = vec![0; value];
    reader.read_exact(&mut k)?;
    reader.read_exact(&mut v)?;
    Ok(Some((k, v)))
}

pub(super) struct Sort {
    rows: Vec<Row>,
    bytes: usize,
    runs: Vec<Run>,
    scratch: Scratch,
    cap: usize,
}
impl Sort {
    pub fn new(scratch: Scratch, cap: usize) -> Self {
        Self {
            rows: Vec::new(),
            bytes: 0,
            runs: Vec::new(),
            scratch,
            cap,
        }
    }
    pub fn push(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<()> {
        let bytes = key.len() + value.len() + 8;
        if key.len() > 65536 || value.len() > 1024 * 1024 || bytes > self.cap {
            return Err(invalid("sort record limit exceeded"));
        }
        if self.bytes + bytes > self.cap {
            self.flush()?;
        }
        self.rows.push((key, value));
        self.bytes += bytes;
        Ok(())
    }
    fn flush(&mut self) -> Result<()> {
        if self.rows.is_empty() {
            return Ok(());
        }
        self.rows.sort_unstable();
        let mut writer = Writer::new(self.scratch.clone())?;
        for row in self.rows.drain(..) {
            writer.row(&row)?;
        }
        self.runs.push(writer.finish()?);
        self.bytes = 0;
        Ok(())
    }
    pub fn finish(mut self) -> Result<Run> {
        self.flush()?;
        if self.runs.is_empty() {
            return Writer::new(self.scratch)?.finish();
        }
        while self.runs.len() > 1 {
            let mut outputs = Vec::new();
            let mut runs = self.runs.into_iter();
            loop {
                let group: Vec<_> = runs.by_ref().take(16).collect();
                if group.is_empty() {
                    break;
                }
                let mut readers: Vec<_> = group.iter().map(Run::reader).collect::<Result<_>>()?;
                let mut heap = BinaryHeap::new();
                for (i, reader) in readers.iter_mut().enumerate() {
                    if let Some(row) = next(reader)? {
                        heap.push(Reverse((row, i)));
                    }
                }
                let mut writer = Writer::new(self.scratch.clone())?;
                while let Some(Reverse((row, i))) = heap.pop() {
                    writer.row(&row)?;
                    if let Some(next) = next(&mut readers[i])? {
                        heap.push(Reverse((next, i)));
                    }
                }
                outputs.push(writer.finish()?);
            }
            self.runs = outputs;
        }
        Ok(self.runs.pop().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn multipass_merge_is_deterministic_and_scratch_is_released() {
        let scratch = Scratch::new(1024 * 1024);
        let mut sorter = Sort::new(scratch.clone(), 128);
        for i in (0_u32..1000).rev() {
            sorter.push(i.to_be_bytes().to_vec(), vec![42; 12]).unwrap();
        }
        let run = sorter.finish().unwrap();
        let mut reader = run.reader().unwrap();
        for i in 0_u32..1000 {
            assert_eq!(
                next(&mut reader).unwrap().unwrap(),
                (i.to_be_bytes().to_vec(), vec![42; 12])
            );
        }
        assert!(next(&mut reader).unwrap().is_none());
        drop(reader);
        drop(run);
        assert_eq!(scratch.used.get(), 0);
        assert!(scratch.high_water() > 24000);
    }
    #[test]
    fn scratch_exhaustion_releases_failed_writer_accounting() {
        let scratch = Scratch::new(24);
        {
            let mut writer = Writer::new(scratch.clone()).unwrap();
            writer.row(&(vec![1; 8], vec![2; 8])).unwrap();
            assert!(writer.row(&(vec![3], vec![4])).is_err());
        }
        assert_eq!(scratch.used.get(), 0);
    }
}
