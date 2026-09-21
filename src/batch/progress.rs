//! Coordinator-only, best-effort human output. No evidence or filenames in updates.
use super::{cli::ProgressMode, BatchStatus, Counters, Manifest};
use std::{collections::VecDeque, io::Write, path::Path, time::Duration};

pub(crate) struct Progress<W: Write> {
    writer: W,
    mode: ProgressMode,
    last: Option<Duration>,
    previous_processed: u64,
    rates: VecDeque<f64>,
}

fn processed(c: &Counters) -> u64 {
    c.complete
        .saturating_add(c.limited)
        .saturating_add(c.failed)
        .saturating_add(c.cancelled)
}

impl<W: Write> Progress<W> {
    pub(crate) fn new(writer: W, mode: ProgressMode) -> Self {
        Self {
            writer,
            mode,
            last: None,
            previous_processed: 0,
            rates: VecDeque::with_capacity(4),
        }
    }

    pub(crate) fn update(
        &mut self,
        manifest: &Manifest,
        bytes: u64,
        elapsed: Duration,
        force: bool,
    ) {
        if self.mode == ProgressMode::Disabled {
            return;
        }
        if !force
            && self
                .last
                .is_some_and(|last| elapsed.saturating_sub(last) < Duration::from_secs(1))
        {
            return;
        }
        let c = &manifest.counters;
        let done = processed(c);
        if let Some(last) = self.last {
            let interval = elapsed.saturating_sub(last).as_secs_f64();
            if interval >= 1.0 {
                if self.rates.len() == 4 {
                    self.rates.pop_front();
                }
                self.rates
                    .push_back(done.saturating_sub(self.previous_processed) as f64 / interval);
            }
        }
        self.last = Some(elapsed);
        self.previous_processed = done;
        let phase = if manifest.status == BatchStatus::Complete {
            "Finished"
        } else if !manifest.stop_reasons.is_empty() {
            "Stopping"
        } else if manifest.discovery_complete {
            "Scanning"
        } else {
            "Discovering"
        };
        let total = if manifest.discovery_complete {
            c.eligible.to_string()
        } else {
            "?".into()
        };
        let mut line = format!("{phase}: {done}/{total} processed | {} active | {} queued | {} complete | {} failed | {} limited | {} cancelled | {} skipped | {} discovery errors | {bytes} selected bytes read | {:.1}s elapsed",
            c.active, c.queued, c.complete, c.failed, c.limited, c.cancelled,
            c.policy_skipped, c.discovery_errors, elapsed.as_secs_f64());
        if elapsed.as_secs_f64() >= 1.0 && manifest.stop_reasons.is_empty() {
            line.push_str(&format!(
                " | {:.1} files/s",
                done as f64 / elapsed.as_secs_f64()
            ));
        }
        // File-completion observations include extra passes and report publication.
        // Require four nonzero, similar windows; never extrapolate byte throughput.
        if manifest.discovery_complete
            && manifest.stop_reasons.is_empty()
            && elapsed >= Duration::from_secs(5)
            && done >= 8
            && done < c.eligible
            && self.rates.len() == 4
        {
            let low = self.rates.iter().copied().fold(f64::INFINITY, f64::min);
            let high = self.rates.iter().copied().fold(0.0, f64::max);
            if low > 0.0 && high <= low * 1.25 {
                let rate = self.rates.iter().sum::<f64>() / 4.0;
                line.push_str(&format!(
                    " | ~{:.0}s remaining (file-rate estimate)",
                    (c.eligible - done) as f64 / rate
                ));
            }
        }
        // Append complete lines even on terminals: long counters may wrap, and
        // cursor rewriting without width tracking would leave stale wrapped rows.
        if writeln!(self.writer, "{line}")
            .and_then(|()| self.writer.flush())
            .is_err()
        {
            self.mode = ProgressMode::Disabled;
        }
    }
}

/// Final orchestration status is distinct from successful analysis counts.
/// Human output is optional; its failure cannot invalidate published artifacts.
pub fn summary(mut writer: impl Write, status: BatchStatus, c: &Counters, root: &Path) {
    let state = if status == BatchStatus::Complete {
        "finished"
    } else {
        "incomplete"
    };
    let indicators = match (c.files_with_indicators, c.limited_files_with_indicators) {
        (Some(all), Some(limited)) => format!("{all} files with indicators ({limited} limited)"),
        _ => "indicators not analyzed".into(),
    };
    let _ = (|| -> std::io::Result<()> {
        writeln!(writer, "Batch {state}: {} processed; {} complete, {} limited, {} failed, {} skipped, {} cancelled; {} discovery errors; {indicators}",
            processed(c), c.complete, c.limited, c.failed, c.policy_skipped, c.cancelled, c.discovery_errors)?;
        for (label, path) in [
            ("Manifest", "manifest.json"),
            ("Files", "files.jsonl"),
            ("Errors", "errors.jsonl"),
            ("Reports", "results"),
        ] {
            writeln!(writer, "{label}: {:?}", root.join(path))?;
        }
        writer.flush()
    })();
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Manifest {
        let mut manifest: Manifest = serde_json::from_str(include_str!(
            "../../tests/fixtures/batch/manifest-empty.json"
        ))
        .unwrap();
        manifest.status = BatchStatus::Incomplete;
        manifest.discovery_complete = false;
        manifest.counters = Counters {
            eligible: 100,
            ..Counters::default()
        };
        manifest
    }

    #[test]
    fn progress_throttles_and_requires_stable_file_rates_for_eta() {
        let mut manifest = fixture();
        let mut progress = Progress::new(Vec::new(), ProgressMode::Plain);
        progress.update(&manifest, 42, Duration::ZERO, false);
        assert!(String::from_utf8_lossy(&progress.writer).contains("Discovering: 0/? processed"));
        let initial = progress.writer.len();
        progress.update(&manifest, 99, Duration::from_millis(999), false);
        assert_eq!(initial, progress.writer.len());
        manifest.discovery_complete = true;
        for second in 1..=5 {
            manifest.counters.complete = second * 2;
            progress.update(&manifest, second * 100, Duration::from_secs(second), false);
        }
        let output = String::from_utf8_lossy(&progress.writer);
        assert!(output.lines().last().unwrap().contains("~45s remaining"));
        assert!(!output.contains('\r') && !output.contains('\x1b'));
        // A stalled file invalidates the estimate immediately at the next refresh.
        progress.update(&manifest, 500, Duration::from_secs(6), false);
        assert!(!String::from_utf8_lossy(&progress.writer)
            .lines()
            .last()
            .unwrap()
            .contains("remaining"));
        manifest.counters.cancelled = 3;
        manifest.counters.failed = 2;
        manifest.counters.limited = 1;
        manifest.stop_reasons.push("interrupted".into());
        progress.update(&manifest, 500, Duration::from_secs(6), true);
        assert!(String::from_utf8_lossy(&progress.writer)
            .lines()
            .last()
            .unwrap()
            .contains("Stopping: 16/100 processed"));
        assert!(!String::from_utf8_lossy(&progress.writer)
            .lines()
            .last()
            .unwrap()
            .contains("files/s"));
    }

    #[test]
    fn broken_optional_writer_disables_progress() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        // Summary must also be best-effort on redirected/broken stderr.
        summary(
            Broken,
            BatchStatus::Incomplete,
            &Counters::default(),
            Path::new("reports"),
        );
        let manifest = fixture();
        let mut broken = Progress::new(Broken, ProgressMode::Plain);
        broken.update(&manifest, 0, Duration::ZERO, false);
        assert_eq!(broken.mode, ProgressMode::Disabled);
    }
}
