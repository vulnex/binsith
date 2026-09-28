//! Process-wide folder interruption policy, shared by CLI and subprocess tests.
use crate::scanner::CancellationToken;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

pub struct InterruptHandler(Arc<AtomicBool>);
static INSTALLED: AtomicBool = AtomicBool::new(false);

impl InterruptHandler {
    /// Install once per process. First interrupt cancels cooperatively; second
    /// exits immediately without waiting for blocked filesystem operations.
    pub fn install(token: CancellationToken) -> Result<Self, Box<dyn std::error::Error>> {
        Self::install_policy(token, true)
    }
    /// Export always cancels cooperatively so a second signal cannot override a
    /// committed bundle's exit status. Blocked kernel I/O can delay cancellation.
    pub fn install_export(token: CancellationToken) -> Result<Self, Box<dyn std::error::Error>> {
        Self::install_policy(token, false)
    }
    fn install_policy(
        token: CancellationToken,
        force_second: bool,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        if INSTALLED.swap(true, Ordering::SeqCst) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "interrupt handler already installed",
            )
            .into());
        }
        let interrupted = Arc::new(AtomicBool::new(false));
        let signal = interrupted.clone();
        #[cfg(unix)]
        // SAFETY: the callback performs only atomic operations and the library's
        // async-signal-safe exit. CancellationToken::cancel must remain atomic-only.
        // Registration occurs before workers start and remains process-wide, as
        // with ctrlc. Keep INSTALLED set on error: registration may be partial,
        // and the CLI exits before claiming output rather than retrying it.
        unsafe {
            signal_hook::low_level::register(signal_hook::consts::SIGINT, move || {
                if signal.swap(true, Ordering::SeqCst) && force_second {
                    signal_hook::low_level::exit(130);
                }
                token.cancel();
            })?;
        }
        #[cfg(not(unix))]
        ctrlc::set_handler(move || {
            if signal.swap(true, Ordering::SeqCst) && force_second {
                std::process::exit(130);
            }
            token.cancel();
        })?;
        Ok(Self(interrupted))
    }
    pub fn is_interrupted(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}
