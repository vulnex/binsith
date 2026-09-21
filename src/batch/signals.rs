//! Process-wide folder interruption policy, shared by CLI and subprocess tests.
use crate::scanner::CancellationToken;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

pub struct InterruptHandler(Arc<AtomicBool>);
impl InterruptHandler {
    /// Install once per process. First interrupt cancels cooperatively; second
    /// exits immediately without waiting for blocked filesystem operations.
    pub fn install(token: CancellationToken) -> Result<Self, ctrlc::Error> {
        let interrupted = Arc::new(AtomicBool::new(false));
        let signal = interrupted.clone();
        ctrlc::set_handler(move || {
            if signal.swap(true, Ordering::SeqCst) {
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
