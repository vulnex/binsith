//! Deterministic test-only I/O boundaries. No hooks or environment switches are
//! compiled into production binaries. Each test owns its plan; workers inherit it
//! explicitly, so parallel tests cannot inject faults into one another.
use std::{
    cell::RefCell,
    io,
    path::PathBuf,
    sync::{Arc, Condvar, Mutex},
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Journal {
    Admission,
    Terminal,
    Diagnostic,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    Write,
    Partial,
    Flush,
    Flushed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Point {
    WorkerSpawn,
    ScanStart,
    QueueSaturated,
    BeforeTerminalSend,
    AfterTerminalSend,
    ReportCreate,
    ReportWrite,
    ReportPartial,
    ReportFlush,
    ReportPublish,
    ReportPublished,
    Journal(Journal, Step),
    ManifestCreate,
    ManifestWrite,
    ManifestFlush,
    ManifestReplace,
    FinalManifestReplace,
    SnapshotCreate,
    SnapshotWrite,
}
#[derive(Clone)]
pub enum Action {
    Full,
    Crash,
    Collision(PathBuf),
    Gate(Arc<Gate>),
    Observe(Arc<Gate>),
    Panic,
}
#[derive(Clone)]
pub struct Plan {
    rules: Vec<Arc<Mutex<State>>>,
    event_capacity: Option<usize>,
}
struct State {
    point: Point,
    occurrence: usize,
    hits: usize,
    fired: bool,
    action: Action,
}
impl Plan {
    pub fn new(point: Point, occurrence: usize, action: Action) -> Self {
        Self {
            rules: vec![Arc::new(Mutex::new(State {
                point,
                occurrence,
                hits: 0,
                fired: false,
                action,
            }))],
            event_capacity: None,
        }
    }
    pub fn and(mut self, other: Self) -> Self {
        self.rules.extend(other.rules);
        self
    }
    pub fn with_event_capacity(mut self, capacity: usize) -> Self {
        assert!(capacity > 0);
        self.event_capacity = Some(capacity);
        self
    }
    pub fn hits(&self) -> usize {
        self.rules.iter().map(|r| r.lock().unwrap().hits).sum()
    }
    pub fn fired(&self) -> bool {
        self.rules.iter().all(|r| r.lock().unwrap().fired)
    }
}
thread_local! { static PLAN: RefCell<Option<Plan>> = const { RefCell::new(None) }; }
pub fn current() -> Option<Plan> {
    PLAN.with(|p| p.borrow().clone())
}
pub struct Guard(Option<Plan>);
pub fn install(plan: Option<Plan>) -> Guard {
    Guard(PLAN.with(|p| p.replace(plan)))
}
impl Drop for Guard {
    fn drop(&mut self) {
        PLAN.with(|p| p.replace(self.0.take()));
    }
}
pub fn event_capacity(default: usize) -> usize {
    current().and_then(|p| p.event_capacity).unwrap_or(default)
}
pub fn hit(point: Point) -> io::Result<()> {
    let Some(plan) = current() else {
        return Ok(());
    };
    for rule in plan.rules {
        let action = {
            let mut state = rule.lock().unwrap();
            if state.point != point {
                continue;
            }
            state.hits += 1;
            if matches!(state.action, Action::Gate(_) | Action::Observe(_)) {
                if state.hits > state.occurrence {
                    continue;
                }
            } else if state.fired || state.hits != state.occurrence {
                continue;
            }
            state.fired = true;
            state.action.clone()
        };
        match action {
            Action::Full => {
                return Err(io::Error::new(
                    io::ErrorKind::StorageFull,
                    format!("injected storage full at {point:?}"),
                ))
            }
            Action::Crash => std::process::exit(99),
            Action::Collision(path) => {
                std::fs::write(path, b"foreign report: preserve these bytes")?
            }
            Action::Gate(gate) => gate.enter(),
            Action::Observe(gate) => gate.arrive(),
            Action::Panic => panic!("injected worker panic at {point:?}"),
        }
    }
    Ok(())
}

/// Test-controlled rendezvous with bounded parent waits and explicit release.
#[derive(Default)]
pub struct Gate {
    state: Mutex<(usize, bool)>,
    changed: Condvar,
}
impl Gate {
    fn arrive(&self) {
        self.state.lock().unwrap().0 += 1;
        self.changed.notify_all();
    }
    pub fn count(&self) -> usize {
        self.state.lock().unwrap().0
    }
    fn enter(&self) {
        let mut state = self.state.lock().unwrap();
        state.0 += 1;
        self.changed.notify_all();
        while !state.1 {
            state = self.changed.wait(state).unwrap();
        }
    }
    pub fn wait_for(&self, count: usize) -> bool {
        let (state, _) = self
            .changed
            .wait_timeout_while(
                self.state.lock().unwrap(),
                std::time::Duration::from_secs(10),
                |state| state.0 < count,
            )
            .unwrap();
        state.0 >= count
    }
    pub fn release(&self) {
        self.state.lock().unwrap().1 = true;
        self.changed.notify_all();
    }
}
