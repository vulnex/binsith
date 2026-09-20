//! Isolated regex-handle experiment, intentionally excluded from normal tests.
//! Measures the real scanner/report path to a sink; it is not a disk throughput gate.
use super::*;
#[test]
#[ignore = "manual release-profile regex handle measurement"]
fn measure_shared_and_cloned_handles() {
    let patterns = crate::string_analysis::load_patterns(None).unwrap();
    let manifest: Manifest = serde_json::from_str(include_str!(
        "../../../tests/fixtures/batch/manifest-empty.json"
    ))
    .unwrap();
    let mut configuration = manifest.configuration.analysis;
    configuration.strings = true;
    configuration.entropy = false;
    configuration.scan_utf16 = false;
    let metadata = serde_json::json!({});
    let payload = b"https://example.com/a\0user@example.org\0plain text\0".repeat(350);
    let mut results = Vec::new();
    for jobs in [1, 4] {
        for round in 0..4 {
            // Alternate order; round zero warms both paths and is excluded below.
            for clone_handles in if round % 2 == 0 {
                [false, true]
            } else {
                [true, false]
            } {
                let started = Instant::now();
                std::thread::scope(|scope| {
                    let mut handles = Vec::new();
                    for _ in 0..jobs {
                        let owned = clone_handles.then(|| patterns.clone());
                        let patterns = &patterns;
                        let configuration = &configuration;
                        let metadata = &metadata;
                        let payload = &payload;
                        handles.push(scope.spawn(move || {
                            let patterns = owned.as_deref().unwrap_or(patterns);
                            let request = ScanRequest {
                                display_path: "sample",
                                configuration,
                                patterns,
                                metadata,
                            };
                            for _ in 0..(256 / jobs) {
                                let outcome = scanner::scan_selected(
                                    payload.as_slice(),
                                    io::sink(),
                                    &request,
                                    &CancellationToken::default(),
                                    |_| {},
                                )
                                .unwrap();
                                assert_eq!(outcome.summary.size_bytes, payload.len() as u64);
                                assert_eq!(outcome.has_actionable_indicators, Some(true));
                            }
                        }));
                    }
                    for handle in handles {
                        handle.join().unwrap();
                    }
                });
                if round != 0 {
                    results.push(serde_json::json!({"jobs":jobs,"cloned_handles":clone_handles,"round":round,"elapsed_ms":started.elapsed().as_secs_f64()*1000.0}));
                }
            }
        }
    }
    println!(
        "REGEX_BENCH={}",
        serde_json::json!({"profile":env!("BINSITH_PROFILE"),"target":env!("BINSITH_TARGET"),"files_per_trial":256,"bytes_per_file":payload.len(),"trials":results})
    );
}
