#![no_main]
use binsith::{
    batch::{export, reader},
    scanner::CancellationToken,
};
use libfuzzer_sys::fuzz_target;
use sha2::{Digest, Sha256};
use std::fs;
const MANIFEST: &[u8] = include_bytes!("../../tests/fixtures/batch/released-v0.5/manifest.json");
const FILES: &[u8] = include_bytes!("../../tests/fixtures/batch/released-v0.5/files.jsonl");
const REPORT: &[u8] = include_bytes!("../../tests/fixtures/batch/released-v0.5/results/9d/9d511e2a5125b6f8bd242d8451cf8016aa80e6325a839712ef7e997dbc3e3788.json");
const LOCATION: &str =
    "results/9d/9d511e2a5125b6f8bd242d8451cf8016aa80e6325a839712ef7e997dbc3e3788.json";
fuzz_target!(|data: &[u8]| {
    if data.len() > 8192 {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path().canonicalize().unwrap();
    let source = base.join("source");
    fs::create_dir_all(source.join("results/9d")).unwrap();
    let names = ["manifest.json", "files.jsonl", "errors.jsonl", LOCATION];
    let mut values = [
        MANIFEST.to_vec(),
        FILES.to_vec(),
        Vec::new(),
        REPORT.to_vec(),
    ];
    if data.len() >= 4 {
        let slot = usize::from(data[0]) % 4;
        let bytes = &mut values[slot];
        let offset = usize::from(u16::from_le_bytes([data[2], data[3]])) % (bytes.len() + 1);
        match data[1] % 4 {
            0 => {
                bytes.splice(offset..offset, data[4..].iter().copied());
            }
            1 => {
                *bytes = data[4..].to_vec();
            }
            2 => {
                bytes.truncate(offset);
            }
            _ => {
                for (to, from) in bytes[offset..].iter_mut().zip(&data[4..]) {
                    *to ^= from;
                }
            }
        }
    }
    for (name, bytes) in names.iter().zip(values) {
        fs::write(source.join(name), bytes).unwrap();
    }
    let options = export::Options {
        reader_limits: reader::Limits {
            manifest_bytes: 65536,
            line_bytes: 65536,
            entries: 16,
            journal_records: 64,
            import_bytes: 1024 * 1024,
            scratch_bytes: 4 * 1024 * 1024,
            sort_buffer_bytes: 16384,
        },
        ..Default::default()
    };
    let destination = base.join("export");
    let result = export::run(
        &source,
        &destination,
        options,
        CancellationToken::default(),
        |_| Ok(()),
    );
    match result {
        Err(_) => assert!(!destination.join("manifest.json").exists()),
        Ok(code) => {
            let manifest: serde_json::Value =
                serde_json::from_slice(&fs::read(destination.join("manifest.json")).unwrap())
                    .unwrap();
            assert_eq!(manifest["exit_code"], code);
            for (name, receipt) in manifest["artifacts"].as_object().unwrap() {
                assert!(matches!(name.as_str(), "indicators.json" | "summary.json"));
                let bytes = fs::read(destination.join(name)).unwrap();
                assert_eq!(receipt["bytes"], bytes.len() as u64);
                assert_eq!(receipt["sha256"], format!("{:x}", Sha256::digest(&bytes)));
            }
        }
    }
    // Every mutation is confined to disposable artifacts. No sample input is supplied.
    assert!(source.join("manifest.json").is_file());
});
