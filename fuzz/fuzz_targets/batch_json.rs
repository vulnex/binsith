#![no_main]
use libfuzzer_sys::fuzz_target;
type Result<T> = std::io::Result<T>;
fn invalid(message: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message)
}
#[allow(dead_code)]
#[path = "../../src/batch/reader/json.rs"]
mod json;
fuzz_target!(|data: &[u8]| {
    let mut parser = json::Parser::new(data);
    parser.scalar_limit = 65536;
    parser.string_limit = 16384;
    if parser.parse(|_, _| Ok(())).is_ok() {
        assert!(serde_json::from_slice::<serde_json::Value>(data).is_ok());
    }
});
