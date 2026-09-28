#![no_main]
use binsith::batch::selection::{NativeEncoding, Selection, SelectionConfiguration};
use libfuzzer_sys::fuzz_target;
use std::path::Path;
fn configuration(pattern: String, encoding: NativeEncoding) -> SelectionConfiguration {
    SelectionConfiguration {
        grammar: "native_glob_v1".into(),
        native_encoding: encoding,
        includes: vec![pattern],
        excludes: vec![],
        max_depth: None,
        max_file_bytes: Some(100),
    }
}
fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    #[cfg(unix)]
    let native_path = {
        use std::os::unix::ffi::OsStringExt;
        std::ffi::OsString::from_vec(data.to_vec())
    };
    #[cfg(windows)]
    let native_path = {
        use std::os::windows::ffi::OsStringExt;
        let units: Vec<u16> = data
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect();
        std::ffi::OsString::from_wide(&units)
    };
    for encoding in [NativeEncoding::Unix, NativeEncoding::Windows] {
        if let Ok(selection) = Selection::compile(configuration(text.to_string(), encoding), true) {
            selection.path_reason(Path::new("nested/a.bin"), false);
            selection.path_reason(Path::new("nested"), true);
            selection.path_reason(Path::new(&native_path), false);
            selection.path_reason(Path::new(&native_path), true);
            assert!(!selection.size_excluded(100));
            assert!(selection.size_excluded(101));
        }
    }
    // Independent regex oracle for the single-component ASCII wildcard subset.
    let split = data.len().min(64) / 2;
    let pattern: String = data[..split]
        .iter()
        .map(|b| ['a', 'b', '*', '?'][usize::from(*b) % 4])
        .collect();
    let name: String = data[split..data.len().min(64)]
        .iter()
        .map(|b| if b % 2 == 0 { 'a' } else { 'b' })
        .collect();
    if name.is_empty() {
        return;
    }
    if let Ok(selection) = Selection::compile(
        configuration(pattern.clone(), NativeEncoding::current()),
        true,
    ) {
        let expression = pattern
            .chars()
            .map(|c| match c {
                '*' => ".*",
                '?' => ".",
                'a' => "a",
                _ => "b",
            })
            .collect::<String>();
        let expected = regex::Regex::new(&format!("^{expression}$"))
            .unwrap()
            .is_match(&name);
        assert_eq!(
            selection.path_reason(Path::new(&name), false).is_none(),
            expected
        );
    }
});
