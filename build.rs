use sha2::{Digest, Sha256};
use std::{fs, path::Path, process::Command};

fn files(path: &Path, out: &mut Vec<std::path::PathBuf>) {
    if path.is_dir() {
        for entry in fs::read_dir(path).expect("read source directory") {
            files(&entry.unwrap().path(), out);
        }
    } else {
        out.push(path.to_owned());
    }
}
fn command(program: &str, args: &[&str]) -> String {
    Command::new(program)
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_else(|| "unknown".into())
}
fn main() {
    let mut paths = vec!["Cargo.toml".into(), "Cargo.lock".into(), "build.rs".into()];
    files(Path::new("src"), &mut paths);
    paths.sort();
    let mut hash = Sha256::new();
    for path in paths {
        println!("cargo:rerun-if-changed={}", path.display());
        let bytes = fs::read(&path).expect("read build input");
        hash.update(path.to_string_lossy().replace('\\', "/"));
        hash.update([0]);
        hash.update((bytes.len() as u64).to_le_bytes());
        hash.update(bytes);
    }
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/index");
    let head = command("git", &["symbolic-ref", "-q", "HEAD"]);
    if head.starts_with("refs/") {
        println!("cargo:rerun-if-changed=.git/{head}");
    }
    println!(
        "cargo:rustc-env=BINSITH_SOURCE_SHA256={:x}",
        hash.finalize()
    );
    println!(
        "cargo:rustc-env=BINSITH_REVISION={}",
        command("git", &["rev-parse", "HEAD"])
    );
    println!(
        "cargo:rustc-env=BINSITH_TARGET={}",
        std::env::var("TARGET").unwrap()
    );
    println!(
        "cargo:rustc-env=BINSITH_PROFILE={}",
        std::env::var("PROFILE").unwrap()
    );
    println!(
        "cargo:rustc-env=BINSITH_RUSTC={}",
        command(&std::env::var("RUSTC").unwrap(), &["--version"])
    );
}
