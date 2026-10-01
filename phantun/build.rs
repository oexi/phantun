//! Compiles the eBPF program in src/bpf with clang (12 or newer). Without a clang able to build
//! it, Phantun is built without eBPF support, unless PHANTUN_REQUIRE_EBPF is set, which turns that
//! into an error. 32-bit x86 is always built without it, as aya, which loads the program, does not
//! support it.
//!
//! Where no suitable clang is available, such as in the images of cross, PHANTUN_BPF_OBJECT_DIR
//! can name a directory (relative to the workspace) with the program already built, as
//! offload.bpfel.o and offload.bpfeb.o, using the arguments in CLANG_ARGS.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const SOURCE: &str = "src/bpf/offload.bpf.c";
// -g emits the BTF that describes the maps, v3 has the atomic instructions. Also used by
// .github/workflows/release.yml.
const CLANG_ARGS: [&str; 5] = ["-O2", "-g", "-Wall", "-Werror", "-mcpu=v3"];

fn main() {
    println!("cargo::rerun-if-changed={SOURCE}");
    println!("cargo::rerun-if-env-changed=CLANG");
    println!("cargo::rerun-if-env-changed=PHANTUN_REQUIRE_EBPF");
    println!("cargo::rerun-if-env-changed=PHANTUN_BPF_OBJECT_DIR");
    println!("cargo::rustc-check-cfg=cfg(ebpf)");

    if env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("x86") {
        return;
    }

    let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join("offload.bpf.o");
    let target = match env::var("CARGO_CFG_TARGET_ENDIAN").as_deref() {
        Ok("big") => "bpfeb",
        _ => "bpfel",
    };

    let result = match env::var_os("PHANTUN_BPF_OBJECT_DIR") {
        Some(dir) => copy_object(Path::new(&dir), target, &out),
        None => compile(target, &out),
    };
    match result {
        Ok(()) => println!("cargo::rustc-cfg=ebpf"),
        Err(message) => {
            if env::var_os("PHANTUN_REQUIRE_EBPF").is_some_and(|v| !v.is_empty() && v != "0") {
                panic!("unable to build the eBPF program:\n{message}");
            }
            for line in format!("building without eBPF support: {message}").lines() {
                println!("cargo::warning={line}");
            }
        }
    }
}

fn copy_object(dir: &Path, target: &str, out: &Path) -> Result<(), String> {
    let workspace = Path::new(&env::var("CARGO_MANIFEST_DIR").unwrap()).join("..");
    let object = workspace.join(dir).join(format!("offload.{target}.o"));
    println!("cargo::rerun-if-changed={}", object.display());
    fs::copy(&object, out)
        .map(|_| ())
        .map_err(|e| format!("{}: {e}", object.display()))
}

fn compile(target: &str, out: &Path) -> Result<(), String> {
    // CLANG picks the compiler, otherwise try the unversioned name first
    let candidates: Vec<String> = match env::var("CLANG") {
        Ok(clang) => vec![clang],
        Err(_) => ["clang".to_string()]
            .into_iter()
            .chain((12..=21).rev().map(|v| format!("clang-{v}")))
            .collect(),
    };

    let mut errors = Vec::new();
    for clang in &candidates {
        let result = Command::new(clang)
            .args(CLANG_ARGS)
            .args(["-target", target, "-c", SOURCE, "-o"])
            .arg(out)
            .output();
        match result {
            Ok(output) if output.status.success() => return Ok(()),
            Ok(output) => errors.push(format!(
                "{clang}: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )),
            // Only show the failures of compilers that exist
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => errors.push(format!("{clang}: {e}")),
        }
    }

    Err(if errors.is_empty() {
        "clang not found".to_string()
    } else {
        errors.join("\n")
    })
}
