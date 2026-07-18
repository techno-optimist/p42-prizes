use sp1_build::{build_program_with_args, BuildArgs};
use std::{env, path::PathBuf};

fn remap_flag(path: PathBuf, stable: &str) -> String {
    let canonical = path
        .canonicalize()
        .expect("cannot canonicalize SP1 build input path");
    let source = canonical
        .to_str()
        .expect("SP1 build input path is not UTF-8");
    format!("--remap-path-prefix={source}={stable}")
}

fn main() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let workspace = manifest
        .ancestors()
        .nth(2)
        .expect("nested objective workspace");
    let home = PathBuf::from(env::var_os("HOME").expect("HOME"));
    let cargo_home = env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".cargo"));
    let rustup_home = env::var_os("RUSTUP_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".rustup"));
    println!("cargo:rerun-if-env-changed=CARGO_HOME");
    println!("cargo:rerun-if-env-changed=RUSTUP_HOME");
    println!("cargo:rerun-if-env-changed=HOME");
    build_program_with_args(
        "../program",
        BuildArgs {
            locked: true,
            rustflags: vec![
                remap_flag(workspace.to_path_buf(), "/p42/objective-programs"),
                remap_flag(cargo_home, "/cargo"),
                remap_flag(rustup_home, "/rustup"),
                remap_flag(home.join(".sp1"), "/sp1"),
            ],
            ..Default::default()
        },
    );
}
