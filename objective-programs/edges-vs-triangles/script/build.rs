use sp1_build::{build_program_with_args, BuildArgs};
use std::{env, path::PathBuf};

fn remap_flag(path: PathBuf, stable: &str) -> String {
    let canonical = path
        .canonicalize()
        .unwrap_or_else(|error| panic!("cannot canonicalize SP1 build input path: {error}"));
    let source = canonical
        .to_str()
        .unwrap_or_else(|| panic!("SP1 build input path is not UTF-8: {canonical:?}"));
    format!("--remap-path-prefix={source}={stable}")
}

fn main() {
    let manifest =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is required"));
    let workspace = manifest
        .ancestors()
        .nth(2)
        .expect("Edges script must remain below the objective-program workspace");
    let home = PathBuf::from(env::var_os("HOME").expect("HOME is required"));
    let cargo_home = env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".cargo"));
    let rustup_home = env::var_os("RUSTUP_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".rustup"));
    let sp1_home = home.join(".sp1");

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
                remap_flag(sp1_home, "/sp1"),
            ],
            ..Default::default()
        },
    );
}
