fn main() {
    let manifest_dir = std::path::PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"),
    );
    let workspace = manifest_dir
        .ancestors()
        .nth(2)
        .expect("objective workspace")
        .canonicalize()
        .expect("canonical objective workspace");
    let cargo_home = std::env::var_os("CARGO_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|home| std::path::PathBuf::from(home).join(".cargo"))
        })
        .expect("CARGO_HOME or HOME");
    let rustflags = vec![
        format!("--remap-path-prefix={}=/workspace", workspace.display()),
        format!("--remap-path-prefix={}=/cargo", cargo_home.display()),
    ];
    sp1_build::build_program_with_args(
        "../program",
        sp1_build::BuildArgs {
            locked: true,
            rustflags,
            ..Default::default()
        },
    );
}
