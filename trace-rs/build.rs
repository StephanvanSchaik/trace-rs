#[cfg(target_os = "macos")]
fn generate_mach_exception_interface() {
    use std::path::PathBuf;
    use std::process::Command;

    // Run xcrun --show-sdk-path to determine the installation path of the MacOS SDK.
    let mut output = Command::new("xcrun")
        .args(["--show-sdk-path"])
        .output()
        .expect("Expected xcrun to be installed - make sure to run xcode-select --install");

    // Truncate the output to the first line.
    if let Some(size) = output.stdout.iter().position(|c| *c == b'\n') {
        output.stdout.truncate(size);
    }

    // Parse the string and convert it into a path.
    let sdk_path = String::from_utf8(output.stdout)
        .expect("Expected xcrun --show-sdk-path to output UTF-8");
    let sdk_path = PathBuf::from(sdk_path);

    let out = std::env::var("OUT_DIR")
        .expect("Expected OUT_DIR to be set");
    let out = PathBuf::from(out);

    let mach_exc_defs = sdk_path
        .join("usr/include/mach/mach_exc.defs")
        .display()
        .to_string();

    println!("cargo:rerun-if-changed={mach_exc_defs}");

    // Use mig to generate the C files from the Mach exception interface definition.
    Command::new("mig")
        .args([mach_exc_defs.to_string()])
        .current_dir(out.display().to_string())
        .spawn()
        .expect("Expected mig to be installed")
        .wait()
        .expect("mig failed to run");

    // Compile and link the C files.
    cc::Build::new()
        .file(out.join("mach_excServer.c"))
        .file(out.join("mach_excUser.c"))
        .compile("mach_excServer");
}

fn main() {
    #[cfg(target_os = "macos")]
    generate_mach_exception_interface();
}
