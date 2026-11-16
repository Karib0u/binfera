//! Compresses the COM databases for embedding. They are about 2 MB of text, which counts against
//! the size limit on the browser's WebAssembly module (see web/scripts/build-wasm.sh).
use std::env;
use std::fs;
use std::io::Write;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out = env::var("OUT_DIR")?;
    for name in ["com_classes.json", "com_interfaces.json"] {
        let source = format!("data/{name}");
        println!("cargo:rerun-if-changed={source}");
        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        encoder.write_all(&fs::read(&source)?)?;
        fs::write(Path::new(&out).join(format!("{name}.z")), encoder.finish()?)?;
    }
    println!("cargo:rerun-if-changed=build.rs");
    Ok(())
}
