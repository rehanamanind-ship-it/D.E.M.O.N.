// main.rs - Cross‑platform EXE/script intent analyser (Rust + embedded Python)
// Dependencies: pyo3, goblin, rfd, serde, serde_json

use pyo3::prelude::*;
use pyo3::types::PyModule;
use goblin::Object;
use rfd::FileDialog;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process;

// ---------------------------------------------------------------------------
// Persistent config: stores the path of the default model (GGUF or ONNX)
// ---------------------------------------------------------------------------
#[derive(Serialize, Deserialize)]
struct Config {
    default_model: Option<String>,
}

impl Config {
    fn path() -> PathBuf {
        std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .join("config.json")
    }

    fn load() -> Self {
        match fs::read_to_string(Self::path()) {
            Ok(data) => serde_json::from_str(&data).unwrap_or(Config { default_model: None }),
            Err(_) => Config { default_model: None },
        }
    }

    fn save(&self) {
        let _ = fs::write(Self::path(), serde_json::to_string_pretty(self).unwrap());
    }
}

// ---------------------------------------------------------------------------
// Static binary analysis (PE/ELF/Mach‑O + suspicious strings)
// ---------------------------------------------------------------------------
fn static_analysis(path: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut file = fs::File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let mut report = String::new();
    match Object::parse(&buffer)? {
        Object::PE(pe) => {
            report.push_str("Format: PE\n");
            report.push_str(&format!("Entry point: 0x{:X}\n", pe.entry));
        }
        Object::ELF(elf) => {
            report.push_str("Format: ELF\n");
            report.push_str(&format!("Entry point: 0x{:X}\n", elf.entry));
        }
        Object::Mach(mach) => {
            report.push_str("Format: Mach-O\n");
            // Entry point depends on subtype – simplified here
        }
        _ => report.push_str("Unknown binary format\n"),
    }

    let suspicious = extract_strings(&buffer);
    report.push_str("\nSuspicious strings:\n");
    for s in suspicious {
        report.push_str(&format!("  {}\n", s));
    }
    Ok(report)
}

fn extract_strings(data: &[u8]) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current = String::new();
    for &byte in data {
        if byte >= 0x20 && byte <= 0x7e {
            current.push(byte as char);
        } else {
            if current.len() >= 4 {
                let lower = current.to_lowercase();
                if lower.contains("http") || lower.contains("www.") ||
                   lower.contains("cmd") || lower.contains("powershell") ||
                   lower.contains("/etc/") || lower.contains("temp") ||
                   lower.contains("passwd") {
                    strings.push(current.clone());
                }
            }
            current.clear();
        }
    }
    strings.sort();
    strings.dedup();
    strings.truncate(30);
    strings
}

// ---------------------------------------------------------------------------
// Call Python: load model and run analysis
// ---------------------------------------------------------------------------
fn run_python(report: &str, model_path: &str) -> Result<String, PyErr> {
    Python::with_gil(|py| {
        let code = fs::read_to_string("ai_brain.py").unwrap();
        let module = PyModule::from_code(py, &code, "ai_brain.py", "ai_brain")?;

        // Load model (caches inside Python if not already loaded)
        module.getattr("load_model")?.call1((model_path,))?;

        let analyze = module.getattr("analyze")?;
        let result: String = analyze.call1((report,))?.extract()?;
        Ok(result)
    })
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------
fn main() {
    let mut config = Config::load();
    let mut model_path: String;

    // -----------------------------------------------------------------------
    // First launch: no valid model – ask user how to proceed
    // -----------------------------------------------------------------------
    match config.default_model.clone() {
        Some(ref p) if Path::new(p).exists() => {
            model_path = p.clone();
        }
        _ => {
            println!("No valid model configured. You can:");
            println!("  1) Select an existing .gguf or .onnx file");
            println!("  2) Generate a default dummy ONNX model (no real AI)");
            print!("Choice [1/2]: ");
            let mut choice = String::new();
            std::io::stdin().read_line(&mut choice).ok();

            if choice.trim() == "2" {
                // Let Python create a minimal ONNX model
                let default_path = std::env::current_exe()
                    .unwrap()
                    .parent()
                    .unwrap()
                    .join("default_model.onnx");
                Python::with_gil(|py| {
                    let code = fs::read_to_string("ai_brain.py").unwrap();
                    let module =
                        PyModule::from_code(py, &code, "ai_brain.py", "ai_brain").unwrap();
                    let gen = module.getattr("generate_default_onnx").unwrap();
                    let msg: String = gen
                        .call1((default_path.to_string_lossy(),))
                        .unwrap()
                        .extract()
                        .unwrap();
                    println!("{}", msg);
                });
                model_path = default_path.to_string_lossy().into();
                config.default_model = Some(model_path.clone());
                config.save();
            } else {
                // Open file dialog to pick a model
                if let Some(p) = FileDialog::new()
                    .add_filter("Model files", &["gguf", "onnx"])
                    .set_title("Select AI model")
                    .pick_file()
                {
                    model_path = p.to_string_lossy().into();
                    config.default_model = Some(model_path.clone());
                    config.save();
                } else {
                    eprintln!("No model selected, exiting.");
                    process::exit(1);
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Main menu loop
    // -----------------------------------------------------------------------
    loop {
        println!("\n=== EXE Intent Analyser ===");
        println!("1. Analyse a file");
        println!("2. Change default model");
        println!("3. Convert GGUF to ONNX");
        println!("4. Generate default dummy ONNX model");
        println!("5. Exit");
        println!("Current model: {}", model_path);

        let mut choice = String::new();
        std::io::stdin().read_line(&mut choice).ok();
        match choice.trim() {
            "1" => {
                if let Some(target) = FileDialog::new()
                    .add_filter("All files", &["*"])
                    .set_title("Select file to analyse")
                    .pick_file()
                {
                    let target = target.to_string_lossy();
                    match static_analysis(&target) {
                        Ok(report) => {
                            println!("--- Static Report ---\n{}", report);
                            match run_python(&report, &model_path) {
                                Ok(intent) => println!("\n=== AI Analysis ===\n{}", intent),
                                Err(e) => eprintln!("Python error: {e}"),
                            }
                        }
                        Err(e) => eprintln!("Analysis error: {e}"),
                    }
                }
            }
            "2" => {
                if let Some(new) = FileDialog::new()
                    .add_filter("Model files", &["gguf", "onnx"])
                    .set_title("Select new default model")
                    .pick_file()
                {
                    model_path = new.to_string_lossy().into();
                    config.default_model = Some(model_path.clone());
                    config.save();
                    println!("Model updated.");
                }
            }
            "3" => {
                if let Some(gguf) = FileDialog::new()
                    .add_filter("GGUF", &["gguf"])
                    .set_title("Select GGUF to convert")
                    .pick_file()
                {
                    if let Some(onnx_out) = FileDialog::new()
                        .add_filter("ONNX", &["onnx"])
                        .set_title("Save ONNX as")
                        .save_file()
                    {
                        println!("Starting conversion (may take a while)...");
                        Python::with_gil(|py| {
                            let code = fs::read_to_string("ai_brain.py").unwrap();
                            let module = PyModule::from_code(
                                py, &code, "ai_brain.py", "ai_brain",
                            )
                            .unwrap();
                            let convert = module.getattr("convert_gguf_to_onnx").unwrap();
                            let msg: String = convert
                                .call1((gguf.to_string_lossy(), onnx_out.to_string_lossy()))
                                .unwrap()
                                .extract()
                                .unwrap();
                            println!("{}", msg);
                        });
                    }
                }
            }
            "4" => {
                // Re‑generate the dummy ONNX model (overwrites if exists)
                let default_path = std::env::current_exe()
                    .unwrap()
                    .parent()
                    .unwrap()
                    .join("default_model.onnx");
                Python::with_gil(|py| {
                    let code = fs::read_to_string("ai_brain.py").unwrap();
                    let module =
                        PyModule::from_code(py, &code, "ai_brain.py", "ai_brain").unwrap();
                    let gen = module.getattr("generate_default_onnx").unwrap();
                    let msg: String = gen
                        .call1((default_path.to_string_lossy(),))
                        .unwrap()
                        .extract()
                        .unwrap();
                    println!("{}", msg);
                });
                model_path = default_path.to_string_lossy().into();
                config.default_model = Some(model_path.clone());
                config.save();
            }
            "5" => break,
            _ => println!("Invalid choice"),
        }
    }
}
