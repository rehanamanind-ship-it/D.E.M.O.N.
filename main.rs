use pyo3::prelude::*;
use pyo3::types::PyModule;
use goblin::Object;
use std::fs;
use std::io::Read;
use std::path::Path;
use std::process;

fn static_analysis(path: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut file = fs::File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let mut report = String::new();

    // Parse with goblin
    match Object::parse(&buffer)? {
        Object::PE(pe) => {
            report.push_str("Format: PE\n");
            report.push_str(&format!("Entry point: 0x{:X}\n", pe.entry));
            // Imports (simplified)
            // We can iterate over pe.imports, etc.
        }
        Object::ELF(elf) => {
            report.push_str("Format: ELF\n");
            report.push_str(&format!("Entry point: 0x{:X}\n", elf.entry));
        }
        Object::Mach(mach) => {
            report.push_str("Format: Mach-O\n");
            // entry point depends on subtype
        }
        _ => report.push_str("Unknown binary format\n"),
    }

    // Extract suspicious strings
    let suspicious = extract_suspicious_strings(&buffer);
    report.push_str("\nSuspicious strings:\n");
    for s in &suspicious {
        report.push_str(&format!("  {}\n", s));
    }

    Ok(report)
}

fn extract_suspicious_strings(data: &[u8]) -> Vec<String> {
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
    strings.dedup();
    strings.truncate(30);
    strings
}

fn analyze_with_python(report: &str, model_path: &str) -> Result<String, PyErr> {
    Python::with_gil(|py| {
        // Load the Python file as a module
        let code = fs::read_to_string("ai_brain.py").unwrap();
        let module = PyModule::from_code(py, &code, "ai_brain.py", "ai_brain")?;
        
        // Call the analyze function
        let analyze_fn = module.getattr("analyze")?;
        let result: String = analyze_fn.call1((report, model_path))?.extract()?;
        Ok(result)
    })
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <file> [model.gguf]", args[0]);
        process::exit(1);
    }
    let path = &args[1];
    let model = if args.len() > 2 { &args[2] } else { "model.gguf" };

    // Static analysis in Rust
    let static_report = static_analysis(path).unwrap_or_else(|e| format!("Error: {e}"));
    println!("--- Static Report (Rust) ---\n{}", static_report);

    // Call Python AI brain
    match analyze_with_python(&static_report, model) {
        Ok(intent) => println!("\n=== AI Analysis ===\n{}", intent),
        Err(e) => eprintln!("Python AI error: {e}"),
    }
}
