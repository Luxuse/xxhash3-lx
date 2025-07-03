use std::fs::File;
use std::io::{BufReader, Read, Write, stdin};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use rayon::prelude::*;
use xxhash_rust::xxh3::Xxh3;
use std::time::Instant;
use md5;
use crc32fast;

#[derive(Debug, Clone, Copy, PartialEq)]
enum HashType {
    Xxh3,
    Md5,
    Crc32,
}

#[derive(Debug, Clone, PartialEq)]
enum FileStatus {
    Ok,
    Corrupted,
    Missing,
    Error,
}

impl FileStatus {
    fn symbol(&self) -> &str {
        match self {
            FileStatus::Ok => "✓",
            FileStatus::Corrupted => "✗",
            FileStatus::Missing => "?",
            FileStatus::Error => "!",
        }
    }

    fn text(&self) -> &str {
        match self {
            FileStatus::Ok => "OK",
            FileStatus::Corrupted => "CORRUPTED",
            FileStatus::Missing => "MISSING",
            FileStatus::Error => "ERROR",
        }
    }

    fn color(&self) -> &str {
        match self {
            FileStatus::Ok => "\x1b[32m",      // Green
            FileStatus::Corrupted | FileStatus::Error => "\x1b[31m", // Red
            FileStatus::Missing => "\x1b[33m",   // Yellow
        }
    }
}

#[derive(Debug, Clone)]
struct FileCheck {
    path: String,
    expected_hash: String,
    status: Option<FileStatus>,
}

struct VerificationResult {
    file_check: FileCheck,
    status: FileStatus,
}

struct Xxh3VerifierCli {
    base_path: PathBuf,
    files: Vec<FileCheck>,
    hash_type: HashType,
}

impl Xxh3VerifierCli {
    fn new() -> Self {
        Self {
            base_path: PathBuf::new(),
            files: Vec::new(),
            hash_type: HashType::Xxh3,
        }
    }

    fn auto_load_hash_file(&mut self) -> Result<(), String> {
        let current_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let candidates = [
            ("CRC.xxhash3", HashType::Xxh3),
            ("CRC.md5", HashType::Md5),
            ("CRC.crc32", HashType::Crc32),
        ];

        for (fname, htype) in candidates.iter() {
            let hash_file_path = current_dir.join(fname);
            if hash_file_path.exists() {
                self.hash_type = *htype;
                return self.load_hash_file(&hash_file_path);
            }
        }

        if let Ok(exe_path) = std::env::current_exe() {
            if let Some(exe_dir) = exe_path.parent() {
                for (fname, htype) in candidates.iter() {
                    let hash_file_path = exe_dir.join(fname);
                    if hash_file_path.exists() {
                        self.hash_type = *htype;
                        return self.load_hash_file(&hash_file_path);
                    }
                }
            }
        }

        Err("No CRC.xxhash3, CRC.md5 or CRC.crc32 file found".to_string())
    }

    fn load_hash_file(&mut self, path: &Path) -> Result<(), String> {
        let file = File::open(path).map_err(|e| format!("Error opening file: {}", e))?;
        let mut reader = BufReader::new(file);
        let mut buffer = Vec::new();

        reader.read_to_end(&mut buffer).map_err(|e| format!("Error reading file: {}", e))?;

        let content = String::from_utf8_lossy(&buffer);

        self.base_path = path.parent().unwrap().to_path_buf();
        self.files.clear();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let (hash, file_path) = match self.hash_type {
                HashType::Xxh3 | HashType::Md5 => {
                    let parts: Vec<&str> = line.splitn(2, ' ').collect();
                    if parts.len() != 2 {
                        continue;
                    }
                    (parts[0].to_string(), parts[1].trim_start_matches('*').to_string())
                }
                HashType::Crc32 => {
                    // Format: CRC32 (hex) [space] filename
                    let parts: Vec<&str> = line.splitn(2, ' ').collect();
                    if parts.len() != 2 {
                        continue;
                    }
                    (parts[0].to_lowercase(), parts[1].trim_start_matches('*').to_string())
                }
            };

            self.files.push(FileCheck {
                path: file_path,
                expected_hash: hash,
                status: None,
            });
        }

        Ok(())
    }
    
    fn verify_files(&mut self) {
        let total_files = self.files.len();
        let start_time = Instant::now();
        const BAR_WIDTH: usize = 40;

        println!("\n\x1b[1m🔍 Starting verification of {} files...\x1b[0m", total_files);

        let display_mutex = Mutex::new(());

        let files_to_process: Vec<FileCheck> = self.files.clone();
        let hash_type = self.hash_type;

        let results: Vec<_> = files_to_process
            .par_iter()
            .enumerate()
            .map(|(index, file_check)| {
                let file_number = index + 1;
                let file_path = PathBuf::from(&file_check.path);
                let full_path = if file_path.is_absolute() {
                    file_path
                } else {
                    self.base_path.join(&file_path)
                };

                let mut last_percent = 0.0;
                let mut progress_bar = String::new();
                let mut percent = 0.0;
                let mut header = String::new();

                let status = if !full_path.exists() {
                    FileStatus::Missing
                } else {
                    let hash_result = match hash_type {
                        HashType::Xxh3 => calculate_xxh3_hash_with_progress(&full_path, |read, total| {
                            percent = if total > 0 {
                                (read as f64 / total as f64) * 100.0
                            } else {
                                100.0
                            };
                            if total > 0 && (percent - last_percent > 0.5 || percent == 100.0) {
                                last_percent = percent;
                                let filled = ((percent / 100.0) * BAR_WIDTH as f64).round() as usize;
                                let empty = BAR_WIDTH - filled;
                                progress_bar = format!(
                                    "{}{}",
                                    "\x1b[44m \x1b[0m".repeat(filled),
                                    "\x1b[100m \x1b[0m".repeat(empty)
                                );
                                header = format!(
                                    "\r\x1b[1;34m[{:>3}/{:<3}]\x1b[0m \x1b[36m{:<40}\x1b[0m",
                                    file_number, total_files, file_check.path
                                );
                                print!(
                                    "{} [{}] {:>6.1}%\x1b[K",
                                    header, progress_bar, percent
                                );
                                std::io::stdout().flush().unwrap();
                            }
                        }),
                        HashType::Md5 => calculate_md5_hash_with_progress(&full_path, |read, total| {
                            percent = if total > 0 {
                                (read as f64 / total as f64) * 100.0
                            } else {
                                100.0
                            };
                            if total > 0 && (percent - last_percent > 0.5 || percent == 100.0) {
                                last_percent = percent;
                                let filled = ((percent / 100.0) * BAR_WIDTH as f64).round() as usize;
                                let empty = BAR_WIDTH - filled;
                                progress_bar = format!(
                                    "{}{}",
                                    "\x1b[44m \x1b[0m".repeat(filled),
                                    "\x1b[100m \x1b[0m".repeat(empty)
                                );
                                header = format!(
                                    "\r\x1b[1;34m[{:>3}/{:<3}]\x1b[0m \x1b[36m{:<40}\x1b[0m",
                                    file_number, total_files, file_check.path
                                );
                                print!(
                                    "{} [{}] {:>6.1}%\x1b[K",
                                    header, progress_bar, percent
                                );
                                std::io::stdout().flush().unwrap();
                            }
                        }),
                        HashType::Crc32 => calculate_crc32_hash_with_progress(&full_path, |read, total| {
                            percent = if total > 0 {
                                (read as f64 / total as f64) * 100.0
                            } else {
                                100.0
                            };
                            if total > 0 && (percent - last_percent > 0.5 || percent == 100.0) {
                                last_percent = percent;
                                let filled = ((percent / 100.0) * BAR_WIDTH as f64).round() as usize;
                                let empty = BAR_WIDTH - filled;
                                progress_bar = format!(
                                    "{}{}",
                                    "\x1b[44m \x1b[0m".repeat(filled),
                                    "\x1b[100m \x1b[0m".repeat(empty)
                                );
                                header = format!(
                                    "\r\x1b[1;34m[{:>3}/{:<3}]\x1b[0m \x1b[36m{:<40}\x1b[0m",
                                    file_number, total_files, file_check.path
                                );
                                print!(
                                    "{} [{}] {:>6.1}%\x1b[K",
                                    header, progress_bar, percent
                                );
                                std::io::stdout().flush().unwrap();
                            }
                        }),
                    };
                    match hash_result {
                        Ok(calculated_hash) => {
                            // Pour CRC32, on ignore la casse et les zéros non significatifs
                            let expected = match hash_type {
                                HashType::Crc32 => file_check.expected_hash.trim_start_matches("0x").trim_start_matches('0').to_lowercase(),
                                _ => file_check.expected_hash.to_lowercase(),
                            };
                            let actual = match hash_type {
                                HashType::Crc32 => calculated_hash.trim_start_matches("0x").trim_start_matches('0').to_lowercase(),
                                _ => calculated_hash.to_lowercase(),
                            };
                            if actual == expected {
                                FileStatus::Ok
                            } else {
                                FileStatus::Corrupted
                            }
                        }
                        Err(_) => FileStatus::Error
                    }
                };

                {
                    let _display_lock = display_mutex.lock().unwrap();
                    let filled = BAR_WIDTH;
                    let progress_bar = format!(
                        "{}",
                        "\x1b[44m \x1b[0m".repeat(filled)
                    );
                    let header = format!(
                        "\r\x1b[1;34m[{:>3}/{:<3}]\x1b[0m \x1b[36m{:<40}\x1b[0m",
                        file_number, total_files, file_check.path
                    );
                    println!(
                        "{} [{}] 100.0%   {}{} {}\x1b[0m",
                        header,
                        progress_bar,
                        status.color(),
                        status.symbol(),
                        status.text()
                    );
                    std::io::stdout().flush().unwrap();
                }

                VerificationResult {
                    file_check: file_check.clone(),
                    status,
                }
            })
            .collect();

        println!();

        for result in results {
            if let Some(file_check) = self.files.iter_mut().find(|f| f.path == result.file_check.path) {
                file_check.status = Some(result.status);
            }
        }

        let duration = start_time.elapsed();
        println!("\nVerification completed in {:.2} seconds", duration.as_secs_f32());
    }

    fn show_results(&self) {
        let ok_count = self.files.iter().filter(|f| matches!(f.status, Some(FileStatus::Ok))).count();
        let corrupted_count = self.files.iter().filter(|f| matches!(f.status, Some(FileStatus::Corrupted))).count();
        let missing_count = self.files.iter().filter(|f| matches!(f.status, Some(FileStatus::Missing))).count();
        let error_count = self.files.iter().filter(|f| matches!(f.status, Some(FileStatus::Error))).count();
        let total = self.files.len();

        println!("\n{}", "=".repeat(60));
        println!("📊 VERIFICATION RESULTS");
        println!("{}", "=".repeat(60));

        if corrupted_count == 0 && missing_count == 0 && error_count == 0 {
            println!("\x1b[32m✅ VERIFICATION SUCCESSFUL!\x1b[0m");
            println!("\x1b[32mAll files are intact.\x1b[0m");
        } else {
            println!("\x1b[33m⚠️ PROBLEMS DETECTED\x1b[0m");
            println!("\x1b[33mSome files need your attention.\x1b[0m");
        }

        println!("\n📈 Detailed Statistics:");
        println!(" \x1b[32m✓ OK files         : {:>4}\x1b[0m", ok_count);
        if corrupted_count > 0 {
            println!(" \x1b[31m✗ Corrupted files  : {:>4}\x1b[0m", corrupted_count);
        }
        if missing_count > 0 {
            println!(" \x1b[33m? Missing files    : {:>4}\x1b[0m", missing_count);
        }
        if error_count > 0 {
            println!(" \x1b[31m! Read errors      : {:>4}\x1b[0m", error_count);
        }
        println!(" 📁 Total files      : {:>4}", total);

        if corrupted_count > 0 || missing_count > 0 || error_count > 0 {
            println!("\n⚠️ Problematic files:");
            for file_check in &self.files {
                if let Some(status) = &file_check.status {
                    match status {
                        FileStatus::Corrupted => println!(" \x1b[31m✗ CORRUPTED\x1b[0m : {}", file_check.path),
                        FileStatus::Missing => println!(" \x1b[33m? MISSING\x1b[0m   : {}", file_check.path),
                        FileStatus::Error => println!(" \x1b[31m! ERROR\x1b[0m     : {}", file_check.path),
                        _ => {}
                    }
                }
            }
        }

        println!("\n{}", "=".repeat(60));

        if total > 0 {
            let success_rate = (ok_count as f32 / total as f32) * 100.0;
            if success_rate == 100.0 {
                println!("\x1b[32m🎉 Success rate : {:.1}% - PERFECT!\x1b[0m", success_rate);
            } else if success_rate >= 90.0 {
                println!("\x1b[33m📊 Success rate : {:.1}% - Good\x1b[0m", success_rate);
            } else {
                println!("\x1b[31m📊 Success rate : {:.1}% - Attention required\x1b[0m", success_rate);
            }
        }
    }

    fn run(&mut self) {
        println!("🔐 XXHash3 File Verifier - Command Line Version");
        println!("{}", "=".repeat(60));
        println!();

        match self.auto_load_hash_file() {
            Ok(()) => {
                println!("✓ Successfully loaded CRC.xxhash3 file");
                println!("📂 Base directory: {}", self.base_path.display());
                println!("📋 {} files to verify", self.files.len());

                self.verify_files();
                self.show_results();
            }
            Err(e) => {
                println!("\x1b[31m❌ Error: {}\x1b[0m", e);
                println!("\nMake sure a 'CRC.xxhash3' file exists in:");
                println!("  - Current directory");
                println!("  - Executable directory");
            }
        }
    }
}

#[allow(dead_code)]
fn calculate_xxh3_hash(file_path: &Path) -> Result<String, std::io::Error> {
    let mut file = File::open(file_path)?;
    let mut hasher = Xxh3::new();
    let mut buffer = [0u8; 8192];

    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 { break; }
        hasher.update(&buffer[..n]);
    }

    Ok(format!("{:016x}", hasher.digest()))
}

fn calculate_xxh3_hash_with_progress(
    file_path: &Path,
    mut progress_callback: impl FnMut(u64, u64) + Send + Sync,
) -> Result<String, std::io::Error> {
    let mut file = File::open(file_path)?;
    let metadata = file.metadata()?;
    let total_size = metadata.len();
    let mut hasher = Xxh3::new();
    let mut buffer = vec![0u8; 1024 * 1024]; // 1 MB buffer
    let mut read_bytes = 0u64;

    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
        read_bytes += n as u64;
        progress_callback(read_bytes, total_size);
    }

    Ok(format!("{:016x}", hasher.digest()))
}

fn calculate_md5_hash_with_progress(
    file_path: &Path,
    mut progress_callback: impl FnMut(u64, u64) + Send + Sync,
) -> Result<String, std::io::Error> {
    let mut file = File::open(file_path)?;
    let metadata = file.metadata()?;
    let total_size = metadata.len();
    let mut context = md5::Context::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    let mut read_bytes = 0u64;

    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 { break; }
        context.consume(&buffer[..n]);
        read_bytes += n as u64;
        progress_callback(read_bytes, total_size);
    }

    Ok(format!("{:032x}", context.finalize()))
}

fn calculate_crc32_hash_with_progress(
    file_path: &Path,
    mut progress_callback: impl FnMut(u64, u64) + Send + Sync,
) -> Result<String, std::io::Error> {
    let mut file = File::open(file_path)?;
    let metadata = file.metadata()?;
    let total_size = metadata.len();
    let mut hasher = crc32fast::Hasher::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    let mut read_bytes = 0u64;

    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 { break; }
        hasher.update(&buffer[..n]);
        read_bytes += n as u64;
        progress_callback(read_bytes, total_size);
    }

    Ok(format!("{:08x}", hasher.finalize()))
}

fn main() {
    println!("XXHash3 File Verifier");
    println!("=====================");
    println!("This tool verifies file integrity using XXH3 hash values.");
    println!("It expects a CRC.xxhash3 file containing file paths and their expected hashes.");
    
    let mut verifier = Xxh3VerifierCli::new();
    verifier.run();

    println!("\nPress Enter to exit...");
    let mut input = String::new();
    stdin().read_line(&mut input).unwrap();
}