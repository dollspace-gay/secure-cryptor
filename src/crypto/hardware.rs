//! Hardware cryptographic acceleration detection and capabilities.
//!
//! This module detects and reports on hardware cryptographic acceleration features
//! available on the current CPU, including:
//!
//! - **AES-NI**: Hardware AES encryption/decryption instructions
//! - **AVX/AVX2/AVX-512**: SIMD extensions that accelerate cryptographic operations
//! - **SHA Extensions**: Hardware SHA-1/SHA-256 acceleration
//! - **CLMUL**: Carry-less multiplication for GCM mode
//! - **RDRAND/RDSEED**: Hardware random number generation
//!
//! # Example
//!
//! ```
//! use tesseract::crypto::hardware::{HardwareCapabilities, detect_capabilities};
//!
//! let caps = detect_capabilities();
//! println!("Hardware capabilities: {}", caps);
//!
//! if caps.has_aes_ni() {
//!     println!("AES-NI is available - using hardware acceleration");
//! }
//!
//! // Get a summary of all features
//! for feature in caps.available_features() {
//!     println!("  - {}", feature);
//! }
//! ```

use std::fmt;

/// CPU vendor identification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuVendor {
    /// Intel Corporation
    Intel,
    /// Advanced Micro Devices
    Amd,
    /// ARM Holdings
    Arm,
    /// Apple Silicon (M1, M2, etc.)
    Apple,
    /// Unknown or unsupported vendor
    Unknown,
}

impl fmt::Display for CpuVendor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CpuVendor::Intel => write!(f, "Intel"),
            CpuVendor::Amd => write!(f, "AMD"),
            CpuVendor::Arm => write!(f, "ARM"),
            CpuVendor::Apple => write!(f, "Apple"),
            CpuVendor::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Hardware cryptographic capabilities detected on the current system.
///
/// This struct provides a comprehensive view of available hardware acceleration
/// features that can improve cryptographic performance.
#[derive(Debug, Clone)]
pub struct HardwareCapabilities {
    /// CPU vendor
    pub vendor: CpuVendor,

    /// CPU brand string (e.g., "Intel(R) Core(TM) i7-10700K")
    pub cpu_brand: String,

    // x86/x86_64 specific features
    /// AES-NI (Advanced Encryption Standard New Instructions)
    pub aes_ni: bool,

    /// PCLMULQDQ (Carry-less multiplication for GCM)
    pub pclmulqdq: bool,

    /// SHA extensions (SHA-1 and SHA-256 hardware acceleration)
    pub sha_ext: bool,

    /// AVX (Advanced Vector Extensions)
    pub avx: bool,

    /// AVX2 (Advanced Vector Extensions 2)
    pub avx2: bool,

    /// AVX-512F (AVX-512 Foundation)
    pub avx512f: bool,

    /// AVX-512VL (AVX-512 Vector Length Extensions)
    pub avx512vl: bool,

    /// VAES (Vector AES - AVX-512 AES)
    pub vaes: bool,

    /// VPCLMULQDQ (Vector CLMUL)
    pub vpclmulqdq: bool,

    /// RDRAND (Hardware random number generator)
    pub rdrand: bool,

    /// RDSEED (Hardware random seed generator)
    pub rdseed: bool,

    /// SSE2 (Streaming SIMD Extensions 2)
    pub sse2: bool,

    /// SSE4.1
    pub sse41: bool,

    /// SSE4.2
    pub sse42: bool,

    /// BMI1 (Bit Manipulation Instructions Set 1)
    pub bmi1: bool,

    /// BMI2 (Bit Manipulation Instructions Set 2)
    pub bmi2: bool,

    /// ADX (Multi-Precision Add-Carry Instruction Extensions)
    pub adx: bool,

    // ARM specific features
    /// ARM AES instructions
    pub arm_aes: bool,

    /// ARM SHA-1 instructions
    pub arm_sha1: bool,

    /// ARM SHA-2 instructions
    pub arm_sha2: bool,

    /// ARM SHA-3 instructions
    pub arm_sha3: bool,

    /// ARM PMULL (polynomial multiply long)
    pub arm_pmull: bool,

    /// ARM NEON (SIMD)
    pub arm_neon: bool,

    /// ARM CRC32 instructions
    pub arm_crc32: bool,
}

impl Default for HardwareCapabilities {
    fn default() -> Self {
        Self {
            vendor: CpuVendor::Unknown,
            cpu_brand: String::new(),
            aes_ni: false,
            pclmulqdq: false,
            sha_ext: false,
            avx: false,
            avx2: false,
            avx512f: false,
            avx512vl: false,
            vaes: false,
            vpclmulqdq: false,
            rdrand: false,
            rdseed: false,
            sse2: false,
            sse41: false,
            sse42: false,
            bmi1: false,
            bmi2: false,
            adx: false,
            arm_aes: false,
            arm_sha1: false,
            arm_sha2: false,
            arm_sha3: false,
            arm_pmull: false,
            arm_neon: false,
            arm_crc32: false,
        }
    }
}

impl HardwareCapabilities {
    /// Returns true if AES hardware acceleration is available.
    ///
    /// On x86/x86_64, this checks for AES-NI.
    /// On ARM, this checks for ARM AES instructions.
    #[inline]
    pub fn has_aes_ni(&self) -> bool {
        self.aes_ni || self.arm_aes
    }

    /// Returns true if hardware GCM acceleration is available.
    ///
    /// GCM mode benefits from CLMUL/PCLMULQDQ instructions.
    #[inline]
    pub fn has_gcm_acceleration(&self) -> bool {
        (self.aes_ni && self.pclmulqdq) || (self.arm_aes && self.arm_pmull)
    }

    /// Returns true if SHA hardware acceleration is available.
    #[inline]
    pub fn has_sha_acceleration(&self) -> bool {
        self.sha_ext || self.arm_sha2
    }

    /// Returns true if hardware random number generation is available.
    #[inline]
    pub fn has_hardware_rng(&self) -> bool {
        self.rdrand || self.rdseed
    }

    /// Returns true if AVX2 SIMD is available.
    #[inline]
    pub fn has_avx2(&self) -> bool {
        self.avx2
    }

    /// Returns true if AVX-512 is available.
    #[inline]
    pub fn has_avx512(&self) -> bool {
        self.avx512f
    }

    /// Returns true if vector AES (VAES) is available.
    ///
    /// VAES allows processing multiple AES blocks in parallel using AVX-512.
    #[inline]
    pub fn has_vaes(&self) -> bool {
        self.vaes && self.avx512f
    }

    /// Returns true if ARM NEON SIMD is available.
    #[inline]
    pub fn has_neon(&self) -> bool {
        self.arm_neon
    }

    /// Returns a list of available cryptographic features.
    pub fn available_features(&self) -> Vec<&'static str> {
        let mut features = Vec::new();

        // x86/x86_64 features
        if self.aes_ni {
            features.push("AES-NI");
        }
        if self.pclmulqdq {
            features.push("PCLMULQDQ (CLMUL)");
        }
        if self.sha_ext {
            features.push("SHA Extensions");
        }
        if self.sse2 {
            features.push("SSE2");
        }
        if self.sse41 {
            features.push("SSE4.1");
        }
        if self.sse42 {
            features.push("SSE4.2");
        }
        if self.avx {
            features.push("AVX");
        }
        if self.avx2 {
            features.push("AVX2");
        }
        if self.avx512f {
            features.push("AVX-512F");
        }
        if self.avx512vl {
            features.push("AVX-512VL");
        }
        if self.vaes {
            features.push("VAES");
        }
        if self.vpclmulqdq {
            features.push("VPCLMULQDQ");
        }
        if self.rdrand {
            features.push("RDRAND");
        }
        if self.rdseed {
            features.push("RDSEED");
        }
        if self.bmi1 {
            features.push("BMI1");
        }
        if self.bmi2 {
            features.push("BMI2");
        }
        if self.adx {
            features.push("ADX");
        }

        // ARM features
        if self.arm_aes {
            features.push("ARM AES");
        }
        if self.arm_sha1 {
            features.push("ARM SHA-1");
        }
        if self.arm_sha2 {
            features.push("ARM SHA-2");
        }
        if self.arm_sha3 {
            features.push("ARM SHA-3");
        }
        if self.arm_pmull {
            features.push("ARM PMULL");
        }
        if self.arm_neon {
            features.push("ARM NEON");
        }
        if self.arm_crc32 {
            features.push("ARM CRC32");
        }

        features
    }

    /// Returns a security assessment of the hardware capabilities.
    pub fn security_assessment(&self) -> SecurityAssessment {
        let mut score = 0;
        let mut recommendations = Vec::new();

        // Check for AES acceleration (critical for performance)
        if self.has_aes_ni() {
            score += 30;
        } else {
            recommendations.push("No AES hardware acceleration - encryption will be slower");
        }

        // Check for GCM acceleration
        if self.has_gcm_acceleration() {
            score += 20;
        } else {
            recommendations.push("No GCM hardware acceleration - consider AES-CTR mode");
        }

        // Check for SHA acceleration
        if self.has_sha_acceleration() {
            score += 15;
        } else {
            recommendations.push("No SHA hardware acceleration - hashing will be slower");
        }

        // Check for hardware RNG
        if self.has_hardware_rng() {
            score += 20;
        } else {
            recommendations.push("No hardware RNG - relying on OS entropy sources");
        }

        // Check for SIMD (performance boost)
        if self.has_avx2() || self.has_neon() {
            score += 10;
        }

        // Check for AVX-512 (additional performance)
        if self.has_avx512() {
            score += 5;
        }

        let level = match score {
            0..=30 => SecurityLevel::Basic,
            31..=60 => SecurityLevel::Good,
            61..=85 => SecurityLevel::Excellent,
            _ => SecurityLevel::Optimal,
        };

        SecurityAssessment {
            score,
            level,
            recommendations,
        }
    }

    /// Returns an estimate of AES-GCM throughput capability.
    pub fn estimated_aes_gcm_throughput(&self) -> ThroughputEstimate {
        if self.has_vaes() && self.vpclmulqdq {
            ThroughputEstimate::VeryHigh // 10+ GB/s possible
        } else if self.has_aes_ni() && self.pclmulqdq {
            if self.avx2 {
                ThroughputEstimate::High // 3-6 GB/s
            } else {
                ThroughputEstimate::Medium // 1-3 GB/s
            }
        } else if self.arm_aes && self.arm_pmull {
            ThroughputEstimate::Medium // 1-3 GB/s on modern ARM
        } else {
            ThroughputEstimate::Low // < 500 MB/s software implementation
        }
    }
}

impl fmt::Display for HardwareCapabilities {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Hardware Cryptographic Capabilities")?;
        writeln!(f, "====================================")?;
        writeln!(f, "CPU Vendor: {}", self.vendor)?;
        if !self.cpu_brand.is_empty() {
            writeln!(f, "CPU Model:  {}", self.cpu_brand)?;
        }
        writeln!(f)?;

        let features = self.available_features();
        if features.is_empty() {
            writeln!(f, "No hardware acceleration features detected")?;
        } else {
            writeln!(f, "Available features ({}):", features.len())?;
            for feature in features {
                writeln!(f, "  - {}", feature)?;
            }
        }

        writeln!(f)?;
        writeln!(f, "Acceleration Summary:")?;
        writeln!(
            f,
            "  AES:  {}",
            if self.has_aes_ni() {
                "Hardware"
            } else {
                "Software"
            }
        )?;
        writeln!(
            f,
            "  GCM:  {}",
            if self.has_gcm_acceleration() {
                "Hardware"
            } else {
                "Software"
            }
        )?;
        writeln!(
            f,
            "  SHA:  {}",
            if self.has_sha_acceleration() {
                "Hardware"
            } else {
                "Software"
            }
        )?;
        writeln!(
            f,
            "  RNG:  {}",
            if self.has_hardware_rng() {
                "Hardware"
            } else {
                "OS/Software"
            }
        )?;

        let assessment = self.security_assessment();
        writeln!(f)?;
        writeln!(f, "Security Assessment: {} ({}/100)", assessment.level, assessment.score)?;

        Ok(())
    }
}

/// Security level assessment based on hardware capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    /// Basic - minimal hardware acceleration
    Basic,
    /// Good - some hardware acceleration available
    Good,
    /// Excellent - most features available
    Excellent,
    /// Optimal - all recommended features available
    Optimal,
}

impl fmt::Display for SecurityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecurityLevel::Basic => write!(f, "Basic"),
            SecurityLevel::Good => write!(f, "Good"),
            SecurityLevel::Excellent => write!(f, "Excellent"),
            SecurityLevel::Optimal => write!(f, "Optimal"),
        }
    }
}

/// Security assessment result.
#[derive(Debug, Clone)]
pub struct SecurityAssessment {
    /// Score out of 100
    pub score: u32,
    /// Security level
    pub level: SecurityLevel,
    /// Recommendations for improvement
    pub recommendations: Vec<&'static str>,
}

/// Estimated throughput capability for AES-GCM operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThroughputEstimate {
    /// Low throughput (< 500 MB/s) - software implementation
    Low,
    /// Medium throughput (1-3 GB/s) - basic hardware acceleration
    Medium,
    /// High throughput (3-6 GB/s) - full hardware acceleration with AVX2
    High,
    /// Very high throughput (10+ GB/s) - AVX-512 VAES acceleration
    VeryHigh,
}

impl fmt::Display for ThroughputEstimate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ThroughputEstimate::Low => write!(f, "Low (< 500 MB/s)"),
            ThroughputEstimate::Medium => write!(f, "Medium (1-3 GB/s)"),
            ThroughputEstimate::High => write!(f, "High (3-6 GB/s)"),
            ThroughputEstimate::VeryHigh => write!(f, "Very High (10+ GB/s)"),
        }
    }
}

/// Detect hardware cryptographic capabilities on the current system.
///
/// This function queries the CPU for available instruction set extensions
/// that can accelerate cryptographic operations.
///
/// # Example
///
/// ```
/// use tesseract::crypto::hardware::detect_capabilities;
///
/// let caps = detect_capabilities();
/// println!("AES-NI available: {}", caps.has_aes_ni());
/// println!("Estimated AES-GCM throughput: {}", caps.estimated_aes_gcm_throughput());
/// ```
pub fn detect_capabilities() -> HardwareCapabilities {
    let mut caps = HardwareCapabilities::default();

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        detect_x86_capabilities(&mut caps);
    }

    #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
    {
        detect_arm_capabilities(&mut caps);
    }

    caps
}

/// Detect x86/x86_64 CPU features using CPUID.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn detect_x86_capabilities(caps: &mut HardwareCapabilities) {
    // Detect vendor
    caps.vendor = detect_x86_vendor();
    caps.cpu_brand = detect_x86_brand();

    // Use std::arch::is_x86_feature_detected! macro for reliable detection
    // These macros handle CPUID queries and OS feature flags correctly

    caps.aes_ni = std::arch::is_x86_feature_detected!("aes");
    caps.pclmulqdq = std::arch::is_x86_feature_detected!("pclmulqdq");
    caps.sha_ext = std::arch::is_x86_feature_detected!("sha");
    caps.sse2 = std::arch::is_x86_feature_detected!("sse2");
    caps.sse41 = std::arch::is_x86_feature_detected!("sse4.1");
    caps.sse42 = std::arch::is_x86_feature_detected!("sse4.2");
    caps.avx = std::arch::is_x86_feature_detected!("avx");
    caps.avx2 = std::arch::is_x86_feature_detected!("avx2");
    caps.avx512f = std::arch::is_x86_feature_detected!("avx512f");
    caps.avx512vl = std::arch::is_x86_feature_detected!("avx512vl");
    caps.vaes = std::arch::is_x86_feature_detected!("vaes");
    caps.vpclmulqdq = std::arch::is_x86_feature_detected!("vpclmulqdq");
    caps.rdrand = std::arch::is_x86_feature_detected!("rdrand");
    caps.rdseed = std::arch::is_x86_feature_detected!("rdseed");
    caps.bmi1 = std::arch::is_x86_feature_detected!("bmi1");
    caps.bmi2 = std::arch::is_x86_feature_detected!("bmi2");
    caps.adx = std::arch::is_x86_feature_detected!("adx");
}

/// Detect x86 CPU vendor from CPUID.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn detect_x86_vendor() -> CpuVendor {
    #[cfg(target_arch = "x86")]
    use std::arch::x86::__cpuid;
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::__cpuid;

    // CPUID leaf 0 returns vendor string in EBX, EDX, ECX
    let result = unsafe { __cpuid(0) };

    // Construct vendor string from registers (12 bytes)
    let mut vendor_bytes = [0u8; 12];
    vendor_bytes[0..4].copy_from_slice(&result.ebx.to_le_bytes());
    vendor_bytes[4..8].copy_from_slice(&result.edx.to_le_bytes());
    vendor_bytes[8..12].copy_from_slice(&result.ecx.to_le_bytes());

    let vendor_string = String::from_utf8_lossy(&vendor_bytes);

    match vendor_string.as_ref() {
        "GenuineIntel" => CpuVendor::Intel,
        "AuthenticAMD" => CpuVendor::Amd,
        _ => CpuVendor::Unknown,
    }
}

/// Detect x86 CPU brand string from CPUID.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn detect_x86_brand() -> String {
    #[cfg(target_arch = "x86")]
    use std::arch::x86::__cpuid;
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::__cpuid;

    // Check if extended CPUID is supported
    let result = unsafe { __cpuid(0x80000000) };
    if result.eax < 0x80000004 {
        return String::new();
    }

    // Brand string is in leaves 0x80000002, 0x80000003, 0x80000004
    let mut brand_bytes = [0u8; 48];

    for (i, leaf) in [0x80000002u32, 0x80000003, 0x80000004].iter().enumerate() {
        let result = unsafe { __cpuid(*leaf) };
        let offset = i * 16;
        brand_bytes[offset..offset + 4].copy_from_slice(&result.eax.to_le_bytes());
        brand_bytes[offset + 4..offset + 8].copy_from_slice(&result.ebx.to_le_bytes());
        brand_bytes[offset + 8..offset + 12].copy_from_slice(&result.ecx.to_le_bytes());
        brand_bytes[offset + 12..offset + 16].copy_from_slice(&result.edx.to_le_bytes());
    }

    // Convert to string, trimming null bytes and whitespace
    String::from_utf8_lossy(&brand_bytes)
        .trim_matches(char::from(0))
        .trim()
        .to_string()
}

/// Detect ARM CPU features.
#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
fn detect_arm_capabilities(caps: &mut HardwareCapabilities) {
    // Detect vendor (simplified - could be expanded with /proc/cpuinfo on Linux)
    #[cfg(target_os = "macos")]
    {
        caps.vendor = CpuVendor::Apple;
    }

    #[cfg(not(target_os = "macos"))]
    {
        caps.vendor = CpuVendor::Arm;
    }

    // Use std_detect for ARM feature detection
    #[cfg(target_arch = "aarch64")]
    {
        caps.arm_aes = std::arch::is_aarch64_feature_detected!("aes");
        caps.arm_sha2 = std::arch::is_aarch64_feature_detected!("sha2");
        caps.arm_sha3 = std::arch::is_aarch64_feature_detected!("sha3");
        caps.arm_pmull = std::arch::is_aarch64_feature_detected!("pmull");
        caps.arm_neon = std::arch::is_aarch64_feature_detected!("neon");
        caps.arm_crc32 = std::arch::is_aarch64_feature_detected!("crc");

        // SHA-1 is usually available with SHA-2 on AArch64
        caps.arm_sha1 = caps.arm_sha2;
    }

    #[cfg(all(target_arch = "arm", not(target_arch = "aarch64")))]
    {
        // 32-bit ARM feature detection is more limited
        caps.arm_neon = std::arch::is_arm_feature_detected!("neon");
    }
}

/// Get a quick summary of whether hardware acceleration is available.
///
/// Returns true if at least AES hardware acceleration is available.
///
/// # Example
///
/// ```
/// use tesseract::crypto::hardware::has_hardware_acceleration;
///
/// if has_hardware_acceleration() {
///     println!("Hardware crypto acceleration is available");
/// }
/// ```
pub fn has_hardware_acceleration() -> bool {
    let caps = detect_capabilities();
    caps.has_aes_ni()
}

/// Print a detailed hardware capabilities report to stdout.
///
/// Useful for diagnostics and debugging.
///
/// # Example
///
/// ```
/// use tesseract::crypto::hardware::print_capabilities_report;
///
/// print_capabilities_report();
/// ```
pub fn print_capabilities_report() {
    let caps = detect_capabilities();
    println!("{}", caps);

    let assessment = caps.security_assessment();
    if !assessment.recommendations.is_empty() {
        println!("Recommendations:");
        for rec in assessment.recommendations {
            println!("  ! {}", rec);
        }
    }

    println!();
    println!(
        "Estimated AES-GCM throughput: {}",
        caps.estimated_aes_gcm_throughput()
    );
}

// ============================================================================
// Benchmarking utilities
// ============================================================================

/// Result of a crypto benchmark run.
#[derive(Debug, Clone)]
pub struct BenchmarkResult {
    /// Name of the benchmark
    pub name: String,
    /// Total bytes processed
    pub bytes_processed: u64,
    /// Time taken in nanoseconds
    pub duration_ns: u64,
    /// Throughput in MB/s
    pub throughput_mbps: f64,
    /// Number of iterations
    pub iterations: u32,
}

impl fmt::Display for BenchmarkResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {:.2} MB/s ({} bytes in {:.2} ms, {} iterations)",
            self.name,
            self.throughput_mbps,
            self.bytes_processed,
            self.duration_ns as f64 / 1_000_000.0,
            self.iterations
        )
    }
}

/// Quick benchmark of AES-GCM encryption performance.
///
/// Runs a simple benchmark to measure actual AES-GCM throughput on this system.
///
/// # Arguments
///
/// * `data_size` - Size of data to encrypt per iteration (in bytes)
/// * `iterations` - Number of encryption iterations
///
/// # Returns
///
/// Benchmark result with throughput measurement.
///
/// # Example
///
/// ```
/// use tesseract::crypto::hardware::benchmark_aes_gcm;
///
/// let result = benchmark_aes_gcm(1024 * 1024, 10); // 1MB, 10 iterations
/// println!("{}", result);
/// ```
pub fn benchmark_aes_gcm(data_size: usize, iterations: u32) -> BenchmarkResult {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Nonce,
    };
    use std::time::Instant;

    // Generate test data and key
    let key = [0x42u8; 32];
    let nonce = Nonce::from_slice(&[0u8; 12]);
    let plaintext = vec![0xABu8; data_size];

    let cipher = Aes256Gcm::new_from_slice(&key).expect("Invalid key length");

    // Warm up
    let _ = cipher.encrypt(nonce, plaintext.as_ref());

    // Benchmark
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = cipher.encrypt(nonce, plaintext.as_ref());
    }
    let duration = start.elapsed();

    let bytes_processed = (data_size as u64) * (iterations as u64);
    let duration_ns = duration.as_nanos() as u64;
    let throughput_mbps = if duration_ns > 0 {
        (bytes_processed as f64 / (1024.0 * 1024.0)) / (duration_ns as f64 / 1_000_000_000.0)
    } else {
        0.0
    };

    BenchmarkResult {
        name: "AES-256-GCM Encrypt".to_string(),
        bytes_processed,
        duration_ns,
        throughput_mbps,
        iterations,
    }
}

/// Quick benchmark of AES-GCM decryption performance.
///
/// # Arguments
///
/// * `data_size` - Size of data to decrypt per iteration (in bytes)
/// * `iterations` - Number of decryption iterations
///
/// # Returns
///
/// Benchmark result with throughput measurement.
pub fn benchmark_aes_gcm_decrypt(data_size: usize, iterations: u32) -> BenchmarkResult {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Nonce,
    };
    use std::time::Instant;

    let key = [0x42u8; 32];
    let nonce = Nonce::from_slice(&[0u8; 12]);
    let plaintext = vec![0xABu8; data_size];

    let cipher = Aes256Gcm::new_from_slice(&key).expect("Invalid key length");
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .expect("Encryption failed");

    // Warm up
    let _ = cipher.decrypt(nonce, ciphertext.as_ref());

    // Benchmark
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = cipher.decrypt(nonce, ciphertext.as_ref());
    }
    let duration = start.elapsed();

    let bytes_processed = (data_size as u64) * (iterations as u64);
    let duration_ns = duration.as_nanos() as u64;
    let throughput_mbps = if duration_ns > 0 {
        (bytes_processed as f64 / (1024.0 * 1024.0)) / (duration_ns as f64 / 1_000_000_000.0)
    } else {
        0.0
    };

    BenchmarkResult {
        name: "AES-256-GCM Decrypt".to_string(),
        bytes_processed,
        duration_ns,
        throughput_mbps,
        iterations,
    }
}

/// Quick benchmark of SHA-256 hashing performance.
///
/// # Arguments
///
/// * `data_size` - Size of data to hash per iteration (in bytes)
/// * `iterations` - Number of hash iterations
///
/// # Returns
///
/// Benchmark result with throughput measurement.
pub fn benchmark_sha256(data_size: usize, iterations: u32) -> BenchmarkResult {
    use sha2::{Digest, Sha256};
    use std::time::Instant;

    let data = vec![0xABu8; data_size];

    // Warm up
    let _ = Sha256::digest(&data);

    // Benchmark
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = Sha256::digest(&data);
    }
    let duration = start.elapsed();

    let bytes_processed = (data_size as u64) * (iterations as u64);
    let duration_ns = duration.as_nanos() as u64;
    let throughput_mbps = if duration_ns > 0 {
        (bytes_processed as f64 / (1024.0 * 1024.0)) / (duration_ns as f64 / 1_000_000_000.0)
    } else {
        0.0
    };

    BenchmarkResult {
        name: "SHA-256".to_string(),
        bytes_processed,
        duration_ns,
        throughput_mbps,
        iterations,
    }
}

/// Quick benchmark of BLAKE3 hashing performance.
///
/// # Arguments
///
/// * `data_size` - Size of data to hash per iteration (in bytes)
/// * `iterations` - Number of hash iterations
///
/// # Returns
///
/// Benchmark result with throughput measurement.
pub fn benchmark_blake3(data_size: usize, iterations: u32) -> BenchmarkResult {
    use std::time::Instant;

    let data = vec![0xABu8; data_size];

    // Warm up
    let _ = blake3::hash(&data);

    // Benchmark
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = blake3::hash(&data);
    }
    let duration = start.elapsed();

    let bytes_processed = (data_size as u64) * (iterations as u64);
    let duration_ns = duration.as_nanos() as u64;
    let throughput_mbps = if duration_ns > 0 {
        (bytes_processed as f64 / (1024.0 * 1024.0)) / (duration_ns as f64 / 1_000_000_000.0)
    } else {
        0.0
    };

    BenchmarkResult {
        name: "BLAKE3".to_string(),
        bytes_processed,
        duration_ns,
        throughput_mbps,
        iterations,
    }
}

/// Run a comprehensive benchmark suite and return results.
///
/// Benchmarks AES-GCM encryption/decryption and SHA-256/BLAKE3 hashing.
///
/// # Example
///
/// ```
/// use tesseract::crypto::hardware::run_benchmark_suite;
///
/// let results = run_benchmark_suite();
/// for result in &results {
///     println!("{}", result);
/// }
/// ```
pub fn run_benchmark_suite() -> Vec<BenchmarkResult> {
    let mut results = Vec::new();

    // Use 1MB data size and 100 iterations for meaningful results
    let data_size = 1024 * 1024; // 1 MB
    let iterations = 100;

    results.push(benchmark_aes_gcm(data_size, iterations));
    results.push(benchmark_aes_gcm_decrypt(data_size, iterations));
    results.push(benchmark_sha256(data_size, iterations));
    results.push(benchmark_blake3(data_size, iterations));

    results
}

/// Print a comprehensive benchmark report.
///
/// Displays hardware capabilities and benchmark results.
///
/// # Example
///
/// ```no_run
/// use tesseract::crypto::hardware::print_benchmark_report;
///
/// print_benchmark_report();
/// ```
pub fn print_benchmark_report() {
    let caps = detect_capabilities();

    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║       Hardware Cryptographic Benchmark Report              ║");
    println!("╚════════════════════════════════════════════════════════════╝");
    println!();

    println!("System Information:");
    println!("  CPU Vendor: {}", caps.vendor);
    if !caps.cpu_brand.is_empty() {
        println!("  CPU Model:  {}", caps.cpu_brand);
    }
    println!();

    println!("Hardware Acceleration:");
    println!(
        "  AES-NI:     {}",
        if caps.has_aes_ni() { "Yes" } else { "No" }
    );
    println!(
        "  GCM (CLMUL): {}",
        if caps.has_gcm_acceleration() {
            "Yes"
        } else {
            "No"
        }
    );
    println!(
        "  SHA Ext:    {}",
        if caps.has_sha_acceleration() {
            "Yes"
        } else {
            "No"
        }
    );
    println!(
        "  AVX2:       {}",
        if caps.has_avx2() { "Yes" } else { "No" }
    );
    println!(
        "  AVX-512:    {}",
        if caps.has_avx512() { "Yes" } else { "No" }
    );
    println!(
        "  VAES:       {}",
        if caps.has_vaes() { "Yes" } else { "No" }
    );
    println!(
        "  HW RNG:     {}",
        if caps.has_hardware_rng() {
            "Yes"
        } else {
            "No"
        }
    );
    println!();

    println!("Running benchmarks (1 MB × 100 iterations)...");
    println!();

    let results = run_benchmark_suite();

    println!("Benchmark Results:");
    println!("─────────────────────────────────────────────────────────────");
    for result in &results {
        println!("  {:20} {:>10.2} MB/s", result.name, result.throughput_mbps);
    }
    println!("─────────────────────────────────────────────────────────────");
    println!();

    let assessment = caps.security_assessment();
    println!(
        "Security Assessment: {} ({}/100)",
        assessment.level, assessment.score
    );

    if !assessment.recommendations.is_empty() {
        println!();
        println!("Recommendations:");
        for rec in &assessment.recommendations {
            println!("  • {}", rec);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_capabilities() {
        let caps = detect_capabilities();

        // Should always be able to detect something
        println!("Detected capabilities:\n{}", caps);

        // Basic sanity checks
        assert!(!caps.cpu_brand.is_empty() || caps.vendor == CpuVendor::Unknown);
    }

    #[test]
    fn test_security_assessment() {
        let caps = detect_capabilities();
        let assessment = caps.security_assessment();

        // Score should be between 0 and 100
        assert!(assessment.score <= 100);

        println!("Security assessment: {} ({}/100)", assessment.level, assessment.score);
        for rec in &assessment.recommendations {
            println!("  - {}", rec);
        }
    }

    #[test]
    fn test_throughput_estimate() {
        let caps = detect_capabilities();
        let throughput = caps.estimated_aes_gcm_throughput();

        println!("Estimated throughput: {}", throughput);
    }

    #[test]
    fn test_available_features() {
        let caps = detect_capabilities();
        let features = caps.available_features();

        println!("Available features ({}):", features.len());
        for feature in &features {
            println!("  - {}", feature);
        }
    }

    #[test]
    fn test_default_capabilities() {
        let caps = HardwareCapabilities::default();

        assert_eq!(caps.vendor, CpuVendor::Unknown);
        assert!(!caps.aes_ni);
        assert!(!caps.avx2);
    }

    #[test]
    fn test_has_hardware_acceleration() {
        let result = has_hardware_acceleration();
        println!("Has hardware acceleration: {}", result);
        // Can't assert true/false as it depends on the machine
    }

    #[test]
    fn test_display_implementations() {
        assert_eq!(format!("{}", CpuVendor::Intel), "Intel");
        assert_eq!(format!("{}", CpuVendor::Amd), "AMD");
        assert_eq!(format!("{}", SecurityLevel::Optimal), "Optimal");
        assert_eq!(format!("{}", ThroughputEstimate::High), "High (3-6 GB/s)");
    }
}
