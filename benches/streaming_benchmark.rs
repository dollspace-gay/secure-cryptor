use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use secure_cryptor::crypto::aes_gcm::AesGcmEncryptor;
use secure_cryptor::crypto::streaming::{
    ChunkedDecryptor, ChunkedEncryptor, ChunkedReader, StreamConfig, MIN_CHUNK_SIZE,
};
use secure_cryptor::encrypt_file;
use std::io::Write;
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

use argon2::password_hash::rand_core::{OsRng, RngCore};
use secure_cryptor::config::NONCE_LEN;

/// Creates a temporary file with random data of the specified size.
fn create_test_file(size: usize) -> NamedTempFile {
    let mut file = NamedTempFile::new().unwrap();
    let data = vec![42u8; size];
    file.write_all(&data).unwrap();
    file.flush().unwrap();
    file
}

/// Benchmark streaming encryption with different file sizes.
fn bench_streaming_encryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("streaming_encryption");

    // Test with different file sizes: 1MB, 10MB, 50MB
    for size in [1024 * 1024, 10 * 1024 * 1024, 50 * 1024 * 1024].iter() {
        let size_mb = size / (1024 * 1024);

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(format!("{}MB", size_mb)), size, |b, &size| {
            b.iter(|| {
                let input_file = create_test_file(size);
                let config = StreamConfig::default();
                let reader = ChunkedReader::open(input_file.path(), config).unwrap();

                let key = Zeroizing::new([1u8; 32]);
                let mut base_nonce = [0u8; NONCE_LEN];
                OsRng.fill_bytes(&mut base_nonce);

                let encryptor = ChunkedEncryptor::new(
                    reader,
                    Box::new(AesGcmEncryptor::new()),
                    key,
                    base_nonce,
                    "benchmark_salt".to_string(),
                );

                let mut output = Vec::new();
                encryptor.encrypt_to(&mut output).unwrap();
                black_box(output);
            });
        });
    }

    group.finish();
}

/// Benchmark streaming decryption with different file sizes.
fn bench_streaming_decryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("streaming_decryption");

    for size in [1024 * 1024, 10 * 1024 * 1024, 50 * 1024 * 1024].iter() {
        let size_mb = size / (1024 * 1024);

        // Pre-encrypt data for decryption benchmark
        let input_file = create_test_file(*size);
        let config = StreamConfig::default();
        let reader = ChunkedReader::open(input_file.path(), config).unwrap();

        let key = Zeroizing::new([1u8; 32]);
        let mut base_nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut base_nonce);

        let encryptor = ChunkedEncryptor::new(
            reader,
            Box::new(AesGcmEncryptor::new()),
            key.clone(),
            base_nonce,
            "benchmark_salt".to_string(),
        );

        let mut encrypted = Vec::new();
        encryptor.encrypt_to(&mut encrypted).unwrap();

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}MB", size_mb)),
            &encrypted,
            |b, encrypted_data| {
                b.iter(|| {
                    let cursor = std::io::Cursor::new(encrypted_data.clone());
                    let mut decryptor = ChunkedDecryptor::new(
                        cursor,
                        Box::new(AesGcmEncryptor::new()),
                        key.clone(),
                    )
                    .unwrap();

                    let mut output = Vec::new();
                    decryptor.decrypt_to(&mut output).unwrap();
                    black_box(output);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark different chunk sizes.
fn bench_chunk_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("chunk_sizes");
    let file_size = 10 * 1024 * 1024; // 10MB

    // Test chunk sizes: 4KB (min), 64KB, 256KB, 1MB, 4MB
    for chunk_size in [
        MIN_CHUNK_SIZE,
        64 * 1024,
        256 * 1024,
        1024 * 1024,
        4 * 1024 * 1024,
    ]
    .iter()
    {
        let chunk_kb = chunk_size / 1024;

        group.throughput(Throughput::Bytes(file_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}KB", chunk_kb)),
            chunk_size,
            |b, &chunk_size| {
                b.iter(|| {
                    let input_file = create_test_file(file_size);
                    let config = StreamConfig::new(chunk_size).unwrap();
                    let reader = ChunkedReader::open(input_file.path(), config).unwrap();

                    let key = Zeroizing::new([1u8; 32]);
                    let mut base_nonce = [0u8; NONCE_LEN];
                    OsRng.fill_bytes(&mut base_nonce);

                    let encryptor = ChunkedEncryptor::new(
                        reader,
                        Box::new(AesGcmEncryptor::new()),
                        key,
                        base_nonce,
                        "benchmark_salt".to_string(),
                    );

                    let mut output = Vec::new();
                    encryptor.encrypt_to(&mut output).unwrap();
                    black_box(output);
                });
            },
        );
    }

    group.finish();
}

/// Compare streaming vs non-streaming encryption.
fn bench_streaming_vs_non_streaming(c: &mut Criterion) {
    let mut group = c.benchmark_group("streaming_vs_non_streaming");
    let file_size = 5 * 1024 * 1024; // 5MB

    group.throughput(Throughput::Bytes(file_size as u64));

    // Streaming encryption
    group.bench_function("streaming", |b| {
        b.iter(|| {
            let input_file = create_test_file(file_size);
            let config = StreamConfig::default();
            let reader = ChunkedReader::open(input_file.path(), config).unwrap();

            let key = Zeroizing::new([1u8; 32]);
            let mut base_nonce = [0u8; NONCE_LEN];
            OsRng.fill_bytes(&mut base_nonce);

            let encryptor = ChunkedEncryptor::new(
                reader,
                Box::new(AesGcmEncryptor::new()),
                key,
                base_nonce,
                "benchmark_salt".to_string(),
            );

            let mut output = Vec::new();
            encryptor.encrypt_to(&mut output).unwrap();
            black_box(output);
        });
    });

    // Non-streaming (traditional) encryption
    group.bench_function("non_streaming", |b| {
        b.iter(|| {
            let input_file = create_test_file(file_size);
            let output_file = NamedTempFile::new().unwrap();

            encrypt_file(
                input_file.path(),
                output_file.path(),
                "BenchmarkPassword123!",
            )
            .unwrap();
            black_box(output_file);
        });
    });

    group.finish();
}

/// Benchmark roundtrip (encrypt + decrypt).
fn bench_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("roundtrip");

    for size in [1024 * 1024, 10 * 1024 * 1024].iter() {
        let size_mb = size / (1024 * 1024);

        group.throughput(Throughput::Bytes((*size * 2) as u64)); // Count both encrypt and decrypt
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}MB", size_mb)),
            size,
            |b, &size| {
                b.iter(|| {
                    // Encrypt
                    let input_file = create_test_file(size);
                    let config = StreamConfig::default();
                    let reader = ChunkedReader::open(input_file.path(), config).unwrap();

                    let key = Zeroizing::new([1u8; 32]);
                    let mut base_nonce = [0u8; NONCE_LEN];
                    OsRng.fill_bytes(&mut base_nonce);

                    let encryptor = ChunkedEncryptor::new(
                        reader,
                        Box::new(AesGcmEncryptor::new()),
                        key.clone(),
                        base_nonce,
                        "benchmark_salt".to_string(),
                    );

                    let mut encrypted = Vec::new();
                    encryptor.encrypt_to(&mut encrypted).unwrap();

                    // Decrypt
                    let cursor = std::io::Cursor::new(encrypted);
                    let mut decryptor =
                        ChunkedDecryptor::new(cursor, Box::new(AesGcmEncryptor::new()), key)
                            .unwrap();

                    let mut output = Vec::new();
                    decryptor.decrypt_to(&mut output).unwrap();
                    black_box(output);
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_streaming_encryption,
    bench_streaming_decryption,
    bench_chunk_sizes,
    bench_streaming_vs_non_streaming,
    bench_roundtrip,
);
criterion_main!(benches);
