use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use tesseract::crypto::pqc::{MlKemKeyPair, encapsulate};
use tesseract::crypto::kdf::Argon2Kdf;
use tesseract::crypto::{Encryptor, KeyDerivation};
use tesseract::SecureAllocator;
use std::alloc::{GlobalAlloc, Layout};

fn bench_ml_kem_keypair_generation(c: &mut Criterion) {
    c.bench_function("ml_kem_1024_keypair_generation", |b| {
        b.iter(|| {
            let keypair = MlKemKeyPair::generate();
            black_box(keypair)
        });
    });
}

fn bench_ml_kem_encapsulation(c: &mut Criterion) {
    let keypair = MlKemKeyPair::generate();
    let public_key = keypair.encapsulation_key();

    c.bench_function("ml_kem_1024_encapsulation", |b| {
        b.iter(|| {
            let (ciphertext, _shared_secret) = encapsulate(public_key).unwrap();
            black_box(ciphertext)
        });
    });
}

fn bench_ml_kem_decapsulation(c: &mut Criterion) {
    let keypair = MlKemKeyPair::generate();
    let public_key = keypair.encapsulation_key();
    let (ciphertext, _) = encapsulate(public_key).unwrap();

    c.bench_function("ml_kem_1024_decapsulation", |b| {
        b.iter(|| {
            let shared_secret = keypair.decapsulate(&ciphertext).unwrap();
            black_box(shared_secret)
        });
    });
}

fn bench_ml_kem_roundtrip(c: &mut Criterion) {
    c.bench_function("ml_kem_1024_full_roundtrip", |b| {
        b.iter(|| {
            // Generate keypair
            let keypair = MlKemKeyPair::generate();
            let public_key = keypair.encapsulation_key();

            // Encapsulate
            let (ciphertext, shared_secret_sender) = encapsulate(public_key).unwrap();

            // Decapsulate
            let shared_secret_receiver = keypair.decapsulate(&ciphertext).unwrap();

            black_box((shared_secret_sender, shared_secret_receiver))
        });
    });
}

fn bench_ml_kem_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("ml_kem_serialization");

    let keypair = MlKemKeyPair::generate();

    group.bench_function("keypair_to_bytes", |b| {
        b.iter(|| {
            let bytes = keypair.to_bytes();
            black_box(bytes)
        });
    });

    let (ek_bytes, dk_bytes) = keypair.to_bytes();
    group.bench_function("keypair_from_bytes", |b| {
        b.iter(|| {
            let kp = MlKemKeyPair::from_bytes(&ek_bytes, &dk_bytes).unwrap();
            black_box(kp)
        });
    });

    group.finish();
}

fn bench_hybrid_mode_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("hybrid_mode");

    let kdf = Argon2Kdf::default();
    let password = b"test_password_for_benchmarking";
    let salt = kdf.generate_salt();

    // Generate PQC keypair
    let keypair = MlKemKeyPair::generate();
    let public_key = keypair.encapsulation_key();

    group.bench_function("hybrid_key_derivation_full", |b| {
        b.iter(|| {
            // Derive classical key
            let classical_key = kdf.derive_key(password, &salt).unwrap();

            // Encapsulate to get PQ shared secret
            let (_ciphertext, pq_secret) = encapsulate(public_key).unwrap();

            // Derive hybrid key using HKDF
            use hkdf::Hkdf;
            use sha2::Sha256;
            let hk = Hkdf::<Sha256>::new(Some(&salt), &*classical_key);
            let mut hybrid_key = zeroize::Zeroizing::new([0u8; 32]);
            hk.expand(&*pq_secret, &mut *hybrid_key).unwrap();

            black_box(hybrid_key)
        });
    });

    // Pre-derive keys for encryption benchmarking
    let classical_key = kdf.derive_key(password, &salt).unwrap();
    let (_ciphertext, pq_secret) = encapsulate(public_key).unwrap();

    use hkdf::Hkdf;
    use sha2::Sha256;
    let hk = Hkdf::<Sha256>::new(Some(&salt), &*classical_key);
    let mut hybrid_key = zeroize::Zeroizing::new([0u8; 32]);
    hk.expand(&*pq_secret, &mut *hybrid_key).unwrap();

    group.bench_function("hybrid_encryption_1kb", |b| {
        let plaintext = vec![0x42u8; 1024];
        let encryptor = tesseract::crypto::aes_gcm::AesGcmEncryptor;
        let nonce = [0u8; 12];

        b.iter(|| {
            let ciphertext = encryptor.encrypt(&*hybrid_key, &nonce, &plaintext).unwrap();
            black_box(ciphertext)
        });
    });

    group.bench_function("hybrid_decryption_1kb", |b| {
        let plaintext = vec![0x42u8; 1024];
        let encryptor = tesseract::crypto::aes_gcm::AesGcmEncryptor;
        let nonce = [0u8; 12];
        let ciphertext = encryptor.encrypt(&*hybrid_key, &nonce, &plaintext).unwrap();

        b.iter(|| {
            let decrypted = encryptor.decrypt(&*hybrid_key, &nonce, &ciphertext).unwrap();
            black_box(decrypted)
        });
    });

    group.finish();
}

fn bench_concurrent_pqc_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrent_pqc");

    group.bench_function("parallel_keypair_generation_4", |b| {
        b.iter(|| {
            use rayon::prelude::*;
            let keypairs: Vec<_> = (0..4)
                .into_par_iter()
                .map(|_| MlKemKeyPair::generate())
                .collect();
            black_box(keypairs)
        });
    });

    let keypairs: Vec<_> = (0..4).map(|_| MlKemKeyPair::generate()).collect();
    let public_keys: Vec<_> = keypairs.iter().map(|kp| kp.encapsulation_key().to_vec()).collect();

    group.bench_function("parallel_encapsulation_4", |b| {
        b.iter(|| {
            use rayon::prelude::*;
            let results: Vec<_> = public_keys
                .par_iter()
                .map(|pk| encapsulate(pk).unwrap())
                .collect();
            black_box(results)
        });
    });

    group.finish();
}

fn bench_memory_allocator_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("pqc_memory_overhead");

    let allocator = SecureAllocator::new();

    // Benchmark memory allocation overhead for PQC-sized allocations
    // ML-KEM-1024 public key is ~1568 bytes, ciphertext is ~1568 bytes
    let pqc_sizes = [1568, 3168, 4096];

    for size in pqc_sizes.iter() {
        group.bench_with_input(BenchmarkId::new("secure_alloc", size), size, |b, &size| {
            b.iter(|| {
                let layout = Layout::from_size_align(size, 8).unwrap();
                unsafe {
                    let ptr = allocator.alloc(layout);
                    black_box(ptr);
                    allocator.dealloc(ptr, layout);
                }
            });
        });
    }

    group.finish();
}

fn bench_pqc_data_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("pqc_encryption_by_size");

    let keypair = MlKemKeyPair::generate();
    let public_key = keypair.encapsulation_key();
    let kdf = Argon2Kdf::default();
    let password = b"benchmark";
    let salt = kdf.generate_salt();

    // Derive hybrid key
    let classical_key = kdf.derive_key(password, &salt).unwrap();
    let (_ciphertext, pq_secret) = encapsulate(public_key).unwrap();

    use hkdf::Hkdf;
    use sha2::Sha256;
    let hk = Hkdf::<Sha256>::new(Some(&salt), &*classical_key);
    let mut hybrid_key = zeroize::Zeroizing::new([0u8; 32]);
    hk.expand(&*pq_secret, &mut *hybrid_key).unwrap();

    let encryptor = tesseract::crypto::aes_gcm::AesGcmEncryptor;

    for size in [1024, 4096, 16384, 65536, 262144].iter() {
        group.bench_with_input(BenchmarkId::new("encrypt", size), size, |b, &size| {
            let plaintext = vec![0x42u8; size];
            let nonce = [0u8; 12];

            b.iter(|| {
                let ciphertext = encryptor.encrypt(&*hybrid_key, &nonce, &plaintext).unwrap();
                black_box(ciphertext)
            });
        });

        group.bench_with_input(BenchmarkId::new("decrypt", size), size, |b, &size| {
            let plaintext = vec![0x42u8; size];
            let nonce = [0u8; 12];
            let ciphertext = encryptor.encrypt(&*hybrid_key, &nonce, &plaintext).unwrap();

            b.iter(|| {
                let decrypted = encryptor.decrypt(&*hybrid_key, &nonce, &ciphertext).unwrap();
                black_box(decrypted)
            });
        });
    }

    group.finish();
}

fn bench_volume_header_pqc(c: &mut Criterion) {
    use tesseract::volume::header::{VolumeHeader, PqVolumeMetadata, PqAlgorithm};

    let mut group = c.benchmark_group("volume_header_pqc");

    // Pre-generate keypair and metadata for benchmarking
    let keypair = MlKemKeyPair::generate();
    let (ciphertext, _) = encapsulate(keypair.encapsulation_key()).unwrap();

    use base64::Engine;
    let pq_metadata = PqVolumeMetadata {
        algorithm: PqAlgorithm::MlKem1024,
        encapsulation_key: base64::engine::general_purpose::STANDARD.encode(keypair.encapsulation_key()),
        ciphertext: base64::engine::general_purpose::STANDARD.encode(&ciphertext),
        encrypted_decapsulation_key: "benchmark_encrypted_key".to_string(),
    };

    let pq_size = pq_metadata.to_json_bytes().unwrap().len() as u32;

    // Benchmark creating a V2 header with PQC
    group.bench_function("create_v2_header_with_pqc", |b| {
        b.iter(|| {
            let header = VolumeHeader::new_with_pqc(
                1024 * 1024 * 1024, // 1GB volume
                4096,                // 4KB sectors
                [0x42u8; 32],        // salt
                [0x43u8; 12],        // header IV
                pq_size,             // PQ metadata size
            );
            black_box(header)
        });
    });

    // Pre-create header for serialization benchmarks
    let header = VolumeHeader::new_with_pqc(
        1024 * 1024 * 1024,
        4096,
        [0x42u8; 32],
        [0x43u8; 12],
        pq_size,
    );

    // Benchmark serializing header to bytes
    group.bench_function("serialize_v2_header", |b| {
        b.iter(|| {
            let bytes = header.to_bytes().unwrap();
            black_box(bytes)
        });
    });

    // Pre-serialize for deserialization benchmark
    let header_bytes = header.to_bytes().unwrap();

    // Benchmark deserializing header from bytes
    group.bench_function("deserialize_v2_header", |b| {
        b.iter(|| {
            let parsed = VolumeHeader::from_bytes(&header_bytes).unwrap();
            black_box(parsed)
        });
    });

    // Benchmark full roundtrip (create + serialize + deserialize)
    group.bench_function("header_full_roundtrip", |b| {
        b.iter(|| {
            let header = VolumeHeader::new_with_pqc(
                1024 * 1024 * 1024,
                4096,
                [0x44u8; 32],
                [0x45u8; 12],
                pq_size,
            );
            let bytes = header.to_bytes().unwrap();
            let parsed = VolumeHeader::from_bytes(&bytes).unwrap();
            black_box(parsed)
        });
    });

    // Benchmark PqVolumeMetadata serialization
    group.bench_function("pq_metadata_serialization", |b| {
        b.iter(|| {
            let bytes = pq_metadata.to_json_bytes().unwrap();
            black_box(bytes)
        });
    });

    let pq_json_bytes = pq_metadata.to_json_bytes().unwrap();
    group.bench_function("pq_metadata_deserialization", |b| {
        b.iter(|| {
            let metadata = PqVolumeMetadata::from_json_bytes(&pq_json_bytes).unwrap();
            black_box(metadata)
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_ml_kem_keypair_generation,
    bench_ml_kem_encapsulation,
    bench_ml_kem_decapsulation,
    bench_ml_kem_roundtrip,
    bench_ml_kem_serialization,
    bench_hybrid_mode_operations,
    bench_concurrent_pqc_operations,
    bench_memory_allocator_overhead,
    bench_pqc_data_sizes,
    bench_volume_header_pqc
);
criterion_main!(benches);
