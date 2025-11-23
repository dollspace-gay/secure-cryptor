use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use tesseract::memory::pool::{EncryptedMemoryPool, SecurityLevel};

/// Benchmark pool creation for different security levels.
fn bench_pool_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("pool_creation");

    for security_level in [SecurityLevel::Standard, SecurityLevel::High, SecurityLevel::Maximum] {
        let level_name = format!("{:?}", security_level);
        group.bench_function(&level_name, |b| {
            b.iter(|| {
                let pool = EncryptedMemoryPool::new(security_level).unwrap();
                black_box(pool);
            });
        });
    }

    group.finish();
}

/// Benchmark allocation performance for different sizes.
fn bench_allocation_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("allocation_sizes");

    // Test with different allocation sizes: 1KB, 16KB, 256KB, 1MB, 16MB
    for size in [1024, 16 * 1024, 256 * 1024, 1024 * 1024, 16 * 1024 * 1024].iter() {
        let size_kb = size / 1024;
        group.throughput(Throughput::Bytes(*size as u64));

        // Test with Standard security level
        group.bench_with_input(
            BenchmarkId::new("Standard", format!("{}KB", size_kb)),
            size,
            |b, &size| {
                let pool = EncryptedMemoryPool::new(SecurityLevel::Standard).unwrap();
                b.iter(|| {
                    let allocation = pool.allocate(size).unwrap();
                    black_box(allocation);
                });
            },
        );

        // Test with High security level (includes memory locking)
        group.bench_with_input(
            BenchmarkId::new("High", format!("{}KB", size_kb)),
            size,
            |b, &size| {
                let pool = EncryptedMemoryPool::new(SecurityLevel::High).unwrap();
                b.iter(|| {
                    let allocation = pool.allocate(size).unwrap();
                    black_box(allocation);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark write (encryption) performance.
fn bench_write_performance(c: &mut Criterion) {
    let mut group = c.benchmark_group("write_encryption");

    // Test with different data sizes
    for size in [1024, 64 * 1024, 1024 * 1024].iter() {
        let size_kb = size / 1024;
        group.throughput(Throughput::Bytes(*size as u64));

        for security_level in [SecurityLevel::Standard, SecurityLevel::High] {
            let level_name = format!("{:?}", security_level);
            group.bench_with_input(
                BenchmarkId::new(&level_name, format!("{}KB", size_kb)),
                size,
                |b, &size| {
                    let pool = EncryptedMemoryPool::new(security_level).unwrap();
                    let data = vec![42u8; size];

                    b.iter(|| {
                        let mut allocation = pool.allocate(size).unwrap();
                        allocation.write(&data).unwrap();
                        black_box(allocation);
                    });
                },
            );
        }
    }

    group.finish();
}

/// Benchmark read (decryption) performance.
fn bench_read_performance(c: &mut Criterion) {
    let mut group = c.benchmark_group("read_decryption");

    // Test with different data sizes
    for size in [1024, 64 * 1024, 1024 * 1024].iter() {
        let size_kb = size / 1024;
        group.throughput(Throughput::Bytes(*size as u64));

        for security_level in [SecurityLevel::Standard, SecurityLevel::High] {
            let level_name = format!("{:?}", security_level);
            group.bench_with_input(
                BenchmarkId::new(&level_name, format!("{}KB", size_kb)),
                size,
                |b, &size| {
                    let pool = EncryptedMemoryPool::new(security_level).unwrap();
                    let data = vec![42u8; size];
                    let mut allocation = pool.allocate(size).unwrap();
                    allocation.write(&data).unwrap();

                    b.iter(|| {
                        let decrypted = allocation.read().unwrap();
                        black_box(decrypted);
                    });
                },
            );
        }
    }

    group.finish();
}

/// Benchmark write-read roundtrip (encrypt + decrypt).
fn bench_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("roundtrip");

    for size in [1024, 64 * 1024, 1024 * 1024].iter() {
        let size_kb = size / 1024;
        group.throughput(Throughput::Bytes((*size * 2) as u64)); // Count both operations

        for security_level in [SecurityLevel::Standard, SecurityLevel::High] {
            let level_name = format!("{:?}", security_level);
            group.bench_with_input(
                BenchmarkId::new(&level_name, format!("{}KB", size_kb)),
                size,
                |b, &size| {
                    let pool = EncryptedMemoryPool::new(security_level).unwrap();
                    let data = vec![42u8; size];

                    b.iter(|| {
                        let mut allocation = pool.allocate(size).unwrap();
                        allocation.write(&data).unwrap();
                        let decrypted = allocation.read().unwrap();
                        black_box(decrypted);
                    });
                },
            );
        }
    }

    group.finish();
}

/// Benchmark key rotation performance.
fn bench_key_rotation(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_rotation");

    for security_level in [SecurityLevel::Standard, SecurityLevel::High, SecurityLevel::Maximum] {
        let level_name = format!("{:?}", security_level);
        group.bench_function(&level_name, |b| {
            let pool = EncryptedMemoryPool::new(security_level).unwrap();
            b.iter(|| {
                pool.rotate_key().unwrap();
                black_box(&pool);
            });
        });
    }

    group.finish();
}

/// Benchmark multiple concurrent allocations.
fn bench_multiple_allocations(c: &mut Criterion) {
    let mut group = c.benchmark_group("multiple_allocations");

    // Test creating multiple allocations of 16KB each
    for count in [10, 50, 100].iter() {
        group.throughput(Throughput::Elements(*count as u64));

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_allocations", count)),
            count,
            |b, &count| {
                let pool = EncryptedMemoryPool::new(SecurityLevel::Standard).unwrap();
                let data = vec![42u8; 16 * 1024];

                b.iter(|| {
                    let mut allocations = Vec::new();
                    for _ in 0..count {
                        let mut allocation = pool.allocate(16 * 1024).unwrap();
                        allocation.write(&data).unwrap();
                        allocations.push(allocation);
                    }
                    black_box(allocations);
                });
            },
        );
    }

    group.finish();
}

/// Compare overhead of different security levels.
fn bench_security_level_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("security_level_overhead");
    let size = 64 * 1024; // 64KB
    let data = vec![42u8; size];

    group.throughput(Throughput::Bytes(size as u64));

    for security_level in [SecurityLevel::Standard, SecurityLevel::High, SecurityLevel::Maximum] {
        let level_name = format!("{:?}", security_level);
        group.bench_function(&level_name, |b| {
            b.iter(|| {
                let pool = EncryptedMemoryPool::new(security_level).unwrap();
                let mut allocation = pool.allocate(size).unwrap();
                allocation.write(&data).unwrap();
                let decrypted = allocation.read().unwrap();
                black_box(decrypted);
            });
        });
    }

    group.finish();
}

/// Benchmark allocation drop and zeroization.
fn bench_drop_zeroization(c: &mut Criterion) {
    let mut group = c.benchmark_group("drop_zeroization");

    for size in [1024, 64 * 1024, 1024 * 1024].iter() {
        let size_kb = size / 1024;
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}KB", size_kb)),
            size,
            |b, &size| {
                let pool = EncryptedMemoryPool::new(SecurityLevel::Standard).unwrap();
                let data = vec![42u8; size];

                b.iter(|| {
                    let mut allocation = pool.allocate(size).unwrap();
                    allocation.write(&data).unwrap();
                    drop(allocation); // Explicitly measure drop time
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_pool_creation,
    bench_allocation_sizes,
    bench_write_performance,
    bench_read_performance,
    bench_roundtrip,
    bench_key_rotation,
    bench_multiple_allocations,
    bench_security_level_overhead,
    bench_drop_zeroization,
);
criterion_main!(benches);
