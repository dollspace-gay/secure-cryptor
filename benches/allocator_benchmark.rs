use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use tesseract::SecureAllocator;
use std::alloc::{GlobalAlloc, Layout, System};

fn bench_system_allocator(c: &mut Criterion) {
    let mut group = c.benchmark_group("system_allocator");

    for size in [64, 256, 1024, 4096, 16384].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter(|| {
                let layout = Layout::from_size_align(size, 8).unwrap();
                unsafe {
                    let ptr = System.alloc(layout);
                    black_box(ptr);
                    System.dealloc(ptr, layout);
                }
            });
        });
    }
    group.finish();
}

fn bench_secure_allocator(c: &mut Criterion) {
    let mut group = c.benchmark_group("secure_allocator");
    let allocator = SecureAllocator::new();

    for size in [64, 256, 1024, 4096, 16384].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
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

fn bench_secure_allocator_zeroed(c: &mut Criterion) {
    let mut group = c.benchmark_group("secure_allocator_zeroed");
    let allocator = SecureAllocator::new();

    for size in [64, 256, 1024, 4096, 16384].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter(|| {
                let layout = Layout::from_size_align(size, 8).unwrap();
                unsafe {
                    let ptr = allocator.alloc_zeroed(layout);
                    black_box(ptr);
                    allocator.dealloc(ptr, layout);
                }
            });
        });
    }
    group.finish();
}

fn bench_secure_allocator_realloc(c: &mut Criterion) {
    let mut group = c.benchmark_group("secure_allocator_realloc");
    let allocator = SecureAllocator::new();

    for size in [256, 1024, 4096].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter(|| {
                let layout = Layout::from_size_align(size, 8).unwrap();
                unsafe {
                    let ptr = allocator.alloc(layout);
                    let new_ptr = allocator.realloc(ptr, layout, size * 2);
                    black_box(new_ptr);
                    allocator.dealloc(new_ptr, Layout::from_size_align(size * 2, 8).unwrap());
                }
            });
        });
    }
    group.finish();
}

fn bench_allocation_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("allocation_overhead_comparison");
    let secure_allocator = SecureAllocator::new();

    // Benchmark with mixed allocation sizes to simulate real-world usage
    group.bench_function("system_mixed", |b| {
        b.iter(|| {
            unsafe {
                let small = System.alloc(Layout::from_size_align(64, 8).unwrap());
                let medium = System.alloc(Layout::from_size_align(1024, 8).unwrap());
                let large = System.alloc(Layout::from_size_align(4096, 8).unwrap());

                black_box((small, medium, large));

                System.dealloc(small, Layout::from_size_align(64, 8).unwrap());
                System.dealloc(medium, Layout::from_size_align(1024, 8).unwrap());
                System.dealloc(large, Layout::from_size_align(4096, 8).unwrap());
            }
        });
    });

    group.bench_function("secure_mixed", |b| {
        b.iter(|| {
            unsafe {
                let small = secure_allocator.alloc(Layout::from_size_align(64, 8).unwrap());
                let medium = secure_allocator.alloc(Layout::from_size_align(1024, 8).unwrap());
                let large = secure_allocator.alloc(Layout::from_size_align(4096, 8).unwrap());

                black_box((small, medium, large));

                secure_allocator.dealloc(small, Layout::from_size_align(64, 8).unwrap());
                secure_allocator.dealloc(medium, Layout::from_size_align(1024, 8).unwrap());
                secure_allocator.dealloc(large, Layout::from_size_align(4096, 8).unwrap());
            }
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_system_allocator,
    bench_secure_allocator,
    bench_secure_allocator_zeroed,
    bench_secure_allocator_realloc,
    bench_allocation_overhead
);
criterion_main!(benches);
