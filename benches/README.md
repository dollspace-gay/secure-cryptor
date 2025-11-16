# Streaming Encryption Benchmarks

This directory contains performance benchmarks for the streaming encryption implementation.

## Running Benchmarks

To run all benchmarks:

```bash
cargo bench
```

To run a specific benchmark group:

```bash
cargo bench streaming_encryption
cargo bench streaming_decryption
cargo bench chunk_sizes
cargo bench streaming_vs_non_streaming
cargo bench roundtrip
```

## Benchmark Groups

### 1. Streaming Encryption
Tests encryption performance with different file sizes (1MB, 10MB, 50MB) using the default chunk size (1MB).

**Metrics:**
- Throughput (MB/s)
- Time per operation

### 2. Streaming Decryption
Tests decryption performance with different file sizes (1MB, 10MB, 50MB).

**Metrics:**
- Throughput (MB/s)
- Time per operation

### 3. Chunk Sizes
Compares performance across different chunk sizes (4KB, 64KB, 256KB, 1MB, 4MB) using a 10MB file.

**Purpose:** Identify optimal chunk size for different use cases.

### 4. Streaming vs Non-Streaming
Compares streaming encryption against traditional (non-streaming) file encryption for a 5MB file.

**Purpose:** Validate that streaming approach doesn't introduce significant overhead.

### 5. Roundtrip
Measures full encrypt + decrypt cycle performance for 1MB and 10MB files.

**Metrics:**
- Total time for complete roundtrip
- Combined throughput

## Interpreting Results

Criterion generates detailed reports in `target/criterion/` including:
- HTML reports with charts
- Statistical analysis
- Comparison with previous runs

### Expected Performance

On a modern system, you should expect:
- **Throughput**: 100-500 MB/s (depends on CPU, chunk size, and file size)
- **Memory usage**: Constant (1-4MB) regardless of file size for streaming
- **Optimal chunk size**: 256KB - 1MB for most use cases

### Performance Factors

1. **Chunk Size Impact:**
   - Smaller chunks: More overhead, lower throughput, better progress tracking
   - Larger chunks: Higher throughput, less overhead, coarser progress updates

2. **File Size Impact:**
   - Larger files amortize setup costs
   - Throughput increases with file size due to better cache utilization

3. **CPU Factors:**
   - AES-NI hardware acceleration significantly improves performance
   - Multi-core systems will benefit from future parallel chunk processing

## Adding New Benchmarks

To add a new benchmark:

1. Add a function to `streaming_benchmark.rs`:
```rust
fn bench_my_feature(c: &mut Criterion) {
    let mut group = c.benchmark_group("my_feature");
    // ... benchmark code ...
    group.finish();
}
```

2. Add to criterion_group!:
```rust
criterion_group!(
    benches,
    // ... existing benchmarks ...
    bench_my_feature,
);
```

## Continuous Performance Monitoring

For CI/CD integration, save baseline results:

```bash
cargo bench -- --save-baseline main
```

Compare against baseline:

```bash
cargo bench -- --baseline main
```
