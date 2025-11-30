#!/bin/bash
# Syscall profiling for security audit
# Checks for unexpected network/system calls

source ~/.cargo/env 2>/dev/null

BINARY="/mnt/c/Users/texas/Tesseract/Tesseract/target/release/tesseract-vault"

echo "=== Syscall Profiling with strace ==="
echo "Checking for unexpected syscalls (especially network-related)"
echo ""

# Check if binary exists
if [ ! -f "$BINARY" ]; then
    echo "Binary not found at $BINARY"
    exit 1
fi

echo "Binary: $BINARY"
echo ""

# Run strace with syscall summary for --help (quick, safe operation)
echo "=== Syscall Summary (--help command) ==="
strace -c "$BINARY" --help 2>&1

echo ""
echo "=== Checking for network syscalls ==="
# Look for socket, connect, bind, sendto, recvfrom, etc.
strace -e trace=network "$BINARY" --help 2>&1 | head -20

echo ""
echo "=== Analysis ==="
# Check if any socket syscalls were made
if strace -e trace=network "$BINARY" --help 2>&1 | grep -q "socket\|connect\|bind\|send\|recv"; then
    echo "[WARNING] Network syscalls detected!"
else
    echo "[OK] No network syscalls detected"
fi
