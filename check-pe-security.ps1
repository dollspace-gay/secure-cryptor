param([string]$ExePath = "target\release\tesseract-vault.exe")

$bytes = [System.IO.File]::ReadAllBytes($ExePath)

# PE signature offset is at 0x3C
$peOffset = [BitConverter]::ToInt32($bytes, 0x3C)

# Check PE signature
$peSignature = [System.Text.Encoding]::ASCII.GetString($bytes, $peOffset, 4)
Write-Host "PE Signature: $peSignature"

# Optional header magic
$optionalMagic = [BitConverter]::ToUInt16($bytes, $peOffset + 24)
if ($optionalMagic -eq 0x20b) {
    Write-Host "Format: PE32+ (64-bit)"
    # DllCharacteristics at offset 70 from optional header start for PE32+
    $dllChar = [BitConverter]::ToUInt16($bytes, $peOffset + 24 + 70)
} else {
    Write-Host "Format: PE32 (32-bit)"
    # DllCharacteristics at offset 70 from optional header start for PE32
    $dllChar = [BitConverter]::ToUInt16($bytes, $peOffset + 24 + 70)
}

$dllCharHex = "0x" + $dllChar.ToString("X4")
Write-Host ""
Write-Host "=== Security Features (DllCharacteristics: $dllCharHex) ==="
Write-Host ""

# Check individual flags
$DYNAMIC_BASE = 0x0040     # ASLR
$NX_COMPAT = 0x0100        # DEP/NX
$HIGH_ENTROPY_VA = 0x0020  # High-entropy ASLR
$FORCE_INTEGRITY = 0x0080  # Code signing
$NO_SEH = 0x0400           # No structured exception handling
$GUARD_CF = 0x4000         # Control Flow Guard

if ($dllChar -band $DYNAMIC_BASE) {
    Write-Host "[PASS] ASLR (DYNAMIC_BASE) enabled"
} else {
    Write-Host "[FAIL] ASLR (DYNAMIC_BASE) NOT enabled"
}

if ($dllChar -band $NX_COMPAT) {
    Write-Host "[PASS] DEP/NX (NX_COMPAT) enabled"
} else {
    Write-Host "[FAIL] DEP/NX (NX_COMPAT) NOT enabled"
}

if ($dllChar -band $HIGH_ENTROPY_VA) {
    Write-Host "[PASS] High-entropy ASLR (64-bit) enabled"
} else {
    Write-Host "[INFO] High-entropy ASLR not enabled (optional for 64-bit)"
}

if ($dllChar -band $GUARD_CF) {
    Write-Host "[PASS] Control Flow Guard (CFG) enabled"
} else {
    Write-Host "[INFO] Control Flow Guard not enabled (requires /guard:cf linker flag)"
}

if ($dllChar -band $NO_SEH) {
    Write-Host "[PASS] NO_SEH - Uses table-based exception handling"
} else {
    Write-Host "[INFO] Uses SEH (legacy exception handling)"
}

if ($dllChar -band $FORCE_INTEGRITY) {
    Write-Host "[PASS] FORCE_INTEGRITY - Code signing required"
} else {
    Write-Host "[INFO] Code signing not enforced"
}

Write-Host ""
Write-Host "=== Summary ==="
$required = ($dllChar -band $DYNAMIC_BASE) -and ($dllChar -band $NX_COMPAT)
if ($required) {
    Write-Host "[OK] Binary has essential security hardening (ASLR + DEP)"
} else {
    Write-Host "[WARNING] Binary missing essential security features!"
}
