#!/usr/bin/env bash
# Cross-compiles the Windows sensor. Needs: rustup target x86_64-pc-windows-gnu
# and the mingw-w64 linker (Debian/Ubuntu: apt install gcc-mingw-w64-x86-64).
set -euo pipefail
cd "$(dirname "$0")/.."
rustup target add x86_64-pc-windows-gnu
CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc \
  cargo build --release -p postern-sensor --target x86_64-pc-windows-gnu
ls -la target/x86_64-pc-windows-gnu/release/postern-sensor.exe
