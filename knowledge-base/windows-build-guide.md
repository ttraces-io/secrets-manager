# `traces-sm` â€” Windows Desktop Application Build Guide

This guide provides step-by-step instructions to build, run, and package the **`traces-sm-desktop`** native desktop application on **Windows 10 / Windows 11**.

---

## ðŸ“‹ Prerequisites

1. **Rust Toolchain**:
   Installed via [rustup.rs](https://rustup.rs). Default host target on Windows: `x86_64-pc-windows-msvc`.
   ```powershell
   rustup default stable-x86_64-pc-windows-msvc
   ```

2. **Visual Studio C++ Build Tools**:
   Install [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) with the **"Desktop development with C++"** workload (provides `link.exe` and C++ runtime libraries).

---

## âš¡ Step-by-Step Build & Execution Instructions

### 1. Open PowerShell
Navigate to the root directory:
```powershell
cd c:\Users\admin\Downloads\Secrets-Manager
```

### 2. Build and Launch the Desktop App
To compile and launch the Windows desktop console directly:
```powershell
cd desktop
cargo run --release
```

### 3. Or Build the Standalone `.exe` Binary Only
```powershell
cd desktop
cargo build --release
```
The compiled executable output:
`c:\Users\admin\Downloads\Secrets-Manager\target\release\traces-sm-desktop.exe`

---

## ðŸ“¦ Packaging as a Windows `.msi` Installer (Winget Ready)

To package `traces-sm-desktop` into a native Windows `.msi` installer:

```powershell
# 1. Install Wix packaging helper
cargo install cargo-wix

# 2. Build .msi installer
cargo wix -p traces-sm-desktop
```
The `.msi` installer will be generated at `target\wix\traces-sm-desktop-0.1.0-x86_64.msi`.

