# QLinux - Quantum OTP Secure Communication OS

## Overview
QLinux is a high-security communication-oriented operating system based on quantum-derived random numbers and a one-time pad (OTP). It provides strict, end-to-end control over key generation, management, consumption, and destruction.

The system is designed to eliminate key reuse and residual data, ensuring maximum confidentiality in communication environments.

## Features
- Quantum-based random number generation (Thermal RNG / QHAL)
- One-Time Pad encryption engine with strict key lifecycle control
- 3-state key pool management (Available / InUse / Consumed)
- Automatic zeroization to prevent key residue
- Multi-factor authentication (Biometric + Password + TPM 2.0)
- Communication shutdown when key pool reaches low threshold
- Local-only processing (no external transmission of biometric data)

## Project Structure

qlinux/
├── qhal/ # Quantum Hardware Abstraction Layer
├── key_pool/ # Key Pool Manager
├── otp_engine/ # OTP encryption engine
├── auth/ # Authentication layer
├── kernel_module/ # Netfilter + XFRM kernel module
└── tools/ # CLI tools


## Build

cargo build --workspace


## Security Principles
- No key reuse by design
- Key length >= plaintext length enforced at runtime
- Immediate zeroization after key consumption
- Strict access control via multi-factor authentication
- Automatic communication halt on low key availability

## Roadmap
- Week1: QHAL + Thermal RNG validation
- Week2: Key Pool Manager implementation
- Week3: OTP Engine integration
- Week4: Secure communication test (LAN)
- Phase2: QKD Fiber / Repeater support
- Phase3: Quantum teleportation channel support

## Notes
This project focuses on maximizing theoretical security using OTP and quantum entropy sources. Proper key distribution and physical security assumptions are critical for real-world deployment.

## License
MIT License
