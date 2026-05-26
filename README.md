# An SRAM-PUF-based cryptographic key generation system on STM32 TrustZone

Lightweight hardware security key generation.
Implemented on STM32 Cortex-M33 (TrustZone).

## What it does
- Generates a unique 128-bit cryptographic key from SRAM power-up noise
- No key stored in Flash — immune to cold-boot and reverse-engineering attacks
- Two keys derived via SHA256.

## Key techniques
- Run-length bit selection
- Fuzzy extractor: W = Y ⊕ C, key reproduced via Hamming correction
- SRAM unstable bits used as physical entropy source for RNG
- SHA256 to produce two keys

## Platform
STM32H5 / Cortex-M33, TrustZone, CubeMX HAL

## Reference
Based on: "SRAM-based PUF using Lightweight Hamming-Code Fuzzy Extractor
for Energy Harvesting Beat Sensors" — Hoang-Long Pham, Duy-Hieu Bui, Xuan-Tu Tran, VNU-ITI / Univ. of Vietnam
