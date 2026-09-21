<div align="center">

# RSA Key Reconstruction and ASN.1 Analysis

**An educational Python demonstration of RSA private-key reconstruction, validation, encryption, and PKCS#1 ASN.1 inspection.**

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![Cryptography](https://img.shields.io/badge/Cryptography-RSA-6C63FF)
[![Tests](https://github.com/maxfroggatt/RSA-Key-Reconstruction/actions/workflows/tests.yml/badge.svg)](https://github.com/maxfroggatt/RSA-Key-Reconstruction/actions/workflows/tests.yml)

</div>

## Overview

This project demonstrates how a complete two-prime RSA private key can be reconstructed when the modulus, public exponent, private exponent, and one prime factor are already known.

It calculates the missing prime factor and Chinese Remainder Theorem values, builds a validated private-key object, and serialises it as PKCS#1 DER for ASN.1 inspection.

The demonstration generates a disposable RSA key pair at runtime and displays its values so the reconstruction process can be followed. The keys exist only in memory and are discarded when the program finishes.

## How the demonstration works

1. A complete disposable RSA key pair is generated in memory.
2. The program extracts `n`, `e`, `d`, and `p` from the original key.
3. It treats `q`, `dP`, `dQ`, and `qInv` as missing.
4. The missing values are calculated and used to build a new private key.
5. The reconstructed key is compared with the original key.
6. A message is encrypted with the original public key and decrypted with the reconstructed private key.
7. The reconstructed key's PKCS#1 ASN.1 fields are inspected.

## What it demonstrates

- RSA component relationships defined by PKCS#1
- Reconstruction of `q`, `dP`, `dQ`, and `qInv`
- Validation of the supplied modulus and exponents
- Creation of a usable RSA private-key object
- OAEP encryption and decryption
- Basic DER length and INTEGER parsing
- PKCS#1 ASN.1 inspection using field names and sizes

## RSA reconstruction

Given `n`, `e`, `d`, and `p`, the project calculates:

| Component | Calculation |
|---|---|
| Second prime | `q = n // p` |
| First CRT exponent | `dP = d mod (p - 1)` |
| Second CRT exponent | `dQ = d mod (q - 1)` |
| CRT coefficient | `qInv = q^-1 mod p` |

The implementation checks that `p` divides `n` and that `d` is the modular inverse of `e` modulo `lcm(p - 1, q - 1)`.

## Run the demonstration

Install the required dependency:

```bash
python -m pip install -r requirements.txt
```

Run the demonstration:

```bash
python src/demo.py
```

The output displays the disposable public and private keys, the supplied RSA components, the reconstructed values, and the mathematical validation checks.

It then compares the original and reconstructed keys, encrypts and decrypts a sample message, and lists the PKCS#1 ASN.1 fields with their bit and byte lengths.

The complete private values are displayed for educational purposes because the key is randomly generated for each run and immediately discarded. No key material is written to disk.

## Run the tests

```bash
python -m unittest discover -s tests -v
```

The tests verify RSA reconstruction, encryption and decryption, invalid-input handling, DER length parsing, and PKCS#1 field inspection.

## Security note

Possession of a private exponent or either RSA prime factor compromises the private key. Real private-key material should never be committed to source control.

Printing private-key values is appropriate here only because the demonstration uses a disposable key that is never used outside the program. Real private keys should never be printed, logged, or shared.

This repository is for defensive education and authorised coursework only.

## References

- [RFC 8017: PKCS #1, RSA Cryptography Specifications Version 2.2](https://www.rfc-editor.org/rfc/rfc8017)
- [Cryptography RSA documentation](https://cryptography.io/en/stable/hazmat/primitives/asymmetric/rsa/)