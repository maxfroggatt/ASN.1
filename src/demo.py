from __future__ import annotations

import base64
import hashlib
import math

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from pkcs1_inspector import inspect_pkcs1_private_key
from rsa_reconstruction import build_private_key, reconstruct_components


LINE_WIDTH = 72


def section(number: int, title: str) -> None:
    print(f"\n{number}. {title}")
    print("-" * LINE_WIDTH)


def format_integer(value: int) -> str:
    return f"0x{value:x} ({value.bit_length()} bits)"


def private_key_pem(key: rsa.RSAPrivateKey) -> str:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii").strip()


def public_key_pem(key: rsa.RSAPrivateKey) -> str:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii").strip()


def public_key_fingerprint(key: rsa.RSAPrivateKey) -> str:
    public_der = key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashlib.sha256(public_der).hexdigest()
    return ":".join(digest[index:index + 2] for index in range(0, 64, 2))


def main() -> None:
    print("=" * LINE_WIDTH)
    print("RSA KEY RECONSTRUCTION AND ASN.1 DEMONSTRATION")
    print("=" * LINE_WIDTH)
    print(
        "This program generates a disposable RSA key and prints its complete\n"
        "values for educational purposes. Never print a real private key."
    )

    section(1, "Generate a disposable RSA key")
    source_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    source_numbers = source_key.private_numbers()
    public_numbers = source_numbers.public_numbers

    print("A temporary 2048-bit RSA key was generated in memory.")
    print("It is not saved and is discarded when the program finishes.")

    print("\nGenerated public key (PEM):")
    print(public_key_pem(source_key))

    print("\nGenerated private key (PEM):")
    print(private_key_pem(source_key))

    section(2, "Select the reconstruction inputs")
    print(
        "The demonstration keeps n, e, d, and p, then treats q, dP, dQ,\n"
        "and qInv as missing. In a real secure key, all private values must\n"
        "remain secret."
    )

    print("\nValues supplied to the reconstruction:")
    print("  n =", format_integer(public_numbers.n))
    print("  e =", public_numbers.e)
    print("  d =", format_integer(source_numbers.d))
    print("  p =", format_integer(source_numbers.p))

    print("\nValues treated as missing:")
    print("  q, dP, dQ, qInv")

    section(3, "Reconstruct the missing RSA values")
    reconstructed = reconstruct_components(
        n=public_numbers.n,
        e=public_numbers.e,
        d=source_numbers.d,
        p=source_numbers.p,
    )

    print("q = n // p")
    print("q =", format_integer(reconstructed.q))

    print("\ndP = d mod (p - 1)")
    print("dP =", format_integer(reconstructed.dmp1))

    print("\ndQ = d mod (q - 1)")
    print("dQ =", format_integer(reconstructed.dmq1))

    print("\nqInv = q^-1 mod p")
    print("qInv =", format_integer(reconstructed.iqmp))

    lambda_n = math.lcm(reconstructed.p - 1, reconstructed.q - 1)

    print("\nCalculation checks:")
    print("  p * q == n:                       ", end="")
    print(reconstructed.p * reconstructed.q == reconstructed.n)
    print("  (e * d) mod lcm(p - 1, q - 1):   ", end="")
    print((reconstructed.e * reconstructed.d) % lambda_n)
    print("  dP == d mod (p - 1):              ", end="")
    print(reconstructed.dmp1 == reconstructed.d % (reconstructed.p - 1))
    print("  dQ == d mod (q - 1):              ", end="")
    print(reconstructed.dmq1 == reconstructed.d % (reconstructed.q - 1))
    print("  (q * qInv) mod p:                 ", end="")
    print((reconstructed.q * reconstructed.iqmp) % reconstructed.p)

    section(4, "Build and compare the reconstructed key")
    rebuilt_key = build_private_key(reconstructed)
    rebuilt_numbers = rebuilt_key.private_numbers()

    source_fingerprint = public_key_fingerprint(source_key)
    rebuilt_fingerprint = public_key_fingerprint(rebuilt_key)
    components_match = rebuilt_numbers == source_numbers

    print("Reconstructed private key (PEM):")
    print(private_key_pem(rebuilt_key))

    print("\nSource public-key fingerprint:")
    print(" ", source_fingerprint)
    print("Reconstructed public-key fingerprint:")
    print(" ", rebuilt_fingerprint)
    print("Fingerprints match:", source_fingerprint == rebuilt_fingerprint)
    print("All private components match:", components_match)

    section(5, "Prove the reconstructed key works")
    message = b"The reconstructed RSA key works correctly."
    oaep = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )

    # Encrypt with the original public key and decrypt with the rebuilt key.
    ciphertext = source_key.public_key().encrypt(message, oaep)
    recovered_message = rebuilt_key.decrypt(ciphertext, oaep)
    encoded_ciphertext = base64.b64encode(ciphertext).decode("ascii")

    print("The original public key encrypts the message.")
    print("The reconstructed private key decrypts it.\n")
    print("Plaintext:")
    print(" ", message.decode("utf-8"))
    print("Ciphertext (Base64):")
    print(" ", encoded_ciphertext)
    print("Decrypted text:")
    print(" ", recovered_message.decode("utf-8"))
    print("Message matches:", recovered_message == message)

    section(6, "Inspect the PKCS#1 ASN.1 structure")
    der_data = rebuilt_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    fields = inspect_pkcs1_private_key(der_data)

    print("The reconstructed key contains the following ASN.1 INTEGER fields:")
    print("PKCS#1 DER size:", len(der_data), "bytes\n")

    for field in fields:
        print(
            f"  {field.name:<18} "
            f"{field.bit_length:>4} bits "
            f"({field.byte_length} bytes)"
        )

    section(7, "Final result")
    reconstruction_successful = components_match and recovered_message == message
    print("RSA reconstruction successful:", reconstruction_successful)
    print("No key files were written to disk.")
    print("The disposable key is discarded when the program finishes.")


if __name__ == "__main__":
    main()