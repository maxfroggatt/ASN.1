from __future__ import annotations

import math
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import rsa


@dataclass(frozen=True)
class RSAComponents:
    n: int
    e: int
    d: int
    p: int
    q: int
    dmp1: int
    dmq1: int
    iqmp: int


# Reconstructs the missing RSA values from n, e, d, and one prime factor.
def reconstruct_components(n: int, e: int, d: int, p: int) -> RSAComponents:
    supplied_values = {"n": n, "e": e, "d": d, "p": p}

    for name, value in supplied_values.items():
        if not isinstance(value, int) or isinstance(value, bool):
            raise TypeError(f"{name} must be an integer")
        if value <= 1:
            raise ValueError(f"{name} must be greater than 1")

    if n % p != 0:
        raise ValueError("p is not a factor of n")

    q = n // p

    if p == q:
        raise ValueError("p and q must be different")

    lambda_n = math.lcm(p - 1, q - 1)

    if math.gcd(e, lambda_n) != 1:
        raise ValueError("e is not valid for the supplied prime factors")

    if (e * d) % lambda_n != 1:
        raise ValueError("d is not the inverse of e modulo lambda(n)")

    return RSAComponents(
        n=n,
        e=e,
        d=d,
        p=p,
        q=q,
        dmp1=d % (p - 1),
        dmq1=d % (q - 1),
        iqmp=pow(q, -1, p),
    )


# Converts the reconstructed values into a validated cryptography key object.
def build_private_key(components: RSAComponents) -> rsa.RSAPrivateKey:
    private_numbers = rsa.RSAPrivateNumbers(
        p=components.p,
        q=components.q,
        d=components.d,
        dmp1=components.dmp1,
        dmq1=components.dmq1,
        iqmp=components.iqmp,
        public_numbers=rsa.RSAPublicNumbers(
            e=components.e,
            n=components.n,
        ),
    )

    return private_numbers.private_key()

