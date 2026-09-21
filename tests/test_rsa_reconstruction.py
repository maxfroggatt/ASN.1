import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from src.rsa_reconstruction import build_private_key, reconstruct_components


class RSAReconstructionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        cls.source_numbers = cls.source_key.private_numbers()

    def test_reconstructs_missing_values(self) -> None:
        numbers = self.source_numbers
        components = reconstruct_components(
            n=numbers.public_numbers.n,
            e=numbers.public_numbers.e,
            d=numbers.d,
            p=numbers.p,
        )

        self.assertEqual(components.q, numbers.q)
        self.assertEqual(components.dmp1, numbers.dmp1)
        self.assertEqual(components.dmq1, numbers.dmq1)
        self.assertEqual(components.iqmp, numbers.iqmp)

    def test_rebuilt_key_decrypts_ciphertext(self) -> None:
        numbers = self.source_numbers
        components = reconstruct_components(
            n=numbers.public_numbers.n,
            e=numbers.public_numbers.e,
            d=numbers.d,
            p=numbers.p,
        )
        rebuilt_key = build_private_key(components)
        oaep = padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        )
        message = b"test message"
        ciphertext = rebuilt_key.public_key().encrypt(message, oaep)

        self.assertEqual(rebuilt_key.decrypt(ciphertext, oaep), message)

    def test_rejects_incorrect_prime_factor(self) -> None:
        numbers = self.source_numbers

        with self.assertRaises(ValueError):
            reconstruct_components(
                n=numbers.public_numbers.n,
                e=numbers.public_numbers.e,
                d=numbers.d,
                p=numbers.p + 2,
            )

    def test_rejects_incorrect_private_exponent(self) -> None:
        numbers = self.source_numbers

        with self.assertRaises(ValueError):
            reconstruct_components(
                n=numbers.public_numbers.n,
                e=numbers.public_numbers.e,
                d=numbers.d + 1,
                p=numbers.p,
            )


if __name__ == "__main__":
    unittest.main()

