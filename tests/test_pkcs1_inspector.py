import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from src.pkcs1_inspector import (
    PKCS1_FIELD_NAMES,
    inspect_pkcs1_private_key,
    read_der_length,
)


class PKCS1InspectorTests(unittest.TestCase):
    def test_reads_short_and_long_der_lengths(self) -> None:
        self.assertEqual(read_der_length(b"\x7f", 0), (127, 1))
        self.assertEqual(read_der_length(b"\x82\x01\x00", 0), (256, 3))

    def test_rejects_indefinite_der_length(self) -> None:
        with self.assertRaises(ValueError):
            read_der_length(b"\x80", 0)

    def test_inspects_all_pkcs1_fields(self) -> None:
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        der_data = key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

        fields = inspect_pkcs1_private_key(der_data)

        self.assertEqual(
            [field.name for field in fields],
            list(PKCS1_FIELD_NAMES),
        )
        self.assertEqual(fields[1].bit_length, 2048)
        self.assertEqual(fields[2].bit_length, 17)

    def test_rejects_non_sequence_input(self) -> None:
        with self.assertRaises(ValueError):
            inspect_pkcs1_private_key(b"\x02\x01\x00")


if __name__ == "__main__":
    unittest.main()

