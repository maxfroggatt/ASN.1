from __future__ import annotations

from dataclasses import dataclass


PKCS1_FIELD_NAMES = (
    "version",
    "modulus",
    "public_exponent",
    "private_exponent",
    "prime1",
    "prime2",
    "exponent1",
    "exponent2",
    "coefficient",
)


@dataclass(frozen=True)
class ASN1IntegerField:
    name: str
    byte_length: int
    bit_length: int


# Reads a DER length and returns the value and next unread position.
def read_der_length(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise ValueError("missing DER length")

    first_byte = data[offset]
    offset += 1

    if first_byte < 0x80:
        return first_byte, offset

    length_bytes = first_byte & 0x7F

    if length_bytes == 0:
        raise ValueError("indefinite lengths are not allowed in DER")
    if length_bytes > 4 or offset + length_bytes > len(data):
        raise ValueError("invalid DER length")

    length = int.from_bytes(data[offset:offset + length_bytes], "big")
    return length, offset + length_bytes


# Reads one DER value with the expected tag.
def read_der_value(
    data: bytes,
    offset: int,
    expected_tag: int,
) -> tuple[bytes, int]:
    if offset >= len(data) or data[offset] != expected_tag:
        raise ValueError(f"expected DER tag 0x{expected_tag:02x}")

    length, value_offset = read_der_length(data, offset + 1)
    end_offset = value_offset + length

    if end_offset > len(data):
        raise ValueError("DER value extends beyond the input")

    return data[value_offset:end_offset], end_offset


# Returns the PKCS#1 field names and sizes without revealing their values.
def inspect_pkcs1_private_key(der_data: bytes) -> list[ASN1IntegerField]:
    sequence, final_offset = read_der_value(der_data, 0, 0x30)

    if final_offset != len(der_data):
        raise ValueError("unexpected data after the PKCS#1 sequence")

    fields = []
    offset = 0

    for name in PKCS1_FIELD_NAMES:
        integer_bytes, offset = read_der_value(sequence, offset, 0x02)

        if not integer_bytes:
            raise ValueError("empty ASN.1 INTEGER")

        unsigned_bytes = integer_bytes.lstrip(b"\x00") or b"\x00"
        integer_value = int.from_bytes(unsigned_bytes, "big")

        fields.append(
            ASN1IntegerField(
                name=name,
                byte_length=len(unsigned_bytes),
                bit_length=integer_value.bit_length(),
            )
        )

    if offset != len(sequence):
        raise ValueError("unexpected fields in the PKCS#1 sequence")

    return fields

