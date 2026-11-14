#!/usr/bin/env python3
"""Generate the DNS-encoded payload of DHCP option 119 (RFC 3397)."""

import argparse
import json
import re
from typing import Iterable, List


_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", re.ASCII)


def normalize_domain(domain: str) -> str:
    """Validate a hostname and return lowercase ASCII using stdlib IDNA2003."""
    if not domain or any(character.isspace() for character in domain):
        raise ValueError("domains must be nonempty and contain no whitespace")
    # IDNA recognizes these separators as equivalent to the ASCII full stop.
    domain = domain.translate(str.maketrans("\u3002\uff0e\uff61", "..."))
    if domain.endswith("."):
        domain = domain[:-1]
    labels = domain.split(".")
    if any(not label for label in labels):
        raise ValueError("domains must contain nonempty labels; the root alone is not allowed")
    ascii_labels = []
    for label in labels:
        try:
            ascii_label = label.encode("idna").decode("ascii").lower()
            if ascii_label.startswith("xn--"):
                # The IDNA encoder passes ASCII through, so validate A-labels too.
                decoded = ascii_label.encode("ascii").decode("idna")
                if decoded.encode("idna").decode("ascii").lower() != ascii_label:
                    raise UnicodeError("noncanonical punycode")
        except UnicodeError as error:
            raise ValueError("invalid IDNA label: {!r}".format(label)) from error
        if not 1 <= len(ascii_label) <= 63:
            raise ValueError("each encoded label must contain 1 to 63 bytes")
        if not _LABEL.fullmatch(ascii_label):
            raise ValueError(
                "labels must use letters, digits or interior hyphens: {!r}".format(label)
            )
        ascii_labels.append(ascii_label)
    if sum(1 + len(label) for label in ascii_labels) + 1 > 255:
        raise ValueError("an uncompressed domain must fit within 255 wire bytes")
    return ".".join(ascii_labels)


def encode_search_list(domains: Iterable[str], *, allow_long: bool = False) -> bytes:
    """Encode domains in order, compressing only previously emitted full suffixes.

    The returned bytes exclude DHCP's option code and length. Long payloads need
    RFC 3396 concatenation by the DHCP server; this function does not fragment.
    """
    normalized = [normalize_domain(domain) for domain in domains]
    if not normalized:
        raise ValueError("at least one search domain is required")
    payload = bytearray()
    suffix_offsets = {}
    for domain in normalized:
        labels = domain.split(".")
        for index, label in enumerate(labels):
            suffix = tuple(labels[index:])
            target = suffix_offsets.get(suffix)
            if target is not None:
                payload.extend((0xC0 | (target >> 8), target & 0xFF))
                break  # A DNS compression pointer terminates the name.
            if len(payload) <= 0x3FFF:
                suffix_offsets[suffix] = len(payload)
            encoded_label = label.encode("ascii")
            payload.append(len(encoded_label))
            payload.extend(encoded_label)
        else:
            payload.append(0)
    if len(payload) > 255 and not allow_long:
        raise ValueError(
            "encoded payload is {} bytes (maximum 255); use --allow-long only "
            "with a DHCP server supporting RFC 3396 concatenation".format(len(payload))
        )
    return bytes(payload)


def main(argv: List[str] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("domains", nargs="+", help="search domains, in preference order")
    parser.add_argument(
        "--format", choices=("colon", "hex", "json"), default="colon",
        help="output format (default: colon-separated hex)",
    )
    parser.add_argument(
        "--allow-long", action="store_true",
        help="allow more than 255 bytes; requires server-side RFC 3396 concatenation",
    )
    args = parser.parse_args(argv)
    try:
        domains = [normalize_domain(domain) for domain in args.domains]
        payload = encode_search_list(domains, allow_long=args.allow_long)
    except ValueError as error:
        parser.error(str(error))
    colon_hex = ":".join("{:02x}".format(byte) for byte in payload)
    if args.format == "json":
        print(json.dumps({"domains": domains, "hexString": colon_hex, "byteLength": len(payload)}))
    elif args.format == "hex":
        print(payload.hex())
    else:
        print(colon_hex)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
