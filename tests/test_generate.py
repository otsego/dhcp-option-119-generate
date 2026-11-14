"""Wire-format round trips, known vectors, validation and CLI behavior."""

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "dhcp-option-119-generate.py"
SPEC = importlib.util.spec_from_file_location("option119", SCRIPT)
option119 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(option119)


def decode_search_list(data):
    """Independent DNS reader; also reject forward pointers and pointer loops."""
    domains = []
    offset = 0
    while offset < len(data):
        labels = []
        cursor = offset
        consumed = None
        visited = set()
        while True:
            if cursor in visited or cursor >= len(data):
                raise AssertionError("loop or out-of-bounds DNS name")
            visited.add(cursor)
            length = data[cursor]
            if length & 0xC0 == 0xC0:
                if cursor + 1 >= len(data):
                    raise AssertionError("truncated pointer")
                target = ((length & 0x3F) << 8) | data[cursor + 1]
                if target >= cursor:
                    raise AssertionError("pointer must target an earlier suffix")
                if consumed is None:
                    consumed = cursor + 2
                cursor = target
            elif length == 0:
                offset = consumed if consumed is not None else cursor + 1
                break
            elif length <= 63:
                if cursor + 1 + length > len(data):
                    raise AssertionError("truncated label")
                labels.append(data[cursor + 1:cursor + 1 + length].decode("ascii"))
                cursor += 1 + length
            else:
                raise AssertionError("invalid DNS label type")
        domains.append(".".join(labels))
    return domains


class EncodingTests(unittest.TestCase):
    def round_trip(self, domains, **kwargs):
        payload = option119.encode_search_list(domains, **kwargs)
        self.assertEqual(decode_search_list(payload), domains)
        return payload

    def test_original_readme_vector(self):
        domains = ["z1.prod.hotgarbagellc.net", "prod.hotgarbagellc.net", "hotgarbagellc.net"]
        payload = self.round_trip(domains)
        self.assertEqual(payload.hex(),
                         "027a310470726f640d686f74676172626167656c6c63036e657400c003c008")

    def test_rfc3397_vector(self):
        payload = self.round_trip(["eng.apple.com", "marketing.apple.com"])
        self.assertEqual(payload.hex(), "03656e67056170706c6503636f6d00096d61726b6574696e67c004")

    def test_unrelated_domains_and_more_than_two(self):
        domains = ["alpha.example.com", "beta.other.net", "gamma.third.org", "delta.fourth.no"]
        self.round_trip(domains)

    def test_repeated_labels_with_different_suffixes(self):
        self.round_trip(["same.one.example", "same.two.example", "a.same.other", "one.example"])

    def test_nested_suffixes_and_pointer_termination(self):
        payload = self.round_trip(["a.b.example", "x.b.example", "y.x.b.example", "b.example"])
        self.assertEqual(payload[-2:], b"\xc0\x02")

    def test_duplicates_preserve_order(self):
        payload = self.round_trip(["a.example", "a.example", "b.example", "a.example"])
        self.assertEqual(payload[-2:], b"\xc0\x00")

    def test_normalization_and_idna(self):
        source = ["EXAMPLE.COM.", "bücher.Example", "faß.de", "EXAMPLE\u3002COM\uff0e"]
        expected = ["example.com", "xn--bcher-kva.example", "fass.de", "example.com"]
        payload = option119.encode_search_list(source)
        self.assertEqual(decode_search_list(payload), expected)

    def test_invalid_domains(self):
        for domain in ["", ".", "..", "a..b", ".example", "example..", "a b", "a\tb", "a\nb",
                       "*.example", "_sip.example", "-a.example", "a-.example", "a/b", "xn--",
                       "xn--a.example", "a" * 64 + ".example"]:
            with self.subTest(domain=domain), self.assertRaises(ValueError):
                option119.encode_search_list([domain])
        with self.assertRaises(ValueError):
            option119.encode_search_list([])

    def test_dns_wire_length_boundaries(self):
        longest = ".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 61])
        self.assertEqual(len(self.round_trip([longest])), 255)
        with self.assertRaises(ValueError):
            option119.encode_search_list([longest + "d"], allow_long=True)

    def test_compressed_payload_length_limit(self):
        longest = ".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 61])
        with self.assertRaisesRegex(ValueError, "257 bytes"):
            option119.encode_search_list([longest, longest])
        self.assertEqual(len(self.round_trip([longest, longest], allow_long=True)), 257)

    def test_offsets_above_one_byte(self):
        longest = ".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 61])
        domains = [longest, "one.test", "two.test"]
        target = len(option119.encode_search_list(domains[:2], allow_long=True))
        payload = self.round_trip(domains + ["two.test"], allow_long=True)
        self.assertGreater(target, 255)
        self.assertEqual(payload[-2:], bytes((0xC0 | target >> 8, target & 255)))

    def test_offsets_beyond_14_bits_stay_literal(self):
        domains = ["host{:04d}.suffix{:04d}".format(index, index) for index in range(850)]
        prefix = option119.encode_search_list(domains, allow_long=True)
        self.assertGreater(len(prefix), 0x3FFF)
        final = "last.unique"
        payload = self.round_trip(domains + [final, final], allow_long=True)
        literal = b"\x04last\x06unique\x00"
        self.assertEqual(payload[len(prefix):], literal + literal)


class CliTests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True)

    def test_default_output(self):
        result = self.run_cli("EXAMPLE.COM.")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, "")
        self.assertEqual(result.stdout, "07:65:78:61:6d:70:6c:65:03:63:6f:6d:00\n")

    def test_hex_output(self):
        result = self.run_cli("--format", "hex", "example.com")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "076578616d706c6503636f6d00\n")

    def test_json_output(self):
        result = self.run_cli("--format", "json", "EXAMPLE.COM.", "bücher.example")
        self.assertEqual(result.returncode, 0)
        document = json.loads(result.stdout)
        self.assertEqual(document["domains"], ["example.com", "xn--bcher-kva.example"])
        self.assertEqual(document["byteLength"], len(bytes.fromhex(document["hexString"].replace(":", ""))))

    def test_cli_errors_have_no_partial_stdout(self):
        for args in [(), ("good.example", "bad..example"), ("--format", "invalid", "example")]:
            with self.subTest(args=args):
                result = self.run_cli(*args)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")
                self.assertIn("error:", result.stderr)

    def test_allow_long_flag(self):
        longest = ".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 61])
        result = self.run_cli(longest, longest)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("257 bytes", result.stderr)
        result = self.run_cli("--allow-long", "--format", "json", longest, longest)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["byteLength"], 257)


if __name__ == "__main__":
    unittest.main()
