#!/usr/bin/env python3
"""Independently generate the archive vectors: the fixtures, what core must list for each, and the
words, from the archives design (2026-11-07-core-archives-design.md §5.1, §6, §9).

Usage:
    python3 -I test-vectors/tools/gen_archives_v1.py test-vectors/archives_v1.json [test-vectors/archives]

No Rust is run. The fixtures are written byte by byte here, with no zlib compression (zlib and
zlib-ng write different deflate streams, so a drift guard over zlib output would fail on a
machine with the other library): deflate data is one fixed-Huffman block encoded below
(RFC 1951 §3.2.6), CRC-32 comes from `binascii`. Python's own `zipfile`, `tarfile` and `gzip` then
read back every generated fixture core lists, as an independent check that the bytes are a
well-formed archive and not something only this file and core agree on.

The password fixtures (aes128.zip ... two-passwords.zip) are made by 7-Zip and Info-ZIP
(make_archive_password_fixtures.sh), salted at random, so they are not written here; their rows
come from the files that script archives. Two ZipCrypto fixtures ARE written here (APPNOTE 6.1
encryption below, deterministic headers), because Info-ZIP always sets the data-descriptor flag:
zipcrypto-crc-check.zip has the flag clear, so its check byte is the CRC's high byte, and starts with
an empty entry; zipcrypto-cp437-quick-check.zip is encrypted with the CP437 bytes of `caf\u00e9-test`,
and its second entry's header is chosen so that the password's UTF-8 bytes also pass its check byte
(a 1-in-256 quick-check false positive, made on purpose). Python's `zipfile` decrypts both back.

Expected listings follow the design:
- names (§6.1): zip names are UTF-8 when flag bit 11 is set (invalid UTF-8 cannot be used), else
  the Info-ZIP Unicode Path field when its CRC matches the raw name, else UTF-8 when the bytes are
  valid UTF-8 with a byte >= 0x80, else CP437; tar names are the pax path, else the GNU long name,
  else ustar prefix + name, each UTF-8 when valid, else ISO-8859-1. Then NFC; a NUL or a control
  character cannot be used; `/` and `\\` both split; a leading `/`, `//server/share/` and a drive
  prefix (`C:` in `C:\\x`, and in the drive-relative `C:x`) are removed; `..` points outside the
  folder; `.` and empty components are dropped;
  `: < > " | ? *` and a trailing dot or space become `_`, a Windows device name gets a leading `_`,
  bidi controls and marks are removed; a component over 255 bytes, a path over 4,096 bytes or
  deeper than 64 cannot be used; `__MACOSX` is macOS resource data;
- the shown name is the decoded name in NFC, with control characters and bidi overrides and
  isolates made visible as U+FFFD (a name like `photo\\u202egpj.exe` must not show as
  `photoexe.jpg`); a folder's shown name is its path;
- kinds (§6.1.10): a zip entry's Unix mode (made by a Unix host) gives a link, a folder or a special
  file (FIFO, device, socket); a name ending in a separator, or the MS-DOS folder attribute, is a
  folder; tar typeflags 1 and 2 are links, 3, 4 and 6 special files, 5 a folder, S a sparse file,
  anything else unknown. A zip method other than stored or deflate is skipped with its APPNOTE
  name;
- implied folders (§5.1): an entry's missing parent folders are listed just before it, outermost
  first; a folder entry for a folder already listed is that same folder, not a second row;
- a plain `.gz` lists one file named by the gzip header's file name (its last component), or no
  name; its size is every member's output together.
Where the design names none, the words for an unsupported entry are "Sparse file" and "Unknown
entry type": `entry_unsupported` puts `{what}` first in its sentence, so it starts with a capital.

Words (§9): the English is copied from the design's table. Plurals are written out here: the
singular is used exactly when the count reads "1". Counts group digits with commas; sizes are
decimal units (B, KB, MB, GB, TB) at one decimal, divided by 1,000 one step at a time, a value
that rounds to 1000.0 carried into the next unit, below 1,000 bytes `N B`, and a size past
2^63 - 1 shown as 2^63 - 1 (core's formatter takes a signed 64-bit count).
"""
import binascii
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import sys
import tarfile
import unicodedata
import zipfile

MTIME = 1710506096  # 2024-03-15 12:34:56 UTC
DOS_TIME = (12 << 11) | (34 << 5) | (56 // 2)
DOS_DATE = ((2024 - 1980) << 9) | (3 << 5) | 15
UNIX, MSDOS = 3, 0
FILE_MODE, DIR_MODE = 0o100644, 0o040755

# The password fixtures and the files make_archive_password_fixtures.sh puts in them.
SECRET = ("secret.txt", 1000)  # "The protected test file.\n" x 40
PLAIN = ("plain.txt", 15)  # "Not protected.\n"
OTHER = ("other.txt", 1000)


# The ZipCrypto fixtures' password, as the person types it.
TEST_PASSWORD = b"beebeeb-test-password"
CP437_PASSWORD_TEXT = "caf\u00e9-test"


def crc32(data):
    return binascii.crc32(data) & 0xFFFFFFFF


# ---------------------------------------------------------------- deflate, gzip


def deflate_fixed(data):
    """One final fixed-Huffman deflate block: literals, and a run of one repeated byte as
    length-258 copies at distance 1."""
    out = bytearray()
    acc = nbits = 0

    def bits(value, count):  # deflate packs bits least significant first
        nonlocal acc, nbits
        acc |= value << nbits
        nbits += count
        while nbits >= 8:
            out.append(acc & 0xFF)
            acc >>= 8
            nbits -= 8

    def code(value, length):  # ... but Huffman codes most significant bit first
        bits(int(format(value, f"0{length}b")[::-1], 2), length)

    def literal(byte):
        if byte < 144:
            code(0x30 + byte, 8)
        else:
            code(0x190 + byte - 144, 9)

    bits(1, 1)  # BFINAL
    bits(1, 2)  # BTYPE 01: fixed Huffman
    i = 0
    while i < len(data):
        byte = data[i]
        literal(byte)
        i += 1
        while data[i : i + 258] == bytes([byte]) * 258:
            code(0xC0 + 285 - 280, 8)  # length 258: code 285, no extra bits
            code(0, 5)  # distance 1: code 0, no extra bits
            i += 258
    code(0, 7)  # end of block: code 256
    if nbits:
        out.append(acc & 0xFF)
    return bytes(out)


def gzip_member(data, name=None, mtime=0):
    flags = 0x08 if name is not None else 0
    header = b"\x1f\x8b\x08" + bytes([flags]) + struct.pack("<I", mtime) + b"\x00\xff"
    if name is not None:
        header += name + b"\x00"
    return header + deflate_fixed(data) + struct.pack("<II", crc32(data), len(data) & 0xFFFFFFFF)


# ---------------------------------------------------------------- ZipCrypto (APPNOTE 6.1)


CRC_TABLE = []
for _n in range(256):
    _c = _n
    for _ in range(8):
        _c = (0xEDB88320 ^ (_c >> 1)) if _c & 1 else _c >> 1
    CRC_TABLE.append(_c)


class ZipCryptoKeys:
    def __init__(self, password):
        self.k0, self.k1, self.k2 = 0x12345678, 0x23456789, 0x34567890
        for b in password:
            self.update(b)

    def update(self, b):
        self.k0 = (self.k0 >> 8) ^ CRC_TABLE[(self.k0 ^ b) & 0xFF]
        self.k1 = ((self.k1 + (self.k0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        self.k2 = (self.k2 >> 8) ^ CRC_TABLE[(self.k2 ^ (self.k1 >> 24)) & 0xFF]

    def stream(self):
        t = (self.k2 | 2) & 0xFFFF
        return ((t * (t ^ 1)) >> 8) & 0xFF

    def encrypt(self, data):
        out = bytearray()
        for p in data:
            out.append(p ^ self.stream())
            self.update(p)
        return bytes(out)

    def decrypt(self, data):
        out = bytearray()
        for c in data:
            p = c ^ self.stream()
            self.update(p)
            out.append(p)
        return bytes(out)


def zipcrypto_payload(password, check, data, label, other=None, other_passes=False):
    """The 12-byte encryption header and `data`, encrypted under `password`. The header's first 11
    bytes are the first SHA-256-derived candidate for `label` whose header passes (or, by default,
    fails) the check byte when decrypted under `other`."""
    for n in range(100_000):
        head = hashlib.sha256(f"{label}-{n}".encode()).digest()[:11] + bytes([check])
        encrypted_head = ZipCryptoKeys(password).encrypt(head)
        if other is not None:
            passes = ZipCryptoKeys(other).decrypt(encrypted_head)[11] == check
            if passes != other_passes:
                continue
        return ZipCryptoKeys(password).encrypt(head + data)
    raise AssertionError(f"no header for {label}")


# ---------------------------------------------------------------- zip


class Z:
    """One zip member, as written and as the design reads it."""

    def __init__(self, name, data=b"", *, utf8=False, method=0, host=UNIX, mode=FILE_MODE, dos_attr=0,
                 upath=None, payload=None, size=None, flags=0, zipcrypto=None):
        self.name = name.encode("utf-8") if isinstance(name, str) else name
        self.data = data
        self.utf8 = utf8
        self.method = method
        self.host = host
        self.mode = mode
        self.dos_attr = dos_attr
        self.upath = upath  # (crc of the raw name it is for, UTF-8 name)
        self.payload = payload if payload is not None else (deflate_fixed(data) if method == 8 else data)
        self.size = len(data) if size is None else size
        self.flags = flags | (0x0800 if utf8 else 0)
        # (password bytes, the payload `zipcrypto_payload` wrote): stored, flag bit 0 set.
        self.zipcrypto = zipcrypto
        if zipcrypto is not None:
            self.payload = zipcrypto[1]
            self.flags |= 0x01

    def extra(self):
        if self.upath is None:
            return b""
        crc, name = self.upath
        body = b"\x01" + struct.pack("<I", crc) + name.encode("utf-8")
        return struct.pack("<HH", 0x7075, len(body)) + body


def zip_bytes(members, *, prefix=b"", end_disk=0):
    out = bytearray(prefix)
    central = bytearray()
    for m in members:
        offset = len(out)
        extra = m.extra()
        out += struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, m.flags, m.method, DOS_TIME, DOS_DATE,
                           crc32(m.data), len(m.payload), m.size, len(m.name), len(extra))
        out += m.name + extra + m.payload
        external = (m.mode << 16) if m.host == UNIX else m.dos_attr
        central += struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, (m.host << 8) | 30, 20, m.flags, m.method,
                               DOS_TIME, DOS_DATE, crc32(m.data), len(m.payload), m.size, len(m.name),
                               len(extra), 0, 0, 0, external, offset)
        central += m.name + extra
    cd_offset = len(out)
    out += central
    out += struct.pack("<IHHHHIIH", 0x06054B50, end_disk, end_disk, len(members), len(members), len(central),
                       cd_offset, 0)
    return bytes(out)


def decode_zip(m):
    """(decoded name, whether its bytes cannot be decoded)."""
    if m.utf8:
        try:
            return m.name.decode("utf-8"), False
        except UnicodeDecodeError:
            return m.name.decode("utf-8", "replace"), True
    if m.upath is not None and m.upath[0] == crc32(m.name):
        return m.upath[1], False
    if any(b >= 0x80 for b in m.name):
        try:
            return m.name.decode("utf-8"), False
        except UnicodeDecodeError:
            pass
    return m.name.decode("cp437"), False


ZIP_METHODS = {9: "Deflate64", 12: "bzip2"}


def zip_entry(m):
    decoded, undecodable = decode_zip(m)
    path, skip = entry_path(decoded, undecodable)
    file_type = (m.mode if m.host == UNIX else 0) & 0o170000
    if file_type == 0o120000:
        kind = "symlink"
    elif file_type == 0o040000:
        kind = "folder"
    elif file_type in (0o010000, 0o020000, 0o060000, 0o140000):
        kind = "device"
    elif decoded.endswith(("/", "\\")) or (m.host == MSDOS and m.dos_attr & 0x10):
        kind = "folder"
    else:
        kind = "file"
    if skip is None:
        if kind == "symlink":
            skip = "link"
        elif kind == "device":
            skip = "device"
        elif kind == "file" and m.method not in (0, 8):
            skip = "method:" + ZIP_METHODS.get(m.method, f"method {m.method}")
    cipher = "zipcrypto" if m.zipcrypto is not None else "none"
    return entry(shown(decoded), path, kind, 0 if kind == "folder" else m.size, cipher, skip)


# ---------------------------------------------------------------- tar


def octal(value, width):
    return b"%0*o\x00" % (width - 1, value)


def tar_block(name, typeflag, *, size=0, mode=0o644, linkname=b"", prefix=b"", major=0, minor=0,
              magic=b"ustar\x0000"):
    h = bytearray(512)

    def put(at, width, value):
        h[at : at + len(value[:width])] = value[:width]

    put(0, 100, name)
    put(100, 8, octal(mode, 8))
    put(108, 8, octal(0, 8))
    put(116, 8, octal(0, 8))
    put(124, 12, octal(size, 12))
    put(136, 12, octal(MTIME, 12))
    h[148:156] = b" " * 8
    h[156:157] = typeflag
    put(157, 100, linkname)
    put(257, 8, magic)
    put(265, 32, b"beebeeb")
    put(297, 32, b"beebeeb")
    put(329, 8, octal(major, 8))
    put(337, 8, octal(minor, 8))
    put(345, 155, prefix)
    h[148:156] = b"%06o\x00 " % sum(h)
    return bytes(h)


def padded(data):
    return data + b"\x00" * (-len(data) % 512)


def pax_record(key, value):
    body = b" " + key + b"=" + value + b"\n"
    length = len(body) + 1
    while len(str(length)) + len(body) != length:
        length = len(str(length)) + len(body)
    return str(length).encode() + body


class T:
    """One tar member, as written and as the design reads it."""

    def __init__(self, name, data=b"", *, typeflag=b"0", prefix=b"", gnu_long=None, pax_path=None,
                 linkname=b"", major=0, minor=0):
        self.name = name.encode("utf-8") if isinstance(name, str) else name
        self.data = data
        self.typeflag = typeflag
        self.prefix = prefix
        self.gnu_long = gnu_long
        self.pax_path = pax_path
        self.linkname = linkname
        self.major, self.minor = major, minor

    def blocks(self):
        out = b""
        if self.pax_path is not None:
            records = pax_record(b"path", self.pax_path)
            out += tar_block(b"PaxHeaders/" + self.name[:80], b"x", size=len(records)) + padded(records)
        magic = b"ustar\x0000"
        if self.gnu_long is not None:
            magic = b"ustar  \x00"
            out += tar_block(b"././@LongLink", b"L", size=len(self.gnu_long) + 1, magic=magic)
            out += padded(self.gnu_long + b"\x00")
        mode = 0o755 if self.typeflag == b"5" else 0o644
        out += tar_block(self.name, self.typeflag, size=len(self.data), mode=mode, linkname=self.linkname,
                         prefix=self.prefix, major=self.major, minor=self.minor, magic=magic)
        return out + padded(self.data)


def tar_bytes(members):
    out = b"".join(m.blocks() for m in members) + b"\x00" * 1024
    return out + b"\x00" * (-len(out) % 10240)  # a whole 10 KiB record, as tar writes


def utf8_or_latin1(raw):
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


TAR_KINDS = {
    b"0": ("file", None), b"\x00": ("file", None), b"7": ("file", None), b"5": ("folder", None),
    b"1": ("hard_link", "link"), b"2": ("symlink", "link"),
    b"3": ("device", "device"), b"4": ("device", "device"), b"6": ("device", "device"),
    b"S": ("other", "unsupported:Sparse file"),
}


def tar_entry(m):
    if m.pax_path is not None:
        decoded = utf8_or_latin1(m.pax_path)
    elif m.gnu_long is not None:
        decoded = utf8_or_latin1(m.gnu_long)
    elif m.prefix:
        decoded = utf8_or_latin1(m.prefix + b"/" + m.name)
    else:
        decoded = utf8_or_latin1(m.name)
    path, skip = entry_path(decoded, False)
    kind, type_skip = TAR_KINDS.get(m.typeflag, ("other", "unsupported:Unknown entry type"))
    return entry(shown(decoded), path, kind, 0 if kind == "folder" else len(m.data), "none", skip or type_skip)


# ---------------------------------------------------------------- names (§6.1)

RESERVED = {"CON", "PRN", "AUX", "NUL"} | {f"{p}{n}" for p in ("COM", "LPT") for n in "123456789¹²³"}
BIDI_CONTROLS = {chr(c) for c in list(range(0x202A, 0x202F)) + list(range(0x2066, 0x206A))}
BIDI_MARKS = {"\u200e", "\u200f", "\u061c"}


def is_control(c):
    return unicodedata.category(c) == "Cc"


def shown(decoded):
    return "".join("\ufffd" if is_control(c) or c in BIDI_CONTROLS else c
                   for c in unicodedata.normalize("NFC", decoded))


def component(name):
    name = "".join(c for c in name if c not in BIDI_CONTROLS and c not in BIDI_MARKS)
    name = "".join("_" if c in ':<>"|?*' else c for c in name)
    kept = name.rstrip(". ")
    name = kept + "_" * (len(name) - len(kept))
    if name.split(".")[0].upper() in RESERVED:
        name = "_" + name
    return name


def entry_path(decoded, undecodable):
    """(components, None) or (None, skip reason)."""
    if undecodable:
        return None, "unusable_name"
    name = unicodedata.normalize("NFC", decoded)
    if "\x00" in name or any(is_control(c) for c in name):
        return None, "unusable_name"
    parts = name.replace("\\", "/").split("/")
    if len(parts) > 3 and parts[0] == "" and parts[1] == "":  # //server/share/...
        parts = parts[4:]
    first = next((i for i, p in enumerate(parts) if p), None)
    if first is not None and parts[first][1:2] == ":" and parts[first][0].isascii() and parts[first][0].isalpha():
        parts[first] = parts[first][2:]  # `C:\\x` and the drive-relative `C:x` alike
    if ".." in parts:
        return None, "outside_folder"
    parts = [p for p in parts if p not in ("", ".")]
    if parts and parts[0] == "__MACOSX":
        return None, "mac_resource"
    parts = [component(p) for p in parts]
    if (not parts or len(parts) > 64 or any(len(p.encode()) > 255 for p in parts)
            or len("/".join(parts).encode()) > 4096):
        return None, "unusable_name"
    return parts, None


# ---------------------------------------------------------------- listings


def entry(display, path, kind, size, cipher, skip):
    return {"display_path": display, "path": path, "kind": kind, "size": size, "cipher": cipher, "skip": skip}


def listing(entries):
    """Implied folders and folder merging (§5.1), then the vectors' row shape."""
    out, folders = [], set()
    for e in entries:
        path = e["path"]
        if path is not None:
            for depth in range(1, len(path)):
                prefix = tuple(path[:depth])
                if prefix not in folders:
                    folders.add(prefix)
                    out.append(entry("/".join(prefix), list(prefix), "folder", 0, "none", None))
            if e["kind"] == "folder" and e["skip"] is None:
                if tuple(path) in folders:
                    continue
                folders.add(tuple(path))
                e = dict(e, display_path="/".join(path))
        out.append(e)
    return [dict(e, path=None if e["path"] is None else "/".join(e["path"]), size=str(e["size"])) for e in out]


def row(file, fmt, entries=None, refusal=None):
    return {"file": file, "format": fmt, "entries": listing(entries or []), "refusal": refusal}


# ---------------------------------------------------------------- the fixtures


def fixtures():
    """[(file name, bytes or None for a tool-made fixture, row, stdlib check)]."""
    out = []

    def add(file, data, fmt, entries=None, refusal=None, check=None):
        out.append((file, data, row(file, fmt, entries, refusal), check))

    plain_zip = [
        Z("docs/", mode=DIR_MODE),
        Z("docs/readme.txt", b"Read me.\n"),
        Z("photos/2024/beach.jpg", b"\xff\xd8\xff\xe0 not really a JPEG\n"),
        Z("notes.txt", b"Notes.\n"),
        Z("empty.txt", b""),
        Z("story.txt", b"Once upon a time, " * 30 + b"\n" + b"z" * 600, method=8),
    ]
    names_zip = [
        Z(b"caf\x82.txt", b"CP437\n"),
        Z("na\u00efve.txt", b"flagged\n", utf8=True),
        Z("r\u00e9sum\u00e9.txt".encode("utf-8"), b"unflagged UTF-8\n"),
        Z(b"old-name.txt", b"Unicode Path\n", upath=(crc32(b"old-name.txt"), "\u65e5\u672c\u8a9e.txt")),
        Z(b"kept.txt", b"stale Unicode Path\n", upath=(crc32(b"something else"), "ignored.txt")),
        Z("Cafe\u0301.txt", b"NFD\n", utf8=True),
        Z("CON.txt", b"device name\n"),
        Z("notes: draft?.txt", b"Windows characters\n"),
        Z("a:b?.txt", b"drive-relative\n"),
        Z("trailing.", b"trailing dot\n"),
        Z("photo\u202egpj.exe", b"bidi override\n", utf8=True),
        Z("bell\x07.txt", b"control\n"),
        Z(b"bad\xff.txt", b"invalid UTF-8\n", utf8=True),
        Z("a" * 256, b"long component\n"),
        Z("d/" * 64 + "f.txt", b"too deep\n"),
    ]
    slip_zip = [
        Z("../evil.txt", b"x"),
        Z("/etc/x", b"x"),
        Z("C:\\x", b"x"),
        Z("..\\..\\x", b"x"),
        Z(b"a\x00b", b"x"),
        Z("//server/share/y.txt", b"x"),
        Z("ok.txt", b"x"),
    ]
    links_zip = [
        Z("target.txt", b"Target.\n"),
        Z("link", b"target.txt", mode=0o120777),
        Z("fifo", mode=0o010644),
        Z("folder-by-mode", mode=DIR_MODE),
        Z("dos-folder", host=MSDOS, dos_attr=0x10),
    ]
    methods_zip = [
        Z("a.bin", payload=b"BZh91AY&SY not really", size=100, method=12),
        Z("b.bin", payload=b"not really Deflate64", size=50, method=9),
        Z("c.bin", payload=b"unknown", size=7, method=77),
        Z("d.txt", b"stored\n"),
    ]
    macos_zip = [
        Z("a.txt", b"Data.\n"),
        Z("__MACOSX/", mode=DIR_MODE),
        Z("__MACOSX/._a.txt", b"\x00\x05\x16\x07AppleDouble"),
    ]
    dupes_zip = [
        Z("Report.txt", b"1\n"),
        Z("report.txt", b"2\n"),
        Z("Report.txt", b"3\n"),
        Z("folder/a.txt", b"a\n"),
        Z("Folder/b.txt", b"b\n"),
        Z("docs/", mode=DIR_MODE),
        Z("docs/", mode=DIR_MODE),
    ]
    for file, members in [("plain.zip", plain_zip), ("names.zip", names_zip), ("slip.zip", slip_zip),
                          ("links.zip", links_zip), ("methods.zip", methods_zip), ("macos.zip", macos_zip),
                          ("dupes.zip", dupes_zip), ("empty.zip", [])]:
        add(file, zip_bytes(members), "zip", [zip_entry(m) for m in members], check=("zip", members))

    plain = zip_bytes(plain_zip)
    add("strong.zip", zip_bytes([Z("secret.txt", b"x", flags=0x41)]), None, refusal="strong_encryption")
    add("spanned.zip", zip_bytes([Z("part.txt", b"x")], end_disk=1), None, refusal="spanned")
    part = zip_bytes([Z("part.txt", b"x")])
    add("spanned.z01", b"PK\x07\x08" + part[: part.index(b"PK\x01\x02")], None, refusal="spanned")
    stub = b"MZ" + b"\x90" * 62 + b"This program cannot be run in DOS mode.\r\n" + b"\x00" * 150
    add("self-extracting.exe", zip_bytes([Z("setup.txt", b"x")], prefix=stub), None, refusal="self_extracting")
    last_central = plain.rindex(b"PK\x01\x02")
    add("truncated.zip", plain[: last_central + 46 + 2], None, refusal="truncated")

    for bits in (128, 192, 256):
        add(f"aes{bits}.zip", None, "zip", [entry(SECRET[0], [SECRET[0]], "file", SECRET[1], f"aes{bits}_ae2", None)])
    add("aes256-stored.zip", None, "zip", [entry(SECRET[0], [SECRET[0]], "file", SECRET[1], "aes256_ae2", None)])
    # ZipCrypto with the data-descriptor flag clear: the check byte is the CRC's high byte (the
    # DOS time's high byte differs, so reading the wrong one refuses the right password).
    secret = b"The protected test file.\n" * 40
    assert crc32(secret) >> 24 != DOS_TIME >> 8
    crc_check = [
        Z("empty.txt", b"", zipcrypto=(TEST_PASSWORD, zipcrypto_payload(TEST_PASSWORD, 0, b"", "empty"))),
        Z("secret.txt", secret,
          zipcrypto=(TEST_PASSWORD, zipcrypto_payload(TEST_PASSWORD, crc32(secret) >> 24, secret, "secret"))),
    ]
    add("zipcrypto-crc-check.zip", zip_bytes(crc_check), "zip", [zip_entry(m) for m in crc_check],
        check=("zip", crc_check))
    # The CP437 password; its UTF-8 bytes fail the first entry's check byte and pass the second's.
    cp437, utf8 = CP437_PASSWORD_TEXT.encode("cp437"), CP437_PASSWORD_TEXT.encode("utf-8")
    first, second = b"First.\n" * 20, b"Second.\n" * 20
    quick = [
        Z("first.txt", first, zipcrypto=(cp437, zipcrypto_payload(cp437, crc32(first) >> 24, first, "first",
                                                                  other=utf8))),
        Z("second.txt", second, zipcrypto=(cp437, zipcrypto_payload(cp437, crc32(second) >> 24, second,
                                                                    "second", other=utf8, other_passes=True))),
    ]
    add("zipcrypto-cp437-quick-check.zip", zip_bytes(quick), "zip", [zip_entry(m) for m in quick],
        check=("zip", quick))
    for file in ("zipcrypto.zip", "zipcrypto-cp437.zip"):
        add(file, None, "zip", [entry(SECRET[0], [SECRET[0]], "file", SECRET[1], "zipcrypto", None)])
    add("mixed.zip", None, "zip", [entry(PLAIN[0], [PLAIN[0]], "file", PLAIN[1], "none", None),
                                   entry(SECRET[0], [SECRET[0]], "file", SECRET[1], "zipcrypto", None)])
    add("two-passwords.zip", None, "zip", [entry(SECRET[0], [SECRET[0]], "file", SECRET[1], "zipcrypto", None),
                                           entry(OTHER[0], [OTHER[0]], "file", OTHER[1], "zipcrypto", None)])

    plain_tar = [
        T("docs/", typeflag=b"5"),
        T("docs/readme.txt", b"Read me.\n"),
        T("docs/link-to-readme", typeflag=b"2", linkname=b"readme.txt"),
        T("docs/hard-readme", typeflag=b"1", linkname=b"docs/readme.txt"),
        T("dev/tty0", typeflag=b"3", major=4),
        T("dev/pipe", typeflag=b"6"),
        T("beach.jpg", b"\xff\xd8\xff\xe0 not really a JPEG\n", prefix=b"photos/2024"),
        T("sparse.img", typeflag=b"S"),
        T("odd", typeflag=b"Z"),
        T("../escape.txt", b"x"),
        T("/abs.txt", b"absolute\n"),
        T("zeros.bin", b"\x00" * 3000),
    ]
    names_tar = [
        T(b"long/" + b"n" * 95, b"GNU long name\n", gnu_long=b"long/" + b"n" * 120 + b".txt"),
        T(b"caf\xe9.txt", b"Latin-1\n"),
        T(b"fallback.txt", b"pax path\n", pax_path="\u65e5\u672c\u8a9e/\u30d5\u30a1\u30a4\u30eb.txt".encode()),
        T(b"nfd.txt", b"pax NFD\n", pax_path="Cafe\u0301.txt".encode()),
    ]
    tar = tar_bytes(plain_tar)
    add("plain.tar", tar, "tar", [tar_entry(m) for m in plain_tar], check=("tar", plain_tar))
    add("names.tar", tar_bytes(names_tar), "tar", [tar_entry(m) for m in names_tar], check=("tar", names_tar))
    add("truncated.tar", tar[: 512 * 2 + 4], None, refusal="truncated")
    add("plain.tgz", gzip_member(tar), "tgz", [tar_entry(m) for m in plain_tar], check=("tgz", plain_tar))

    notes = b"Notes.\n" * 3
    gz = gzip_member(notes, name=b"backup/notes.txt", mtime=MTIME)
    add("notes.txt.gz", gz, "gz", [entry("notes.txt", ["notes.txt"], "file", len(notes), "none", None)],
        check=("gz", notes))
    add("nameless.gz", gzip_member(b"no name\n"), "gz", [entry("", None, "file", 8, "none", None)],
        check=("gz", b"no name\n"))
    joined = gzip_member(b"first\n", name=b"joined.txt") + gzip_member(b"second\n")
    add("two-members.gz", joined, "gz", [entry("joined.txt", ["joined.txt"], "file", 13, "none", None)],
        check=("gz", b"first\nsecond\n"))
    add("truncated.gz", gz[:-4], None, refusal="truncated")

    add("notes.txt", b"Just some notes, not an archive.\n", None, refusal="not_an_archive")
    for file, magic, name in [("archive.rar", b"Rar!\x1a\x07\x01\x00", "rar"),
                              ("archive.7z", b"7z\xbc\xaf\x27\x1c\x00\x04", "7z"),
                              ("archive.xz", b"\xfd7zXZ\x00\x00\x04", "xz"),
                              ("archive.zst", b"\x28\xb5\x2f\xfd\x24\x00", "zstd"),
                              ("archive.bz2", b"BZh91AY&SY", "bzip2")]:
        add(file, magic + b"\x00" * 32, None, refusal=f"foreign:{name}")
    return out


def stdlib_check(file, data, check):
    """Read a generated fixture back with Python's own readers."""
    kind, expected = check
    if kind == "zip":
        # zipfile refuses a whole archive over one flagged name that is not UTF-8, so that member
        # is left out of the archive it reads back.
        readable = [m for m in expected if not (m.utf8 and decode_zip(m)[1])]
        if len(readable) != len(expected):
            data, expected = zip_bytes(readable), readable
        infos = zipfile.ZipFile(io.BytesIO(data)).infolist()
        assert [i.file_size for i in infos] == [m.size for m in expected], file
        assert [i.CRC for i in infos] == [crc32(m.data) for m in expected], file
        for info, m in zip(infos, expected):
            if m.method in (0, 8):
                pwd = m.zipcrypto[0] if m.zipcrypto is not None else None
                assert zipfile.ZipFile(io.BytesIO(data)).read(info, pwd=pwd) == m.data, file
    elif kind in ("tar", "tgz"):
        mode = "r:gz" if kind == "tgz" else "r:"
        with tarfile.open(fileobj=io.BytesIO(data), mode=mode) as archive:
            members = archive.getmembers()
            assert [x.size for x in members] == [len(m.data) for m in expected], file
            for x, m in zip(members, expected):
                if x.isfile():
                    assert archive.extractfile(x).read() == m.data, file
    elif kind == "gz":
        assert gzip.decompress(data) == expected, file


# ---------------------------------------------------------------- words (§9)


def count(n):
    return f"{n:,}"


def size(n):
    n = min(n, 2**63 - 1)
    if n < 1000:
        return f"{n} B"
    units = ["B", "KB", "MB", "GB", "TB"]
    value, unit = float(n), 0
    while unit + 1 < len(units) and value >= 1000.0:
        value /= 1000.0
        unit += 1
    text = f"{value:.1f}"
    if unit + 1 < len(units) and float(text) >= 1000.0:
        value /= 1000.0
        unit += 1
        text = f"{value:.1f}"
    return f"{text} {units[unit]}"


def one(n, singular, plural):
    return singular if n == "1" else plural


WORDS = {
    "archive_reading": lambda a: "Reading the archive\u2026",
    "archive_kind_zip": lambda a: "ZIP archive",
    "archive_kind_tar": lambda a: "TAR archive",
    "archive_kind_tgz": lambda a: "TAR archive, gzip-compressed",
    "archive_kind_gz": lambda a: "gzip-compressed file",
    "archive_summary": lambda a: f"{a['files']} {one(a['files'], 'file', 'files')}, "
                                 f"{a['folders']} {one(a['folders'], 'folder', 'folders')} \u00b7 {a['size']}",
    "archive_empty": lambda a: "This archive is empty.",
    "archive_some_protected": lambda a: "Some files in this archive are protected by a password.",
    "archive_all_protected": lambda a: "The files in this archive are protected by a password.",
    "archive_names_not_protected": lambda a: "The password protects the files' contents, not their names.",
    "archive_zipcrypto_weak": lambda a: "This archive uses ZipCrypto, an old protection that can be broken "
                                        "without the password. Files you extract are stored with Beebeeb's own "
                                        "encryption.",
    "archive_listing_incomplete": lambda a: "This archive is too large to list here. Extract it to see all its "
                                            "files.",
    "entry_link": lambda a: "Link, not extracted",
    "entry_device": lambda a: "Special file, not extracted",
    "entry_outside": lambda a: "Points outside the folder, not extracted",
    "entry_bad_name": lambda a: "Name can't be used, not extracted",
    "entry_method": lambda a: f"Uses {a['method']} compression, which Beebeeb can't open",
    "entry_too_large": lambda a: "Too large to extract here",
    "entry_bomb": lambda a: "Expands far more than a normal file, not extracted",
    "entry_mac_resource": lambda a: "macOS resource data, not extracted",
    "entry_unsupported": lambda a: f"{a['what']}, not extracted",
    "entry_corrupt": lambda a: "Damaged in the archive, not extracted",
    "entry_other_password": lambda a: "Uses a different password, not extracted",
    "entry_renamed": lambda a: f"Saved as \"{a['name']}\"",
    "action_extract": lambda a: "Extract",
    "action_extract_to": lambda a: "Extract to\u2026",
    "action_extract_selected": lambda a: f"Extract {a['n']} {one(a['n'], 'item', 'items')}",
    "action_download": lambda a: "Download",
    "action_open": lambda a: "Open",
    "action_stop": lambda a: "Stop",
    "action_open_folder": lambda a: "Open folder",
    "action_move_to_trash": lambda a: "Move to Trash",
    "action_cancel": lambda a: "Cancel",
    "password_title": lambda a: "Enter the archive's password",
    "password_body": lambda a: f"\"{a['name']}\" is protected by a password. Beebeeb uses it on this device "
                               "only and doesn't keep it.",
    "password_wrong": lambda a: "That password didn't work. Check it and try again.",
    "extract_progress": lambda a: f"Extracting {a['done']} of {a['total']} {one(a['total'], 'file', 'files')} "
                                  f"\u00b7 {a['bytes_done']} of {a['bytes_total']}",
    "extract_keep_open": lambda a: "Keep Beebeeb open until extraction finishes.",
    "extract_done": lambda a: f"Extracted {a['files']} {one(a['files'], 'file', 'files')} to \"{a['folder']}\".",
    "extract_done_with_skips": lambda a: f"Extracted {a['files']} {one(a['files'], 'file', 'files')} to "
                                         f"\"{a['folder']}\". {a['skipped']} {one(a['skipped'], 'was', 'were')} "
                                         "not extracted; the list says why.",
    "extract_renamed": lambda a: f"{a['n']} {one(a['n'], 'file', 'files')} had the same name as another file "
                                 f"and {one(a['n'], 'was', 'were')} renamed.",
    "extract_stopped": lambda a: f"Extraction stopped. {a['done']} of {a['total']} "
                                 f"{one(a['total'], 'file is', 'files are')} in \"{a['folder']}\"; the rest were "
                                 "not extracted.",
    "extract_failed_storage_full": lambda a: f"Your storage is full. {a['done']} of {a['total']} "
                                             f"{one(a['total'], 'file was', 'files were')} extracted to "
                                             f"\"{a['folder']}\".",
    "extract_failed_network": lambda a: f"The connection was lost. {a['done']} of {a['total']} "
                                        f"{one(a['total'], 'file was', 'files were')} extracted to "
                                        f"\"{a['folder']}\".",
    "extract_failed_damaged": lambda a: f"The archive is damaged after {a['done']} of {a['total']} "
                                        f"{one(a['total'], 'file', 'files')}. "
                                        f"{one(a['done'], 'That file is', 'Those files are')} in \"{a['folder']}\".",
    "extract_failed_changed": lambda a: f"The archive changed while it was being extracted. {a['done']} of "
                                        f"{a['total']} {one(a['total'], 'file is', 'files are')} in "
                                        f"\"{a['folder']}\". Open it again to extract the new version.",
    "refuse_not_archive": lambda a: "This file isn't an archive Beebeeb can open. Beebeeb opens ZIP, TAR, TGZ and "
                                    "GZ files.",
    "refuse_foreign": lambda a: f"This is a {a['format']} archive. Beebeeb opens ZIP, TAR, TGZ and GZ files.",
    "refuse_sfx": lambda a: "This is a self-extracting program, not a plain archive.",
    "refuse_spanned": lambda a: "This is one part of a multi-part archive. Beebeeb opens single-file archives "
                                "only.",
    "refuse_strong_encryption": lambda a: "This archive uses PKWARE strong encryption, which Beebeeb can't open.",
    "refuse_damaged": lambda a: "This archive is damaged and can't be read.",
    "refuse_truncated": lambda a: "This archive ends too early. It may not have finished uploading.",
    "refuse_too_many": lambda a: "This archive has more than 100,000 items, more than Beebeeb extracts at once.",
    "refuse_too_large": lambda a: f"This archive expands to {a['size']}, more than Beebeeb extracts at once "
                                  f"({a['limit']}).",
    "refuse_bomb": lambda a: "This archive expands far more than normal archives do, so Beebeeb won't extract it.",
    "refuse_quota": lambda a: f"Extracting needs {a['needed']} and you have {a['free']} free.",
    "refuse_device_space": lambda a: f"Extracting needs {a['needed']} free on this device, and it has "
                                     f"{a['free']}.",
    "refuse_backups": lambda a: "Backups are read-only. Choose a folder outside Backups to extract to.",
    "refuse_read_only_folder": lambda a: "You can't add files to this folder. Choose another folder to extract to.",
    "refuse_web_entry_too_large": lambda a: f"{a['n']} {one(a['n'], 'file is', 'files are')} larger than "
                                            f"{a['limit']}, more than the browser can extract. Extract the rest "
                                            "here, or use the Beebeeb app or bb extract for all of them.",
    "cli_password_needed": lambda a: "This archive needs a password. Run it in a terminal, or pass the password "
                                     "with --password-stdin.",
    "cli_extract_to_hint": lambda a: "Add --to <folder> to extract somewhere else.",
}

GIB = 1 << 30
# (key, arguments) for every row; a key with no row here gets one with no arguments.
WORD_ROWS = [
    ("archive_summary", {"files": count(1), "folders": count(1), "size": size(999)}),
    ("archive_summary", {"files": count(1234), "folders": count(0), "size": size(3_355_443)}),
    ("entry_method", {"method": "bzip2"}),
    ("entry_unsupported", {"what": "Sparse file"}),
    ("entry_renamed", {"name": "report (2).pdf"}),
    ("action_extract_selected", {"n": count(1)}),
    ("action_extract_selected", {"n": count(1000)}),
    ("password_body", {"name": "photos.zip"}),
    ("extract_progress", {"done": count(0), "total": count(1), "bytes_done": size(0), "bytes_total": size(1500)}),
    ("extract_progress", {"done": count(1200), "total": count(12345), "bytes_done": size(2 * GIB),
                          "bytes_total": size(64 * GIB)}),
    ("extract_done", {"files": count(1), "folder": "photos"}),
    ("extract_done", {"files": count(12), "folder": "photos 2024"}),
    ("extract_done_with_skips", {"files": count(10), "folder": "photos", "skipped": count(1)}),
    ("extract_done_with_skips", {"files": count(1), "folder": "photos", "skipped": count(3)}),
    ("extract_renamed", {"n": count(1)}),
    ("extract_renamed", {"n": count(4)}),
    ("extract_stopped", {"done": count(0), "total": count(1), "folder": "photos"}),
    ("extract_stopped", {"done": count(5), "total": count(9), "folder": "photos"}),
    ("extract_failed_storage_full", {"done": count(1), "total": count(1), "folder": "photos"}),
    ("extract_failed_storage_full", {"done": count(2), "total": count(10), "folder": "photos"}),
    ("extract_failed_network", {"done": count(0), "total": count(1), "folder": "photos"}),
    ("extract_failed_network", {"done": count(1500), "total": count(2000), "folder": "photos"}),
    ("extract_failed_damaged", {"done": count(1), "total": count(5), "folder": "photos"}),
    ("extract_failed_damaged", {"done": count(4), "total": count(7), "folder": "photos"}),
    ("extract_failed_changed", {"done": count(1), "total": count(1), "folder": "photos"}),
    ("extract_failed_changed", {"done": count(3), "total": count(8), "folder": "photos"}),
    ("refuse_foreign", {"format": "RAR"}),
    ("refuse_too_large", {"size": size(300_000_000_000), "limit": size(256 * GIB)}),
    ("refuse_quota", {"needed": size(5 * GIB), "free": size(GIB)}),
    ("refuse_device_space", {"needed": size(64 * GIB), "free": size(999_950)}),
    ("refuse_web_entry_too_large", {"n": count(1), "limit": size(2 * GIB)}),
    ("refuse_web_entry_too_large", {"n": count(3), "limit": size(2 * GIB)}),
]
COUNTS = [0, 1, 12, 999, 1000, 12_345, 100_000, 1_234_567, 2**64 - 1]
SIZES = [0, 1, 999, 1000, 1049, 1050, 1250, 1_500_000, 999_949, 999_950, 2 * GIB, 64 * GIB, 256 * GIB,
         10**15, 2**63 - 1, 2**64 - 1]


def words():
    with_args = {key for key, _ in WORD_ROWS}
    rows = [(key, {}) for key in WORDS if key not in with_args] + WORD_ROWS
    rows.sort(key=lambda r: list(WORDS).index(r[0]))
    return [{"key": key, "args": args, "text": WORDS[key](args)} for key, args in rows]


def main():
    if len(sys.argv) not in (2, 3):
        sys.exit(__doc__)
    out_json = Path(sys.argv[1])
    out_dir = Path(sys.argv[2]) if len(sys.argv) == 3 else Path(__file__).resolve().parent.parent / "archives"
    out_dir.mkdir(parents=True, exist_ok=True)
    made = fixtures()
    generated = 0
    for file, data, fixture_row, check in made:
        if data is None:
            continue
        assert len(data) <= 64 * 1024, f"{file} is {len(data)} bytes, over 64 KiB"
        if check is not None:
            stdlib_check(file, data, check)
        (out_dir / file).write_bytes(data)
        generated += 1
    doc = {
        "version": 1,
        "platform": "native",
        "fixtures": sorted((r for _, _, r, _ in made), key=lambda r: r["file"]),
        "words": words(),
        "counts": [{"value": str(n), "text": count(n)} for n in COUNTS],
        "sizes": [{"bytes": str(n), "text": size(n)} for n in SIZES],
    }
    assert len(WORDS) == 63 and {w["key"] for w in doc["words"]} == set(WORDS)
    out_json.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {len(made)} fixture rows ({generated} fixtures written), {len(doc['words'])} words, "
          f"{len(COUNTS)} counts and {len(SIZES)} sizes to {out_json}")


if __name__ == "__main__":
    main()
