#!/usr/bin/env python3
"""Independently generate the name-clash vectors: numbered names, drive conflict names and the
normalised form that decides when two names clash.

Usage:
    python3 -I test-vectors/tools/gen_name_clash_v1.py test-vectors/name_clash_v1.json

No Rust is run. Normalisation is NFKC(simple_casefold(NFKC(name))), with NFKC from `unicodedata`
and simple folding (CaseFolding.txt statuses C and S, never Python's full `str.casefold`) read from
the same Unicode file core's table comes from. Expected names follow the design's rules:
- a file's extension is the text from its last dot, and a name whose only dot leads has none;
- a folder's whole name is its stem;
- the counter goes onto the name as given, starting at (2), and never parses an existing suffix;
- the stem is cut at a character boundary so that the whole name fits in 255 bytes;
- the device in a conflict name has `/` and `\\` replaced by `_` and is cut to 64 bytes.
"""
import json
from pathlib import Path
import sys
import unicodedata

UCD = Path(__file__).parent / "ucd" / "CaseFolding-17.0.0.txt"
UNICODE_VERSION = "17.0.0"
MAX_NAME_BYTES = 255
DEVICE_MAX_BYTES = 64
MAX_INPUT_BYTES = 1024
MAX_OUTPUT_BYTES = 4096


def simple_folds():
    folds = {}
    for line in UCD.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        code, status, mapping = [field.strip() for field in line.split(";")[:3]]
        if status in ("C", "S"):
            folds[chr(int(code, 16))] = chr(int(mapping, 16))
    return folds


FOLDS = simple_folds()


def normalize(name):
    """The normalised form, or None when the name is refused (empty, or over 1024 bytes before
    normalising, or over 4096 after)."""
    if not name or len(name.encode("utf-8")) > MAX_INPUT_BYTES:
        return None
    first = unicodedata.normalize("NFKC", name)
    folded = "".join(FOLDS.get(c, c) for c in first)
    out = unicodedata.normalize("NFKC", folded)
    if len(out.encode("utf-8")) > MAX_OUTPUT_BYTES:
        return None
    return out


def taken_key(name):
    key = normalize(name)
    return key if key is not None else name.lower()


def split_extension(name):
    dot = name.rfind(".")
    if dot <= 0:
        return name, ""
    return name[:dot], name[dot:]


def prefix_within(text, max_bytes):
    data = text.encode("utf-8")
    if len(data) <= max_bytes:
        return text
    end = max_bytes
    while end > 0 and (data[end] & 0xC0) == 0x80:
        end -= 1
    return data[:end].decode("utf-8")


def first_char_len(text):
    return len(text[0].encode("utf-8")) if text else 0


def with_suffix(name, kind, suffix):
    if kind == "folder":
        stem, extension = name, ""
    else:
        stem, extension = split_extension(name)
        if len(extension.encode()) + len(suffix.encode()) + first_char_len(stem) > MAX_NAME_BYTES:
            stem, extension = name, ""
    room = max(0, MAX_NAME_BYTES - len(suffix.encode()) - len(extension.encode()))
    return prefix_within(stem, room) + suffix + extension


def clean_device(device):
    # Only the rows below are covered: plain devices, separators and length. Anything the full
    # path-safety rule would change otherwise is refused here, so this port cannot drift silently.
    assert not any(c in device for c in ':<>"|?*\0') and device.strip(". ") == device, device
    assert all(unicodedata.category(c)[0] != "C" for c in device), device
    cleaned = device.replace("/", "_").replace("\\", "_")
    return prefix_within(cleaned, DEVICE_MAX_BYTES)


def numbered_name(original, kind, taken):
    keys = {taken_key(name) for name in taken}
    counter = 2
    while True:
        candidate = with_suffix(original, kind, f" ({counter})")
        if taken_key(candidate) not in keys:
            return candidate
        counter += 1


def numbered_candidates(original, kind, count):
    return [with_suffix(original, kind, f" ({n})") for n in range(2, count + 2)]


def drive_conflict_name(original, kind, device, taken):
    keys = {taken_key(name) for name in taken}
    base = f" (conflict, {clean_device(device)})"
    counter = 1
    while True:
        suffix = base if counter == 1 else f"{base} ({counter})"
        candidate = with_suffix(original, kind, suffix)
        if taken_key(candidate) not in keys:
            return candidate
        counter += 1


def numbered(id_, original, kind, taken, note):
    return {"id": id_, "kind": "numbered", "item": kind, "original": original, "taken": taken,
            "expected": numbered_name(original, kind, taken), "note": note}


def drive(id_, original, kind, device, taken, note):
    return {"id": id_, "kind": "drive", "item": kind, "original": original, "device": device, "taken": taken,
            "expected": drive_conflict_name(original, kind, device, taken), "note": note}


def candidates(id_, original, kind, count, note):
    return {"id": id_, "kind": "candidates", "item": kind, "original": original, "count": count,
            "expected": numbered_candidates(original, kind, count), "note": note}


def same(id_, a, b, note):
    return {"id": id_, "kind": "normalize", "a": a, "b": b, "normalized_a": normalize(a),
            "normalized_b": normalize(b), "same": normalize(a) == normalize(b), "note": note}


def main():
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parents[1] / "name_clash_v1.json"
    long_stem = "a" * 300
    cases = [
        numbered("numbered_extension", "report.pdf", "file", [], "the counter goes before the extension"),
        numbered("numbered_next_free", "report.pdf", "file", ["report (2).pdf"], "(2) is taken, so (3)"),
        numbered("numbered_no_extension", "notes", "file", [], "a file without a dot"),
        numbered("numbered_leading_dot", ".env", "file", [], "a name whose only dot leads has no extension"),
        numbered("numbered_folder_with_dot", "v1.2", "folder", [], "a folder's whole name is its stem"),
        numbered("numbered_existing_suffix", "report (2).pdf", "file", [],
                 "an existing suffix is never parsed: the counter goes onto the name as given"),
        numbered("numbered_full_width_taken", "report.pdf", "file", ["report (\uff12).pdf"],
                 "a taken full-width (2) is the same name after NFKC, so (3)"),
        numbered("numbered_case_taken", "Report.PDF", "file", ["REPORT (2).pdf"],
                 "a taken name in other case blocks its spelling"),
        numbered("numbered_folder_counts_up", "Photos", "folder", ["photos (2)", "PHOTOS (3)"],
                 "folders count up past every taken spelling"),
        numbered("numbered_255_cut", long_stem + ".pdf", "file", [],
                 "the stem is cut so that the whole name is exactly 255 bytes"),
        numbered("numbered_255_cut_multibyte", "\u00e9" * 200 + ".txt", "file", [],
                 "the cut never splits a character"),
        drive("drive_file", "report.pdf", "file", "GLegion", [], "the second copy names the device that lost"),
        drive("drive_taken_counts", "report.pdf", "file", "B", ["report (conflict, B).pdf"],
              "a taken conflict name gets (2) after the device"),
        drive("drive_taken_other_case", "report.pdf", "file", "B",
              ["REPORT (CONFLICT, B).PDF", "report (conflict, b) (2).pdf"],
              "taken spellings are compared normalised"),
        drive("drive_folder", "Photos", "folder", "B", [], "a folder's whole name is the stem"),
        drive("drive_folder_superscript", "x\u00b2", "folder", "B", [], "the name is kept as typed"),
        drive("drive_device_separator", "report.pdf", "file", "a/b", [], "a separator in the device becomes _"),
        drive("drive_device_backslash", "report.pdf", "file", "a\\b", [], "a backslash too"),
        drive("drive_device_cut", "report.pdf", "file", "d" * 100, [], "the device is cut to 64 bytes"),
        drive("drive_255_cut", long_stem + ".pdf", "file", "GLegion", [],
              "the stem is cut, never the device or the extension"),
        candidates("candidates_three", "report.pdf", "file", 3, "(2) to (count + 1), no taken set"),
        candidates("candidates_folder", "v1.2", "folder", 2, "a folder's whole name is the stem"),
        same("normalize_case", "Backups", "BACKUPS", "case is folded"),
        same("normalize_full_width", "Backups", "\uff22\uff41\uff43\uff4b\uff55\uff50\uff53", "NFKC folds full-width forms"),
        same("normalize_composed", "\u00e9", "e\u0301", "composed and decomposed are one name"),
        same("normalize_ligature", "\ufb01le", "file", "NFKC splits the ligature"),
        same("normalize_capital_sharp_s", "Stra\u00dfe", "STRA\u1e9eE", "U+1E9E folds to the sharp s"),
        same("normalize_no_full_folding", "Stra\u00dfe", "STRASSE", "simple folding never maps the sharp s to ss"),
        same("normalize_sigma", "\u03a3\u0391\u03a3", "\u03c3\u03b1\u03c2", "both sigmas fold to one"),
        same("normalize_dotted_i", "\u0130stanbul", "istanbul", "the dotted capital I has no simple folding"),
        same("normalize_zwj_kept", "a\u200db", "ab", "a zero-width joiner is kept"),
        same("normalize_micro", "\u00b5m", "\u03bcm", "micro sign and mu are one name"),
        same("normalize_cherokee", "\uab70", "\u13a0", "Cherokee small letters fold to the capitals"),
        same("normalize_compose_after_folding", "T\u0308", "\u1e97",
             "folding T + U+0308 gives t + U+0308, which the second NFKC composes"),
        same("normalize_refused_empty", "", "", "an empty name is refused"),
        same("normalize_limit", "a" * 1024, "A" * 1024, "1024 bytes is the longest input"),
        same("normalize_refused_long", "a" * 1025, "a" * 1025, "1025 bytes is refused"),
    ]
    doc = {
        "version": 1,
        "unicode": UNICODE_VERSION,
        "note": "Name clashes: numbered names, drive conflict names and the normalised form; generated by "
                "tools/gen_name_clash_v1.py (unicodedata and CaseFolding.txt), never edited by hand.",
        "cases": cases,
    }
    assert len({case["id"] for case in cases}) == len(cases)
    out.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
