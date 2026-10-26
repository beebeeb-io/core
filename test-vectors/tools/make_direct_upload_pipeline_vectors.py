#!/usr/bin/env python3
"""Contract fixtures for task 2173, option A. No runtime or network dependencies."""
import json
from pathlib import Path

CONSTANTS = {
    "UPLOAD_COMMIT_SLOTS_SMALL": 2,
    "UPLOAD_COMMIT_SLOTS_LARGE": 1,
    "UPLOAD_COMMIT_SLOTS_SMALL_BELOW": 16 * 1024 * 1024,
    "UPLOAD_PUT_LANES": 1,
    "UPLOAD_FILE_CONCURRENCY_DEFAULT": 4,
    "UPLOAD_FILE_CONCURRENCY_MAX": 8,
    "UPLOAD_TAIL_FILES_MAX": 4,
    "UPLOAD_API_REQUESTS_PER_SECOND_MAX": 60,
    "UPLOAD_API_BURST": 20,
}


def vectors():
    return {
        "source": "task 2173 direct upload pipelining design sections 3.3 and 4",
        "constants": CONSTANTS,
    }


if __name__ == "__main__":
    path = Path(__file__).resolve().parents[1] / "direct_upload_pipeline.json"
    path.write_text(json.dumps(vectors(), indent=2) + "\n")
