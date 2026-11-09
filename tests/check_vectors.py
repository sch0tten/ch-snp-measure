#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run ch-snp-measure over tests/vectors.json.

    uv run python tests/check_vectors.py

Vectors whose kernel/initramfs files are missing are skipped (they are not in git; see each vector's
"source"). A wrong input file (sha256 mismatch) is a FAIL. A 'measured' vector that does not reproduce
its chip-signed value is a FAIL. A 'predicted' vector that changes is reported as CHANGED (the tool's
model moved; decide whether that is a fix or a regression). Exit 1 on any FAIL.
"""
import hashlib
import io
import json
import os
import sys
from contextlib import redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
import ch_snp_measure  # noqa: E402


def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    vectors = json.load(open(os.path.join(HERE, "vectors.json")))["vectors"]
    fail = changed = ok = skipped = 0
    for v in vectors:
        paths = {k: os.path.join(ROOT, v[k]) for k in ("igvm", "kernel", "initrd") if v.get(k)}
        missing = [p for p in paths.values() if not os.path.exists(p)]
        if missing:
            print(f"SKIP     {v['id']}: missing {', '.join(os.path.relpath(p, ROOT) for p in missing)}")
            skipped += 1
            continue
        bad_input = False
        for k in ("igvm", "kernel", "initrd"):
            want = v.get(f"{k}_sha256")
            if want and k in paths and sha256(paths[k]) != want:
                print(f"FAIL     {v['id']}: {k} sha256 mismatch (wrong input file)")
                bad_input = True
        if bad_input:
            fail += 1
            continue
        argv = ["--igvm", paths["igvm"], "--vcpus", str(v["vcpus"]), "--policy", str(v["policy"])]
        if v.get("kernel"):
            argv += ["--kernel", paths["kernel"], "--cmdline", v["cmdline"]]
        if v.get("initrd") and v.get("fw_cfg_initramfs", True):
            argv += ["--initrd", paths["initrd"]]
        out = io.StringIO()
        with redirect_stdout(out):
            rc = ch_snp_measure.main(argv)
        got = out.getvalue().strip().split()[-1] if out.getvalue().strip() else ""
        if rc not in (0, None) or not got:
            print(f"FAIL     {v['id']}: tool exited {rc}")
            fail += 1
        elif got == v["expected"]:
            print(f"PASS     {v['id']} ({v['status']}) {got[:16]}…")
            ok += 1
        elif v["status"] == "measured":
            print(f"FAIL     {v['id']}: measured {v['expected'][:16]}… got {got[:16]}…")
            fail += 1
        else:
            print(f"CHANGED  {v['id']}: predicted {v['expected'][:16]}… now {got[:16]}…")
            changed += 1
    print(f"\n{ok} pass, {fail} fail, {changed} changed, {skipped} skipped (inputs not present)")
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
