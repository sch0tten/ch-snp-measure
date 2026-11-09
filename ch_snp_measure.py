#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""ch-snp-measure: offline SEV-SNP launch measurement for Cloud Hypervisor (KVM) + IGVM.

Predicts the MEASUREMENT field of the SNP attestation report of a Cloud Hypervisor guest launched with
`--platform sev_snp=on --igvm <file>` on KVM, optionally with fw_cfg direct kernel boot
(`--kernel/--initramfs/--cmdline` + `--fw-cfg-config kernel=on,cmdline=on[,initramfs=on]`), without
launching the guest.

It replays Cloud Hypervisor v54.0's launch sequence (vmm/src/igvm/igvm_loader.rs `load_igvm`, KVM path):

1. IGVM directives in file order. Every PAGE_DATA becomes one SNP_LAUNCH_UPDATE (one 4 KiB page each,
   hypervisor/src/kvm/mod.rs `import_isolated_pages`) with the KVM page type:
     NORMAL + data          -> NORMAL     (contents = sha384(page))
     NORMAL + no data       -> ZERO       (contents = 0)      [KVM only; MSHV uses NORMAL]
     NORMAL + unmeasured    -> UNMEASURED (contents = 0)
     SECRETS                -> SECRETS    (contents = 0)
     CPUID_DATA             -> CPUID      (contents = 0; CH fills it from host CPUID, not measured)
   PARAMETER_INSERT -> one UNMEASURED page per page of the parameter area.
   SNP_VP_CONTEXT is NOT measured as a page on KVM (page_types.vmsa = None); CH only loads the VMSA's
   registers into the vCPU (setup_sev_snp_regs) and KVM builds the real VMSA itself.
2. The SEV kernel-hashes page (vmm/src/sev.rs, QEMU/OVMF-compatible table at GPA 0x10c00) if fw_cfg
   kernel+cmdline are on: injected into the IGVM page that covers 0x10000 if there is one (and measured as
   NORMAL in place), otherwise measured as an extra NORMAL page at 0x10000 after all directives.
3. KVM SNP_LAUNCH_FINISH: one VMSA page per vCPU (vCPU 0..N-1), GPA 0xFFFFFFFFF000, contents = the save
   area KVM synchronises from the vCPU state (arch/x86/kvm/svm/sev.c sev_es_sync_vmsa). That state is
   KVM's reset defaults overwritten by the IGVM VP context's segments, CRs, EFER, GDTR/IDTR and GPRs;
   sev_features = KVM_SEV_INIT2 vmsa_features (= IGVM vp0 sev_features with SNP_ACTIVE) | SNP_ACTIVE.

The digest primitives (PAGE_INFO chaining, SEV hash table, VMSA layout) come from sev-snp-measure.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
import sys
from dataclasses import dataclass, field

from sevsnpmeasure.gctx import GCTX
from sevsnpmeasure.sev_hashes import SevHashes
from sevsnpmeasure.vmsa import SevEsSaveArea, VmcbSeg

PAGE = 4096
SEV_HASH_BLOCK_ADDRESS = 0x10C00  # vmm/src/sev.rs
SEV_HASH_BLOCK_SIZE = 0x400

IGVM_MAGIC = 0x4D564749  # "IGVM"

VHT_SUPPORTED_PLATFORM = 0x1
VHT_GUEST_POLICY = 0x101
VHT_PARAMETER_AREA = 0x301
VHT_PAGE_DATA = 0x302
VHT_PARAMETER_INSERT = 0x303
VHT_VP_CONTEXT = 0x304
VHT_REQUIRED_MEMORY = 0x305
VHT_VP_COUNT_PARAMETER = 0x307
VHT_SNP_ID_BLOCK = 0x30B
VHT_MEMORY_MAP = 0x30C
VHT_COMMAND_LINE = 0x30E

PAGE_DATA_NORMAL, PAGE_DATA_SECRETS, PAGE_DATA_CPUID, PAGE_DATA_CPUID_XF = 0, 1, 2, 3
FLAG_2MB, FLAG_UNMEASURED, FLAG_SHARED = 1, 2, 4

# SNP_LAUNCH_UPDATE page types (SNP firmware ABI, PAGE_INFO.PAGE_TYPE)
PT_NORMAL, PT_VMSA, PT_ZERO, PT_UNMEASURED, PT_SECRETS, PT_CPUID = 1, 2, 3, 4, 5, 6
PT_NAME = {1: "NORMAL", 2: "VMSA", 3: "ZERO", 4: "UNMEASURED", 5: "SECRETS", 6: "CPUID"}

SNP_ACTIVE = 1
EFER_SVME = 1 << 12
CR0_CD, CR0_NW = 1 << 30, 1 << 29
CR4_MCE = 1 << 6
KVM_PAT_DEFAULT = 0x0007040600070406


# --------------------------------------------------------------------------------------------- IGVM parsing
@dataclass
class PageData:
    gpa: int
    compat: int
    flags: int
    data_type: int
    data: bytes  # b"" when file_offset == 0


@dataclass
class VpContext:
    gpa: int
    compat: int
    vp_index: int
    vmsa: SevEsSaveArea


@dataclass
class ParameterArea:
    index: int
    size: int


@dataclass
class ParameterInsert:
    gpa: int
    compat: int
    index: int


@dataclass
class Other:
    typ: int
    body: bytes


@dataclass
class Igvm:
    platforms: list = field(default_factory=list)
    policy: int | None = None
    directives: list = field(default_factory=list)
    sha256: str = ""


def parse_igvm(path: str) -> Igvm:
    raw = open(path, "rb").read()
    magic, ver, vh_off, vh_size, total, _crc = struct.unpack_from("<6I", raw, 0)
    if magic != IGVM_MAGIC:
        raise ValueError(f"{path}: not an IGVM file")
    if total != len(raw):
        raise ValueError(f"{path}: total_file_size {total} != {len(raw)}")
    out = Igvm(sha256=hashlib.sha256(raw).hexdigest())
    off, end = vh_off, vh_off + vh_size
    while off < end:
        typ, length = struct.unpack_from("<II", raw, off)
        body = raw[off + 8: off + 8 + length]
        off += 8 + ((length + 7) & ~7)
        if typ == VHT_SUPPORTED_PLATFORM:
            compat, vtl, ptype, pver, shared = struct.unpack_from("<IBBHQ", body)
            out.platforms.append(dict(compat=compat, platform_type=ptype, version=pver))
        elif typ == VHT_GUEST_POLICY:
            policy, _compat = struct.unpack_from("<QI", body)
            if policy and out.policy is None:  # CH: first non-zero GuestPolicy wins
                out.policy = policy
        elif typ == VHT_PAGE_DATA:
            gpa, compat, foff, flags, dtype, rsvd = struct.unpack_from("<QIIIHH", body)
            if flags & FLAG_2MB:
                raise NotImplementedError("2 MiB PAGE_DATA: Cloud Hypervisor v54 asserts 4 KiB only")
            data = raw[foff: foff + PAGE] if foff else b""
            out.directives.append(PageData(gpa, compat, flags, dtype, data))
        elif typ == VHT_VP_CONTEXT:
            gpa, compat, foff, vp, _r = struct.unpack_from("<QIIHH", body)
            vmsa = SevEsSaveArea.from_buffer_copy(raw[foff: foff + PAGE].ljust(PAGE, b"\0"))
            out.directives.append(VpContext(gpa, compat, vp, vmsa))
        elif typ == VHT_PARAMETER_AREA:
            nbytes, idx, _foff = struct.unpack_from("<QII", body)
            out.directives.append(ParameterArea(idx, nbytes))
        elif typ == VHT_PARAMETER_INSERT:
            gpa, compat, idx = struct.unpack_from("<QII", body)
            out.directives.append(ParameterInsert(gpa, compat, idx))
        elif typ < 0x300:
            continue  # other platform / initialization headers do not affect the digest
        else:
            out.directives.append(Other(typ, body))
    return out


# --------------------------------------------------------------------------------------------- VMSA (KVM)
def _seg(s: VmcbSeg) -> VmcbSeg:
    # make_segment() -> KVM_SET_SREGS -> svm_set_segment(): selector/base/limit kept, attrib rebuilt from
    # type/s/dpl/present/avl/l/db/g (bits 0-11). unusable = 0, so P is kept.
    return VmcbSeg(s.selector, s.attrib & 0x0FFF, s.limit, s.base)


def kvm_vmsa(ctx: SevEsSaveArea, sev_features: int, rdx: int | None = None) -> bytes:
    """VMSA page KVM measures at SNP_LAUNCH_FINISH for a vCPU set up from an IGVM VP context by CH."""
    v = SevEsSaveArea()
    for name in ("es", "cs", "ss", "ds", "fs", "gs", "ldtr", "tr"):
        setattr(v, name, _seg(getattr(ctx, name)))
    # GDTR/IDTR: only base + limit go through kvm_sregs (struct kvm_dtable); selector/attrib stay 0.
    v.gdtr = VmcbSeg(0, 0, ctx.gdtr.limit & 0xFFFF, ctx.gdtr.base)
    v.idtr = VmcbSeg(0, 0, ctx.idtr.limit & 0xFFFF, ctx.idtr.base)
    v.cpl = (ctx.ss.attrib >> 5) & 3  # svm_set_segment(SS) sets CPL from SS.DPL
    v.efer = ctx.efer | EFER_SVME  # svm_set_efer() always sets SVME
    v.cr0 = ctx.cr0 & ~(CR0_CD | CR0_NW)  # svm_set_cr0(), KVM_X86_QUIRK_CD_NW_CLEARED
    v.cr4 = ctx.cr4 | CR4_MCE  # svm_set_cr4() ORs in the host's CR4.MCE
    v.cr3 = ctx.cr3
    v.dr7 = 0x400
    v.dr6 = 0xFFFF0FF0
    v.rflags = ctx.rflags
    v.rip = ctx.rip
    v.rsp = ctx.rsp
    for r in ("rax", "rbx", "rcx", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"):
        setattr(v, r, getattr(ctx, r))
    v.rdx = ctx.rdx if rdx is None else rdx
    v.g_pat = KVM_PAT_DEFAULT
    v.sev_features = sev_features
    v.xcr0 = 1
    v.mxcsr = 0x1F80  # KVM guest FPU reset state (CH's setup_fpu writes the same values)
    v.x87_fcw = 0x37F
    b = bytes(v)
    assert len(b) == PAGE
    return b


# --------------------------------------------------------------------------------------------- replay
@dataclass
class Step:
    page_type: int
    gpa: int
    contents: bytes  # 48-byte contents hash (zeros for non-NORMAL/VMSA)
    note: str


def replay(igvm: Igvm, vcpus: int, hash_block: bytes | None, rdx: int | None,
           zero_as_normal: bool = False, vmsa_from_igvm: bool = False) -> tuple[list[Step], dict]:
    steps: list[Step] = []
    zeros48 = bytes(48)
    areas: dict[int, int] = {}
    hash_page = SEV_HASH_BLOCK_ADDRESS // PAGE * PAGE
    hash_off = SEV_HASH_BLOCK_ADDRESS % PAGE
    hash_inserted = hash_block is None
    vp_ctx: dict[int, SevEsSaveArea] = {}
    info = dict(page_data=0, zero=0, normal=0, cpuid=0, secrets=0, unmeasured=0, vp_contexts=0)

    for d in igvm.directives:
        if isinstance(d, PageData):
            info["page_data"] += 1
            if d.data_type == PAGE_DATA_NORMAL:
                if d.flags & FLAG_UNMEASURED:
                    pt = PT_UNMEASURED
                elif not d.data and not zero_as_normal:
                    pt = PT_ZERO
                else:
                    pt = PT_NORMAL
            elif d.data_type == PAGE_DATA_SECRETS:
                pt = PT_SECRETS
            elif d.data_type == PAGE_DATA_CPUID:
                pt = PT_CPUID
            else:
                raise NotImplementedError(f"PAGE_DATA type {d.data_type}: Cloud Hypervisor v54 todo!()s on it")
            data = d.data
            note = ""
            if hash_block is not None and d.gpa == hash_page and pt != PT_CPUID:
                page = bytearray(data.ljust(PAGE, b"\0"))
                page[hash_off: hash_off + SEV_HASH_BLOCK_SIZE] = hash_block
                data, pt, hash_inserted, note = bytes(page), PT_NORMAL, True, "kernel hashes injected"
            info[PT_NAME[pt].lower()] += 1
            contents = hashlib.sha384(data.ljust(PAGE, b"\0")).digest() if pt == PT_NORMAL else zeros48
            steps.append(Step(pt, d.gpa, contents, note))
        elif isinstance(d, ParameterArea):
            areas[d.index] = d.size
        elif isinstance(d, ParameterInsert):
            hash_end = SEV_HASH_BLOCK_ADDRESS + SEV_HASH_BLOCK_SIZE
            size = areas[d.index]
            if hash_block is not None and d.gpa <= SEV_HASH_BLOCK_ADDRESS and hash_end <= d.gpa + size:
                raise ValueError("IGVM parameter area overlaps the kernel-hashes block; CH refuses to launch")
            for p in range(size // PAGE):
                steps.append(Step(PT_UNMEASURED, d.gpa + p * PAGE, zeros48, f"parameter area {d.index}"))
        elif isinstance(d, VpContext):
            info["vp_contexts"] += 1
            vp_ctx[d.vp_index] = d.vmsa
            if vmsa_from_igvm:  # MSHV-style: the IGVM VMSA itself is measured in place (hypothesis only)
                steps.append(Step(PT_VMSA, d.gpa, hashlib.sha384(bytes(d.vmsa)).digest(), f"IGVM VMSA vp{d.vp_index}"))
        elif isinstance(d, Other):
            if d.typ in (VHT_VP_COUNT_PARAMETER, VHT_MEMORY_MAP, VHT_COMMAND_LINE, VHT_REQUIRED_MEMORY,
                         VHT_SNP_ID_BLOCK):
                continue  # parameter contents land in unmeasured pages; ID block only goes to LAUNCH_FINISH
            raise NotImplementedError(f"IGVM header type {d.typ:#x}: Cloud Hypervisor v54 todo!()s on it")

    if not hash_inserted:
        page = bytearray(PAGE)
        page[hash_off: hash_off + SEV_HASH_BLOCK_SIZE] = hash_block
        steps.append(Step(PT_NORMAL, hash_page, hashlib.sha384(bytes(page)).digest(),
                          "kernel hashes page (appended after IGVM directives)"))

    if not vmsa_from_igvm:
        if 0 not in vp_ctx:
            raise ValueError("IGVM has no VP context for vp_index 0")
        sev_features = (vp_ctx[0].sev_features & ~SNP_ACTIVE) | SNP_ACTIVE
        info["sev_features"] = sev_features
        for i in range(vcpus):
            if i not in vp_ctx:
                raise ValueError(f"vCPU {i} has no IGVM VP context (IGVM built for {len(vp_ctx)} vCPUs); "
                                 "CH would leave KVM reset state there -- not modelled")
            page = kvm_vmsa(vp_ctx[i], sev_features, rdx)
            steps.append(Step(PT_VMSA, GCTX.VMSA_GPA, hashlib.sha384(page).digest(), f"KVM VMSA vcpu{i}"))
        if len(vp_ctx) > vcpus:
            info["warning"] = (f"IGVM has {len(vp_ctx)} VP contexts but only {vcpus} vCPUs: CH applies the "
                               f"extra contexts to no vCPU; KVM measures {vcpus} VMSAs")
    return steps, info


def digest(steps: list[Step]) -> bytes:
    g = GCTX()
    for s in steps:
        g._update(s.page_type, s.gpa, s.contents)
    return g.ld()


def build_hash_block(kernel: str, initrd: str | None, cmdline: str) -> bytes:
    h = SevHashes(kernel, initrd, cmdline)  # sha256(kernel), sha256(initrd or b""), sha256(cmdline + NUL)
    table = h.construct_table()
    return table + bytes(SEV_HASH_BLOCK_SIZE - len(table))


# --------------------------------------------------------------------------------------------- CLI
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="ch-snp-measure",
        description="Predict the SEV-SNP launch MEASUREMENT of a Cloud Hypervisor (KVM) guest booted from an "
                    "IGVM firmware, optionally with fw_cfg direct kernel boot.")
    ap.add_argument("--igvm", required=True, help="IGVM file passed to cloud-hypervisor --igvm")
    ap.add_argument("--vcpus", type=int, required=True, help="boot vCPUs (--cpus boot=N)")
    ap.add_argument("--policy", type=lambda s: int(s, 0),
                    help="expected guest policy; checked against the IGVM GUEST_POLICY header (CH takes the "
                         "policy from the IGVM; the policy is not part of the digest)")
    ap.add_argument("--kernel", help="bzImage given to --kernel (with --fw-cfg-config kernel=on,cmdline=on)")
    ap.add_argument("--initrd", help="initramfs given to --initramfs (only if fw_cfg initramfs=on)")
    ap.add_argument("--cmdline", help="exact string given to --cmdline")
    ap.add_argument("--vcpu-sig", type=lambda s: int(s, 0),
                    help="override RDX in the measured VMSAs (CH copies RDX from the IGVM VP context; buildigvm "
                         "writes 0). For delta analysis only")
    ap.add_argument("--zero-as-normal", action="store_true",
                    help="hypothesis: measure data-less PAGE_DATA as NORMAL zero pages (MSHV/igvm-crate style) "
                         "instead of KVM ZERO pages")
    ap.add_argument("--vmsa-from-igvm", action="store_true",
                    help="hypothesis: measure the IGVM VMSA bytes in place (igvm crate / MSHV style) instead of "
                         "the KVM-built VMSAs")
    ap.add_argument("--no-kernel-hashes", action="store_true",
                    help="ignore --kernel/--initrd/--cmdline (as if fw_cfg kernel/cmdline were off)")
    ap.add_argument("--trace", action="store_true", help="print every measured page to stderr")
    ap.add_argument("--json", action="store_true", help="print a JSON record (inputs + measurement)")
    a = ap.parse_args(argv)

    igvm = parse_igvm(a.igvm)
    if not igvm.platforms or igvm.platforms[0]["platform_type"] != 2:  # IgvmPlatformType::SEV_SNP = 0x02
        print(f"warning: first IGVM platform is not SEV-SNP: {igvm.platforms}", file=sys.stderr)
    if a.policy is not None and igvm.policy != a.policy:
        have = f"{igvm.policy:#x}" if igvm.policy is not None else "absent"
        print(f"error: --policy {a.policy:#x} but the IGVM GUEST_POLICY is {have} (CH launches with the IGVM's)",
              file=sys.stderr)
        return 2

    hash_block = None
    if a.kernel and not a.no_kernel_hashes:
        if a.cmdline is None:
            print("error: CH builds the kernel-hashes table only when both kernel and cmdline are set "
                  "(pass --cmdline, '' for an empty one, or --no-kernel-hashes)", file=sys.stderr)
            return 2
        hash_block = build_hash_block(a.kernel, a.initrd, a.cmdline)

    try:
        steps, info = replay(igvm, a.vcpus, hash_block, a.vcpu_sig, a.zero_as_normal, a.vmsa_from_igvm)
    except (ValueError, NotImplementedError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    ld = digest(steps)

    if a.trace:
        for i, s in enumerate(steps):
            print(f"{i:4d} {PT_NAME[s.page_type]:<10} gpa={s.gpa:#014x} contents={s.contents.hex()[:16]} {s.note}",
                  file=sys.stderr)
        print(f"summary: {info}", file=sys.stderr)
    if "warning" in info:
        print(f"warning: {info['warning']}", file=sys.stderr)

    if a.json:
        import json

        def sha(p):
            return hashlib.sha256(open(p, "rb").read()).hexdigest() if p else None
        rec = dict(measurement=ld.hex(), igvm=a.igvm, igvm_sha256=igvm.sha256, vcpus=a.vcpus,
                   policy=hex(igvm.policy) if igvm.policy is not None else None,
                   kernel_hashes=hash_block is not None,
                   kernel_sha256=sha(a.kernel) if hash_block else None,
                   initrd_sha256=sha(a.initrd) if hash_block else None,
                   cmdline=a.cmdline if hash_block else None,
                   sev_features=hex(info.get("sev_features", 0)), pages_measured=len(steps),
                   model="cloud-hypervisor v54.0 KVM igvm_loader")
        print(json.dumps(rec, indent=2))
    else:
        print(ld.hex())
    return 0


if __name__ == "__main__":
    sys.exit(main())
