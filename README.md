# ch-snp-measure

**Offline SEV-SNP launch measurement for Cloud Hypervisor guests booted from an IGVM firmware.**

`ch-snp-measure` predicts the `MEASUREMENT` field of the AMD SEV-SNP attestation report of a
[Cloud Hypervisor](https://github.com/cloud-hypervisor/cloud-hypervisor) guest **without launching it**. The guest is:

- booted on KVM from an IGVM firmware image (Project Oak's [stage0](https://github.com/project-oak/oak/tree/main/stage0),
  packed with `buildigvm`);
- optionally given a direct-boot kernel, initramfs and command line over fw_cfg
  (`--kernel --initramfs --cmdline --fw-cfg-config kernel=on,cmdline=on,initramfs=on`).

A relying party can compute the expected value at build time and load it into its verifier (for example Trustee's
reference-value store) before the guest exists. Each new kernel, command-line variant or vCPU shape is a computation,
not a launch.

**Validated against hardware:** every chip-signed measurement we could read back from real launches matched the tool
bit for bit. Six distinct values so far, over four distribution kernels, two vCPU counts and a command-line variation.
Host: AMD EPYC 8124P (Siena), Cloud Hypervisor v54.0, Linux 7.0 host kernel. See [Test vectors](#test-vectors).

```
$ uv run ch-snp-measure --igvm igvm/stage0-legacygap-snp-8vcpu.igvm --vcpus 8 --policy 0x30000 \
    --kernel vmlinuz-7.0.0-43-generic --initrd initrd.img-7.0.0-43-generic \
    --cmdline 'root=UUID=a9c87573-c170-44a0-8c14-09fcc03a56a9 ro console=ttyS0 pci=realloc,nocrs swiotlb=262144'
8aa870bc6370bf97e68dfe3855b347ee2973e31d231d59472348a2b8e576e730da06b0006f37b123409dfaac2b737f84
```

That is the value the SNP firmware put in the report of the guest launched with exactly those files.

## Why a new tool

No existing calculator reproduces Cloud Hypervisor's value (checked 2026-11-08):

| Tool | What it computes | Why it does not give the Cloud Hypervisor value |
|---|---|---|
| [`sev-snp-measure`](https://github.com/virtee/sev-snp-measure) 0.0.13 and `main` | QEMU/OVMF, EC2 and GCE layouts, from the OVMF SEV metadata | No IGVM input. Fed the raw stage0 ROM as `--ovmf` it gives a different value, because QEMU measures the kernel-hashes page in metadata order right after the CPUID page, while Cloud Hypervisor measures it *after all IGVM pages*. The `igvm-support` branch cited by Cloud Hypervisor PR #8123 only adds an IGVM *ID-block output*, not an IGVM measurement mode |
| [`igvm`](https://github.com/microsoft/igvm) crate, `measurement::generate_snp_measurement` | Digest straight from the IGVM headers | Models the MSHV/OpenHCL view: data-less pages are measured as NORMAL zero pages, the IGVM VMSA bytes are measured in place, and there is no kernel-hashes page. KVM uses ZERO pages and builds its own VMSAs |
| Oak `snp_measurement` | stage0 from its ROM/ELF, `--qemu` or a GCE-like layout | Does not read IGVM; without `--qemu` it skips the kernel-hashes page, and it puts the CPU family/model/stepping in RDX. Its "expected measurements for 1/2/4/…/64 vCPUs" in the stage0 provenance bundle therefore do not apply to Cloud Hypervisor |
| Hyper-V / OpenHCL `igvmfilegen`, `igvm_measure` | MSHV | Same model as the igvm crate |

`ch-snp-measure` is a small calculator on top of `sev-snp-measure`'s primitives (the `GCTX` PAGE_INFO chaining, the
SEV hash table and the `SevEsSaveArea` VMSA layout).

## Install and run

```sh
git clone https://github.com/sch0tten/ch-snp-measure
cd ch-snp-measure
uv sync                                   # Python >= 3.12 venv with sev-snp-measure==0.0.13; nothing system-wide
uv run ch-snp-measure --help
uv run python tests/check_vectors.py      # replays tests/vectors.json (needs the kernels; see below)
```

How each option maps to the Cloud Hypervisor launch:

| Tool option | Cloud Hypervisor | Notes |
|---|---|---|
| `--igvm` | `--igvm` | The same file, byte for byte |
| `--vcpus` | `--cpus boot=N` | The IGVM must have at least N VP contexts; `buildigvm --cpucount` must equal N. (On `main` after the SNP CPU-hotplug change the count that matters may be `max=`; all our launches used `boot=N,max=N`. Unverified) |
| `--policy` | — | Only checked against the IGVM `GUEST_POLICY` header. Cloud Hypervisor launches with the IGVM's policy; the policy is a separate report field, not part of the digest |
| `--kernel`, `--cmdline` | `--kernel`, `--cmdline` | Only with `--fw-cfg-config kernel=on,cmdline=on`. Without both, Cloud Hypervisor builds no hash table: omit them or pass `--no-kernel-hashes`. The cmdline is the exact `--cmdline` string, hashed with a trailing NUL. stage0 appends `-- --oak-dice=…` later; that is not part of the hash |
| `--initrd` | `--initramfs` | Only if `initramfs=on`. With `initramfs=off`, omit it: Cloud Hypervisor hashes an empty initrd, which gives a different value |
| `--json` | — | Prints a record with the inputs, their sha256s and the measurement: one line of a golden-image registry |

Diagnostic switches for testing hypotheses (none is needed for the validated case): `--trace` prints every measured
page; `--vcpu-sig`, `--zero-as-normal`, `--vmsa-from-igvm`, `--no-kernel-hashes` switch to the other models in the table
above.

**Not part of the digest:** `--host-data` (a separate report field), memory size, disks, NICs, passed-through devices
(a GPU with a 128 GiB BAR gave the same value), the ACPI tables and E820. stage0 measures ACPI and E820 into its own
DICE event log, not into `MEASUREMENT`.

## What it models (Cloud Hypervisor v54.0, KVM path)

The digest is SHA-384 chained over 0x70-byte `PAGE_INFO` structures, per the SNP firmware ABI (`SNP_LAUNCH_UPDATE`).
Each structure holds the running digest, the page contents digest (sha384 of the page for NORMAL and VMSA pages, zero
otherwise), the length, the page type, `imi = 0`, the VMPL permissions and the GPA.

Cloud Hypervisor issues the updates in this order (source references are to tag `v54.0`):

1. **IGVM directives, in file order.** Cloud Hypervisor keeps file order on KVM because the digest depends on it
   (`vmm/src/igvm/igvm_loader.rs`), one `KVM_SEV_SNP_LAUNCH_UPDATE` per 4 KiB page (`hypervisor/src/kvm/mod.rs`,
   `import_isolated_pages`). Page types:

   | IGVM `PAGE_DATA` | SNP page type | contents |
   |---|---|---|
   | NORMAL with data | NORMAL | sha384(page) |
   | NORMAL without data (`file_offset = 0`) | **ZERO** (KVM only) | 0 |
   | NORMAL + `unmeasured` flag | UNMEASURED | 0 |
   | SECRETS | SECRETS | 0 |
   | CPUID_DATA | CPUID | 0 (filled from host CPUID, content not measured) |
   | PARAMETER_INSERT | UNMEASURED, one per page of the area | 0 |
   | SNP_VP_CONTEXT | **not a page on KVM** | — |

   For a `buildigvm` stage0 IGVM that is: 128 ROM pages at `0xFFF80000-0xFFFFFFFF`, SECRETS at `0x2000`, ZERO at
   `0x0`, CPUID at `0x1000`, 32 ZERO pages at `0x60000-0x7FFFF`: 163 `PAGE_DATA` directives.
2. **The SEV kernel-hashes page**, only if fw_cfg `kernel` and `cmdline` are on (`vmm/src/vm.rs`). It holds the
   QEMU/OVMF-compatible table at GPA `0x10C00` (`vmm/src/sev.rs`): sha256 of the cmdline plus NUL, of the initrd (or of
   the empty string without one), and of the whole bzImage. Its **content is measured** as a NORMAL page. If an IGVM
   `PAGE_DATA` covers page `0x10000`, the table is injected into it and that page is measured in place; otherwise, as
   with `buildigvm`'s stage0 IGVM, it is measured as an extra NORMAL page at `0x10000` **after all IGVM directives**.
   This placement is the difference from QEMU/OVMF. Cloud Hypervisor refuses an IGVM whose parameter area overlaps
   the table; the tool raises an error for that case.
3. **`SNP_LAUNCH_FINISH`: KVM measures one VMSA per vCPU**, vCPU 0..N-1, at GPA `0xFFFFFFFFF000`. Cloud Hypervisor
   does not import the IGVM VMSA on KVM. It copies segments, CR0/3/4, EFER (minus SVME), GDTR/IDTR, RIP, RFLAGS and
   the GPRs into the vCPU (`setup_sev_snp_regs`), and KVM builds the VMSA itself (`arch/x86/kvm/svm/sev.c`,
   `sev_es_sync_vmsa`): EFER.SVME, CR4.MCE, CR0 with CD/NW cleared, DR6 `0xFFFF0FF0`, DR7 `0x400`, G_PAT
   `0x0007040600070406`, XCR0 1, x87 FCW `0x37F`, MXCSR `0x1F80`, `sev_features` = the `KVM_SEV_INIT2` `vmsa_features`
   (the IGVM vp0's `sev_features`) with SNP_ACTIVE. These are the same KVM defaults that `sev-snp-measure`'s QEMU VMSA
   encodes. `buildigvm` writes RDX = 0 where QEMU puts the CPUID signature, so the **CPU family/model does not enter
   the digest** for these IGVMs and `--vcpu-sig` is not an input.

Each piece is pinned by the validated vectors. Changing any one of them changes the value:

| Changed piece | Result for the 8-vCPU Ubuntu vector |
|---|---|
| no kernel hashes | `ef7604f5…` |
| ZERO pages measured as NORMAL | `d36568c9…` |
| RDX = 0xaa0f02 | `4279b4a3…` |
| IGVM VMSA bytes instead of the KVM VMSA | `c0e421ef…` |

## Test vectors

`tests/vectors.json` has 24 launch shapes from a matrix of ten stock distribution kernels (Linux 6.1 to 7.2) booted as
SNP guests under Cloud Hypervisor v54.0 with the released stage0 and with the patched one in `igvm/`. Six of them are
**measured**: the chip-signed `MEASUREMENT` read from the guest, which the tool reproduces exactly.

| Kernel | IGVM | vCPUs | Measured value |
|---|---|---|---|
| Ubuntu 26.04 `7.0.0-43-generic` | legacygap | 8 | `8aa870bc…2b737f84` |
| same, cmdline + `cclab=1` | legacygap | 8 | `85a3bf18…45954790` (one extra token changes the value) |
| same | legacygap | **24** | `ffedc316…dc48e4ae1` (the vCPU count changes the value) |
| Ubuntu 24.04 HWE `7.0.0-42-generic` | legacygap | 8 | `4bb6b7d3…39fd4ae8` |
| Fedora 45 `7.2.11-300.fc45` | legacygap | 8 | `859e51f6…db1c02e0` |
| Arch `7.2.11-arch1-1` | legacygap | 8 | `9152eeae…6cf055` |

The other 18 are **predicted**: either the kernel panicked under the released stage0 before a report could be read
(the legacy-range bug, [Oak #5205](https://github.com/project-oak/oak/issues/5205)), or the guest booted but its 6.x
kernel read the DICE handoff page back as ciphertext so the value could not be captured. They are in the file so that a
model change shows up as `CHANGED`, and so that anyone who launches one of those shapes can promote it to `measured`.

The kernels and initramfs images are not in git. Every vector records the exact source (distribution cloud image or
package URL with its published checksum) and the sha256 of each boot file. `tests/extract-boot-files.sh` copies the boot
files out of a cloud image read-only. `tests/check_vectors.py` skips vectors whose inputs are missing, fails on a
sha256 mismatch or a measured vector that does not reproduce, and reports a predicted vector that moved as `CHANGED`.

Two of the six measured inputs are reproducible only approximately: the Ubuntu 26.04 initramfs was generated by
`update-initramfs` on an installed system and the Ubuntu 24.04 HWE initramfs was generated inside the cloud image after
installing the HWE package; their sha256s are recorded. The Fedora and Arch inputs come straight out of the published
cloud images.

## What the measurement proves, and what it does not

Oak's published `stage0_bin` is built without the `sev_kernel_hashes` crate feature, and so are the IGVMs in `igvm/`.
So:

| | |
|---|---|
| **Proves** | A chip-signed report with this `MEASUREMENT` comes from a guest that started in exactly this IGVM (stage0 bits, page layout, initial vCPU state for N vCPUs) with this kernel-hashes table in memory. The table names the kernel, initramfs and cmdline that the **host claimed** |
| **Does not prove** | That stage0 loaded *that* kernel. stage0 reads the kernel over fw_cfg and does not compare it with the table, so a malicious host can write the right table and feed another kernel. Measured, not enforced |

Two ways to close the gap: (a) build stage0 with `sev_kernel_hashes`, so it refuses mismatching blobs and the
`MEASUREMENT` alone covers the kernel; or (b) have the verifier also check stage0's DICE event log, which records the
kernel, setup, cmdline and initrd digests stage0 computed itself, signed by the key bound into `REPORT_DATA`. Until
one of those is in place, treat the kernel part of this value as an integrity claim by the host.

## Using it as a golden-image registry

One `MEASUREMENT` corresponds to one tuple: (IGVM sha256, vCPU count, kernel sha256, initramfs sha256, exact cmdline,
Cloud Hypervisor version). The host CPU model and host kernel range are metadata, not inputs.

```sh
uv run ch-snp-measure --json --igvm … --vcpus 8 --kernel … --initrd … --cmdline '…'   # one record per approved tuple
```

Register the values as a list under your verifier's SNP launch-measurement reference key (for Trustee, the
`snp_launch_measurement` RVPS key) and let the policy accept a launch whose `MEASUREMENT` is in the list, together with
`host_data`/initdata and TCB checks. The registry (inputs, sha256s, value) is then the auditable artefact, and a new
distribution kernel is a new row, computed in CI, no launch needed.

## Limits

- **Code paths without a test vector yet** (modelled from source, unverified): parameter areas and inserts, `unmeasured`
  `PAGE_DATA`, a `PAGE_DATA` that covers `0x10000` (in-place injection, e.g. an OVMF-derived IGVM), IGVMs whose VMSA sets
  CR0.CD/NW, a non-zero RDX or `sev_features` beyond SNP_ACTIVE (DebugSwap, SecureTSC).
- **Not supported:** more vCPUs than IGVM VP contexts (the tool errors), 2 MiB pages and CPUID_XF, MSHV, the SNP ID block
  (it changes `ID_KEY_DIGEST`/`AUTHOR_KEY_DIGEST`, not `MEASUREMENT`).
- **Host dependence:** CR4.MCE comes from the host CR4 (always set on EPYC); the KVM VMSA defaults are those of Linux 7.0
  KVM, and the FPU/XCR0 sync for `KVM_SEV_INIT2` VMs exists since Linux 6.10. Record the host kernel range next to the
  value. The result should be host-CPU independent for `buildigvm` IGVMs (RDX = 0); verified on Siena only.
- **Cloud Hypervisor version:** the model is v54.0. The order of the kernel-hashes page and the ZERO-page mapping are
  Cloud Hypervisor choices, not ABI. Re-validate on every bump; the measured vectors are the regression test.

## Background

Built in the course of a confidential-computing lab on a single AMD EPYC 8004 + NVIDIA RTX PRO 6000 Blackwell Server
Edition box, where SNP guests under Cloud Hypervisor needed reference values a key broker could gate on. Related work
from the same lab: the stage0 legacy-range fix ([Oak #5205](https://github.com/project-oak/oak/issues/5205),
[PR #5206](https://github.com/project-oak/oak/pull/5206)) that lets stock distribution kernels boot under stage0 at
all, and a Cloud Hypervisor documentation note on running SNP guests with stage0 and a distribution kernel.

Written by Stefano Schotten with Claude Code assistance; every value in this repository was checked against a
chip-signed report or the referenced source before being written down.

## License

Apache-2.0 (see `LICENSE` and `NOTICE`). The IGVM images are builds of Project Oak's stage0, also Apache-2.0.
