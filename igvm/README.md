# IGVM firmware images used by the test vectors

All four are Project Oak **stage0** (https://github.com/project-oak/oak) wrapped for SEV-SNP with Oak's `buildigvm`
(`buildigvm --cpucount N --guest-policy 0x30000`, buildigvm built from Oak commit `58264592`). Apache-2.0.

| File | sha256 | stage0 source |
|---|---|---|
| `stage0-snp-8vcpu.igvm` | `a9231292b62de8366692253284c6e2eaa8b505287faf5d8c8926c87144b48a9c` | Oak `96d36345ed43ba7d5316421fbeab101583c7b92b` (2026-10-30), the ROM is bit-identical to Oak's published `stage0_bin` `215848dcea1c4190d48fe94c0590c273ea510cbec27f5b1dd9f043f444d74c4d` |
| `stage0-snp-24vcpu.igvm` | `e61b69a4a2f8cb816c729086af0bdc0ed5b89255aff4d0480cebaf6658f2c6cd` | same ROM, 24 VP contexts |
| `stage0-legacygap-snp-8vcpu.igvm` | `7ad5f63feb97ac57eff56d40ce69ccafe43ea476b62d814132aeb243a3e39b1d` | Oak `96d36345` + the legacy-range fix proposed in https://github.com/project-oak/oak/pull/5206 (ROM `23a949d35be7a3e464692cc2a41f2334fe330fc0490e1b9c07ae9a9002f51b1e`) |
| `stage0-legacygap-snp-24vcpu.igvm` | `4b62553755ffeeff31af37d00db4559646cd3f0e0c3ddda991c889a015832e85` | same patched ROM, 24 VP contexts |

Why two ROMs: the released stage0 leaves the legacy range `0xA0000-0xEFFFF` unvalidated, and every stock distribution
kernel with `CONFIG_ISCSI_IBFT_FIND=y` scans it at boot and dies with `Unsupported exit-code 0x404 in early #VC
exception` (https://github.com/project-oak/oak/issues/5205). The `legacygap` builds validate `0xC0000-0xFFFFF`, which
is what lets the distribution kernels in `tests/vectors.json` boot and produce a report. Only the ROM pages differ,
so the two variants share the IGVM structure: 1 platform header (SEV-SNP), `GUEST_POLICY` 0x30000, 163 `PAGE_DATA`
directives, N `VP_CONTEXT`.

Neither ROM is built with stage0's `sev_kernel_hashes` feature: the kernel hashes page is **measured but not
enforced** (see the main README, "What the measurement proves").

Verify: `shasum -a 256 -c SHA256SUMS`.
