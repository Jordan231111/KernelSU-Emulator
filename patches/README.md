# Compatibility patches

The three kernel patches below modify GPL-2.0-only code. The NeoZygisk patch
retains its upstream GPL-3.0 license; the r2frida correction is MIT-licensed.
Upstream copyright notices remain applicable.

| Patch | Target | Purpose |
| --- | --- | --- |
| `mumu-task-layout.patch` | Android common `f931d3c324845b1be4337d27b565351fb581f206` | Match MuMu's measured task layout |
| `kernelsu-next-mumu.patch` | KernelSU Next legacy `e5f5ec998de88b9fc43c62cff8f7ae12d3f4800a` | Adapt root hooks, credentials, UAPI 5 and loading to MuMu |
| `susfs-lkm-mumu.patch` | SUSFS LKM main `761b93083afd846858257221453bf306465042a3` | Adapt 4.19 prototypes, symbol/layout resolution, filesystem hooks and locking |
| `neozygisk-frida-compat.patch` | NeoZygisk `cc0bbba7c2e0215b0f3fe1fb27e2ee88ade9e688` | Preserve unrelated mutable mappings, executable replacement permissions and reused source mappings; include the regression fixture |
| `r2frida-6.2.6-info.patch` | r2frida `6f9091ebe9273a85c42e37245be8b50cdce6008d` | Emit separate module-base and JNI-environment flags on Android |

The build uses these exact revisions, the profile's configuration, and zero-fuzz patch application. SUSFS files listed in its profile are normalized to LF before patching. Recheck ABI assumptions before applying the patches to another kernel.
