# agent.md — kernel_xiaomi_sm8250 (alioth)

msm-4.19 based Android kernel. Version 4.19.325. Device alioth (POCO F3), SoC kona / sm8250. Branch `aosp-16`, remote `PocoF3Releases/kernel_xiaomi_sm8250`.

## Key files
- Defconfig: `arch/arm64/configs/alioth_defconfig` (`CONFIG_ARCH_KONA=y`, `CONFIG_LOCALVERSION="-Neko"`, `CONFIG_KSU=y`, `CONFIG_KSU_SUSFS` unset — SUSFS needs fs/ patches this tree doesn't carry)
- Build entry: `build.config.xiaomi.alioth` → inherits `build.config.xiaomi.sm8250` → ACK `build.config.common` / `build.config.aarch64` (clang, `BUILD_CONFIG` style, not plain `make`)
- Outputs: `arch/arm64/boot/Image`, `arch/arm64/boot/dts/vendor/qcom/*.dtb`, `arch/arm64/boot/dtbo.img`
- Device DTS: `arch/arm64/boot/dts/vendor/qcom/alioth-sm8250*.dts(i)`
- Out-of-tree SoC bits: `techpack/` (audio, camera, display, video, data)
- SukiSU-Ultra (manual hooks, `builtin` branch @ b20dee7): source `SukiSU-Ultra/`, wired via symlink `drivers/kernelsu`; hooks in `fs/exec.c` (`do_execveat_common`), `fs/open.c` (`do_faccessat`), `fs/read_write.c` (`vfs_read`), `fs/stat.c` (newfstatat/fstatat64/compat sucompat + newfstat/fstat64 `ksu_handle_vfs_fstat`), `kernel/reboot.c`, `drivers/input/input.c` (`input_event`). All under `#ifdef CONFIG_KSU`, no KPROBES needed. Carries `sukisu-builtin-fixes.patch` (applied in CI) for upstream 4.19/non-SUSFS build breaks; refresh on submodule bump.

## Rules for agents
- Do NOT build or test locally in this checkout (user constraint). Edit + static inspection only.
- Prefer `read`/`grep`/`glob` over `shell`. Never run `make`, `build/build.sh`, or defconfig builds here.
- Trace callers before fixing a bug; fix once at the shared choke point, not per-caller.
- Keep diffs minimal: no reformats, no speculative cleanups, no new Kconfig options unless asked.
- Match existing driver style (this tree predates latest checkpatch; don't reformat whole files).
- DTS changes: touch only the `alioth-*` overlays unless the bug is clearly in shared `kona-*`.
- Defconfig changes: one `CONFIG_*` line per change, keep alphabetical/context position.
