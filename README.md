# holy-hv

holy-hv is a Windows Hyper-V research project that experiments with a custom
EFI-side hypervisor hook, a small kernel probe driver, and a user-mode control
tool for observing VM-exit state and testing memory translation behavior in a
local lab environment.

The project is focused on learning how the Windows boot chain, Hyper-V,
VM-exit handling, guest page tables, host page tables, EPT translation, and
kernel/user communication fit together.

## Project Status

This is an experimental research build. It is not production software, and it
should only be used in an isolated test machine or VM where crashes, boot
failures, and manual recovery are acceptable.

The active build marker is tracked in:

```text
HolyHypervisor/projects/HolyHypervisor/BuildMode.h
```

At the time this README was written, the active marker is:

```text
STAGE3_TEXT_PADDING_v53_HOOK_FN_VA
```

## Main Components

- `HolyHypervisor/`
  - EFI and Hyper-V hook research code.
  - Locates the target Hyper-V VM-exit path.
  - Copies the hook payload into controlled image padding.
  - Applies relocation and patch stages controlled by `BuildMode.h`.
  - Maintains a shared CPUID-based command protocol in `HolyProtocol.h`.

- `HolyHvProbe/`
  - Windows kernel probe driver.
  - Provides a stable device interface for user-mode tools.
  - Issues CPUID calls from kernel context when needed.
  - Includes helper logic for controlled process memory tests.

- `HolyHvProbe/holyctl.c`
  - User-mode command-line tool for diagnostics and testing.
  - Talks to the Hyper-V hook through keyed CPUID commands.
  - Provides commands for hook liveness checks, VM-exit counters, host state
    inspection, scratch-page inspection, page-table walking, EPT translation,
    and guest memory read/write experiments.

- `HolyHvProbe/HolyCpuid.asm`
  - 64-bit CPUID wrapper used to preserve full register input/output across
    the command channel.

## Features

- CPUID-based command channel guarded by a project-specific key.
- VM-exit hook liveness checks with deterministic ping values.
- VM-exit count and last-exit diagnostics.
- Guest CR3 and VMCS host-state inspection helpers.
- Hyper-V image scratch-page reporting.
- Hyper-V virtual address read/write experiments.
- Safer page-table checked reads for mapped/unmapped memory testing.
- Hyper-V section listing and page probing.
- EPT information and address translation experiments.
- Guest virtual address translation through guest page tables plus EPT.
- Guest memory read/write tests for controlled local research.
- Batch read/copy helpers for faster diagnostic dumping.
- Driver-backed process memory read/write helpers for comparison testing.

## Build Notes

This project expects a Windows development environment with Visual Studio,
MSVC, MASM, the Windows Driver Kit, and the local EDK-II/VisualUefi project
layout used by this repository.

The probe driver and tools can be built from:

```text
HolyHvProbe/build.bat
```

The EFI/Hyper-V side can be built from:

```text
HolyHypervisor/build.bat
```

Build artifacts such as `.sys`, `.efi`, `.exe`, `.pdb`, and signing
certificates are intentionally excluded from source control.

## Authorship Note

The main function, project direction, and core implementation decisions were
written by me. I used a small amount of Cloud Code assistance only for
calculation-heavy parts, deeper implementation reasoning, code cleanup,
formatting, and adding comments. The main logic and final integration remain my
own work.

## Research Scope

This repository is for personal learning and controlled defensive research. It
is intended to help study low-level Windows internals, boot-time behavior,
Hyper-V VM-exit mechanics, page-table translation, and driver/tooling
integration.

Do not use this project on systems you do not own or administer.

## Credits

The original HolyHypervisor/SecureHack research tree references prior public
research projects and ideas, including Voyager, DmaBackdoorHv, and VisualUefi.
See `HolyHypervisor/README.md` for the original upstream-style notes and
credits retained in this repository.

## 네이밍

하이퍼바이져를 공부하면서 여러가지가 기독교 안에서 '예수'와 겹쳐보여 프로젝트 이름을 holy라고 지었습니다.
