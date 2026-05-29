#pragma once

#define HOLY_BUILD_MARKER "STAGE3_TEXT_PADDING_v41_PROTOCOL_PING"

//
// hv.exe mutation stages. Each stage adds one more step to ProcessHvImage;
// everything below stays on. Bump one stage at a time when bisecting.
//
//   STAGE_NONE     - no mutation, allocation/backing diagnostics only
//   STAGE_COPYMEM  - + CopyMem payload into .text padding (hook NOT armed)
//   STAGE_RELOC    - + apply base relocations to the copy
//   STAGE_PATCH    - + set OriginalVmExitHandlerIntelAddr, patch VMEXIT CALL
//                    (first stage where the hook actually fires)
//
#define HOLY_HV_MUTATION_STAGE_NONE    0
#define HOLY_HV_MUTATION_STAGE_COPYMEM 1
#define HOLY_HV_MUTATION_STAGE_RELOC   2
#define HOLY_HV_MUTATION_STAGE_PATCH   3

#define HOLY_HV_MUTATION_STAGE HOLY_HV_MUTATION_STAGE_PATCH

// Back-compat for older guards.
#if HOLY_HV_MUTATION_STAGE > HOLY_HV_MUTATION_STAGE_NONE
#define HOLY_ALLOW_HV_IMAGE_MUTATION 1
#else
#define HOLY_ALLOW_HV_IMAGE_MUTATION 0
#endif
