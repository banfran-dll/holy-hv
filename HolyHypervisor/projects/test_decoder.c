#include <stdio.h>
#include <string.h>

/* Exact copy of LightHook.h implementation (reverted to original + parentheses fix) */

static unsigned char PREFIXES[] = { 0xF0, 0xF2, 0xF3, 0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65, 0x66, 0x67 };
static unsigned char OP1_MODRM[] = { 0x62, 0x63, 0x69, 0x6B, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0xC0, 0xC1, 0xC4, 0xC5, 0xC6, 0xC7, 0xD0, 0xD1, 0xD2, 0xD3, 0xF6, 0xF7, 0xFE, 0xFF };
static unsigned char OP1_IMM8[] = { 0x04, 0x0C, 0x14, 0x1C, 0x24, 0x2C, 0x34, 0x3C, 0x6A, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xC0, 0xC1, 0xC6, 0xCD, 0xD4, 0xD5, 0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xEB, 0xF6, 0xF7 };
static unsigned char OP1_IMM32[] = { 0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D, 0x68, 0x69, 0x81, 0xA9, 0xC7, 0xE8, 0xE9 };
static unsigned char OP2_MODRM[] = { 0x00, 0x01, 0x02, 0x03, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x20, 0x21, 0x22, 0x23, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x38, 0x3A, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x7E, 0x7F, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F, 0xA3, 0xA4, 0xA5, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF, 0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE };

#define HOOK_R (*b >> 4)
#define HOOK_C (*b & 0xF)

static int FindByte(unsigned char* array, const unsigned long long size, const unsigned char byte)
{
    for (unsigned long long i = 0; i < size; i++)
        if (array[i] == byte)
            return 1;
    return 0;
}

static void ParseModRM(unsigned char** buffer, const int addressPrefix)
{
    const unsigned char modRm = *++ * buffer; /* pre-increment: skip opcode, read ModRM */

    if (!addressPrefix || (addressPrefix && **buffer >= 0x40))
    {
        int hasSib = 0;
        if (**buffer < 0xC0 && (**buffer & 0x7) == 0x4 && !addressPrefix)
            hasSib = 1, (*buffer)++;

        if (modRm >= 0x40 && modRm <= 0x7F)
            (*buffer)++;
        else if ((modRm <= 0x3F && (modRm & 0x7) == 0x5) || (modRm >= 0x80 && modRm <= 0xBF))
            *buffer += (addressPrefix) ? 2 : 4;
        else if (hasSib && (**buffer & 0x7) == 0x5)
            *buffer += (modRm & 0x40) ? 1 : 4;
    }
    else if (addressPrefix && **buffer == 0x26)
        *buffer += 2;
}

static int GetInstructionSize(const void* address)
{
    unsigned long long offset = 0;
    int operandPrefix = 0, addressPrefix = 0, rexW = 0;
    unsigned char* b = (unsigned char*)address;

    /* ONLY FIX: added parentheses around (FindByte(...) || HOOK_R == 4) */
    for (int i = 0; i < 14 && (FindByte(PREFIXES, sizeof(PREFIXES), *b) || HOOK_R == 4); i++, b++)
    {
        if (*b == 0x66)
            operandPrefix = 1;
        else if (*b == 0x67)
            addressPrefix = 1;
        else if (HOOK_R == 4 && HOOK_C >= 8)
            rexW = 1;
    }

    if (*b == 0x0F)
    {
        b++;
        if (*b == 0x38 || *b == 0x3A)
        {
            if (*b++ == 0x3A)
                offset++;

            ParseModRM(&b, addressPrefix);
        }
        else
        {
            if (HOOK_R == 8)
                offset += 4;
            else if ((HOOK_R == 7 && HOOK_C < 4) || *b == 0xA4 || *b == 0xC2 || (*b > 0xC3 && *b <= 0xC6) || *b == 0xBA || *b == 0xAC)
                offset++;

            if (FindByte(OP2_MODRM, sizeof(OP2_MODRM), *b) || (HOOK_R != 3 && HOOK_R > 0 && HOOK_R < 7) || *b >= 0xD0 || (HOOK_R == 7 && HOOK_C != 7) || HOOK_R == 9 || HOOK_R == 0xB || (HOOK_R == 0xC && HOOK_C < 8) || (HOOK_R == 0 && HOOK_C < 4))
                ParseModRM(&b, addressPrefix);
        }
    }
    else
    {
        if ((HOOK_R == 0xE && HOOK_C < 8) || (HOOK_R == 0xB && HOOK_C < 8) || HOOK_R == 7 || (HOOK_R < 4 && (HOOK_C == 4 || HOOK_C == 0xC)) || (*b == 0xF6 && !(*(b + 1) & 48)) || FindByte(OP1_IMM8, sizeof(OP1_IMM8), *b))
            offset++;
        else if (*b == 0xC2 || *b == 0xCA)
            offset += 2;
        else if (*b == 0xC8)
            offset += 3;
        else if ((HOOK_R < 4 && (HOOK_C == 5 || HOOK_C == 0xD)) || (HOOK_R == 0xB && HOOK_C >= 8) || (*b == 0xF7 && !(*(b + 1) & 48)) || FindByte(OP1_IMM32, sizeof(OP1_IMM32), *b))
        {
            if (*b == 0xB8 || (*b >= 0xB8 && *b <= 0xBF))
                offset += rexW ? 8 : 4;
            else if (*b == 0xC7)
                offset += 4;
            else if (*b == 0x69)
                offset += 4;
            else
                offset += (operandPrefix) ? 2 : 4;
        }
        else if (HOOK_R == 0xA && HOOK_C < 4)
            offset += (rexW) ? 8 : (addressPrefix ? 2 : 4);
        else if (*b == 0xEA || *b == 0x9A)
            offset += operandPrefix ? 4 : 6;

        if (FindByte(OP1_MODRM, sizeof(OP1_MODRM), *b) || (HOOK_R < 4 && (HOOK_C < 4 || (HOOK_C >= 8 && HOOK_C < 0xC))) || HOOK_R == 8 || (HOOK_R == 0xD && HOOK_C >= 8))
            ParseModRM(&b, addressPrefix);
    }

    return (int)(++b + offset - (unsigned char*)address);
}

/* Simulate CreateHook's loop */
static const unsigned char JUMP_CODE[] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

int main() {
    /* Actual bytes from BlMmAllocateVirtualPages on Win10 19041 */
    unsigned char bytes[] = { 0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x7C, 0x24, 0x10, 0x55, 0x48, 0x8D, 0x6C, 0x24, 0xA9,
                              0x48, 0x81, 0xEC, 0xB0, 0x00, 0x00, 0x00, 0x33, 0xFF };

    printf("=== Instruction decode test ===\n");
    int total = 0;
    int instNum = 0;
    while (total < 25) {
        int sz = GetInstructionSize(bytes + total);
        printf("Inst %d @ offset %d: size=%d  ", instNum, total, sz);
        for(int j=0; j<sz && total+j < 25; j++) printf("%02X ", bytes[total+j]);
        printf("\n");
        if (sz <= 0) { printf("DECODE FAILURE!\n"); break; }
        total += sz;
        instNum++;
    }

    printf("\n=== CreateHook simulation ===\n");
    printf("JUMP_CODE size = %d\n", (int)sizeof(JUMP_CODE));
    int size = 0;
    while (size < (int)sizeof(JUMP_CODE)) {
        int instSize = GetInstructionSize(bytes + size);
        printf("  size=%d + instSize=%d = %d\n", size, instSize, size + instSize);
        if (instSize == 0) { printf("  DECODE FAILURE at offset %d!\n", size); break; }
        size += instSize;
    }
    printf("Total bytes to copy for trampoline: %d (need >= %d)\n", size, (int)sizeof(JUMP_CODE));
    if (size >= (int)sizeof(JUMP_CODE))
        printf("SUCCESS: Hook would be installed\n");
    else
        printf("FAILURE: Not enough bytes decoded\n");

    return 0;
}
