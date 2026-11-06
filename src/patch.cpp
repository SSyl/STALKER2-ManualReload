#include "patch.h"

#include <Windows.h>

#include <cstdio>
#include <cstring>

namespace manual_reload
{
    namespace
    {
        // The fire handler branches on the native EShootingAvailability getter's result:
        //   cmp eax, 3 (NoAmmoLoaded) ; je <reload block>
        //   cmp eax, 4 (NoAmmo)       ; je <dry fire>
        //   cmp byte [reg+disp32], 5  (Jammed)
        // Jump targets, the jam-check offset and its base register are wildcarded so a
        // recompile that only moves code or struct fields still matches.
        constexpr size_t kPatternSize = 25;
        constexpr size_t kReloadRel = 5;
        constexpr size_t kReloadNext = 9;
        constexpr size_t kDryFireRel = 14;
        constexpr size_t kDryFireNext = 18;

        bool MatchesAt(const uint8_t* p)
        {
            static constexpr uint8_t head[] = {0x83, 0xF8, 0x03, 0x0F, 0x84};
            static constexpr uint8_t mid[] = {0x83, 0xF8, 0x04, 0x0F, 0x84};
            if (std::memcmp(p, head, sizeof(head)) != 0) return false;
            if (std::memcmp(p + kReloadNext, mid, sizeof(mid)) != 0) return false;
            if (p[18] != 0x80) return false;
            // ModRM for "cmp r/m8, imm8" with mod=10: 0xB8-0xBF. rm=100 needs a SIB byte, which
            // would shift the layout, so it is excluded.
            const uint8_t modrm = p[19];
            if (modrm < 0xB8 || modrm > 0xBF || modrm == 0xBC) return false;
            return p[24] == 0x05;
        }

        int32_t ReadRel32(const uint8_t* p)
        {
            int32_t value;
            std::memcpy(&value, p, sizeof(value));
            return value;
        }

        struct Pe
        {
            const IMAGE_NT_HEADERS64* nt = nullptr;
            const IMAGE_SECTION_HEADER* text = nullptr;
            const RUNTIME_FUNCTION* functions = nullptr;
            size_t functionCount = 0;
        };

        bool ParsePe(const uint8_t* base, Pe& pe, std::string& error)
        {
            auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            {
                error = "no MZ header";
                return false;
            }
            pe.nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
            if (pe.nt->Signature != IMAGE_NT_SIGNATURE || pe.nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            {
                error = "not a PE32+ image";
                return false;
            }
            auto sections = IMAGE_FIRST_SECTION(pe.nt);
            for (WORD i = 0; i < pe.nt->FileHeader.NumberOfSections; ++i)
            {
                if (std::memcmp(sections[i].Name, ".text", 6) == 0)
                {
                    pe.text = &sections[i];
                    break;
                }
            }
            if (!pe.text)
            {
                error = "no .text section";
                return false;
            }
            const auto& exceptionDir = pe.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
            pe.functions = reinterpret_cast<const RUNTIME_FUNCTION*>(base + exceptionDir.VirtualAddress);
            pe.functionCount = exceptionDir.Size / sizeof(RUNTIME_FUNCTION);
            if (pe.functionCount == 0)
            {
                error = "no exception directory";
                return false;
            }
            return true;
        }

        // .pdata is sorted by BeginAddress.
        const RUNTIME_FUNCTION* FunctionContaining(const Pe& pe, uint32_t rva)
        {
            size_t lo = 0;
            size_t hi = pe.functionCount;
            while (lo < hi)
            {
                const size_t mid = (lo + hi) / 2;
                if (pe.functions[mid].BeginAddress <= rva) lo = mid + 1;
                else hi = mid;
            }
            if (lo == 0) return nullptr;
            const RUNTIME_FUNCTION* candidate = &pe.functions[lo - 1];
            return rva < candidate->EndAddress ? candidate : nullptr;
        }

        std::string Hex(uint32_t value)
        {
            char buffer[16];
            std::snprintf(buffer, sizeof(buffer), "0x%X", value);
            return buffer;
        }
    }

    const char* StatusName(ScanStatus status)
    {
        switch (status)
        {
        case ScanStatus::ReadyToPatch: return "ReadyToPatch";
        case ScanStatus::AlreadyPatched: return "AlreadyPatched";
        case ScanStatus::NotFound: return "NotFound";
        case ScanStatus::Ambiguous: return "Ambiguous";
        case ScanStatus::ValidationFailed: return "ValidationFailed";
        }
        return "Unknown";
    }

    ScanResult Scan(const uint8_t* imageBase)
    {
        ScanResult result;
        Pe pe;
        if (!ParsePe(imageBase, pe, result.detail))
        {
            result.status = ScanStatus::ValidationFailed;
            return result;
        }
        result.peTimestamp = pe.nt->FileHeader.TimeDateStamp;

        const uint32_t textRva = pe.text->VirtualAddress;
        const uint32_t textSize = pe.text->Misc.VirtualSize;
        const uint8_t* text = imageBase + textRva;
        for (uint32_t offset = 0; offset + kPatternSize <= textSize; ++offset)
        {
            if (!MatchesAt(text + offset)) continue;
            ++result.matchCount;
            if (result.matchCount == 1) result.matchRva = textRva + offset;
        }
        if (result.matchCount == 0)
        {
            result.status = ScanStatus::NotFound;
            result.detail = "shooting-availability branch not found";
            return result;
        }
        if (result.matchCount > 1)
        {
            result.status = ScanStatus::Ambiguous;
            result.detail = std::to_string(result.matchCount) + " matches";
            return result;
        }

        const uint8_t* match = imageBase + result.matchRva;
        result.reloadTargetRva = result.matchRva + kReloadNext + ReadRel32(match + kReloadRel);
        result.dryFireTargetRva = result.matchRva + kDryFireNext + ReadRel32(match + kDryFireRel);

        // Targets outside the owning RUNTIME_FUNCTION mean an unknown code layout.
        const RUNTIME_FUNCTION* owner = FunctionContaining(pe, result.matchRva);
        if (!owner)
        {
            result.status = ScanStatus::ValidationFailed;
            result.detail = "match at " + Hex(result.matchRva) + " is not inside a known function";
            return result;
        }
        const auto inOwner = [owner](uint32_t rva) { return rva >= owner->BeginAddress && rva < owner->EndAddress; };
        if (!inOwner(result.reloadTargetRva) || !inOwner(result.dryFireTargetRva))
        {
            result.status = ScanStatus::ValidationFailed;
            result.detail = "branch targets " + Hex(result.reloadTargetRva) + " / " + Hex(result.dryFireTargetRva) +
                            " leave function " + Hex(owner->BeginAddress) + "-" + Hex(owner->EndAddress);
            return result;
        }

        result.status = result.reloadTargetRva == result.dryFireTargetRva ? ScanStatus::AlreadyPatched : ScanStatus::ReadyToPatch;
        return result;
    }

    bool Apply(uint8_t* imageBase, const ScanResult& result, std::string& error)
    {
        if (result.status != ScanStatus::ReadyToPatch)
        {
            error = std::string("scan status is ") + StatusName(result.status);
            return false;
        }

        uint8_t* relSite = imageBase + result.matchRva + kReloadRel;
        const int32_t expectedRel = static_cast<int32_t>(result.reloadTargetRva - (result.matchRva + kReloadNext));
        const int32_t newRel = static_cast<int32_t>(result.dryFireTargetRva - (result.matchRva + kReloadNext));

        DWORD oldProtect = 0;
        if (!VirtualProtect(relSite, sizeof(int32_t), PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            error = "VirtualProtect failed, error " + std::to_string(GetLastError());
            return false;
        }
        const bool unchanged = ReadRel32(relSite) == expectedRel;
        if (unchanged) std::memcpy(relSite, &newRel, sizeof(newRel));
        DWORD ignored = 0;
        VirtualProtect(relSite, sizeof(int32_t), oldProtect, &ignored);
        FlushInstructionCache(GetCurrentProcess(), relSite, sizeof(int32_t));

        if (!unchanged)
        {
            error = "branch bytes changed between scan and write";
            return false;
        }
        return true;
    }
}
