#pragma once

#include <cstdint>
#include <string>

namespace manual_reload
{
    enum class ScanStatus
    {
        ReadyToPatch,
        AlreadyPatched,
        NotFound,
        Ambiguous,
        ValidationFailed,
    };

    struct ScanResult
    {
        ScanStatus status = ScanStatus::NotFound;
        std::string detail;
        int matchCount = 0;
        uint32_t matchRva = 0;
        uint32_t reloadTargetRva = 0;
        uint32_t dryFireTargetRva = 0;
        uint32_t peTimestamp = 0;
    };

    // imageBase must point at a PE image laid out by section RVAs (as the loader maps it).
    ScanResult Scan(const uint8_t* imageBase);

    // Rewrites the NoAmmoLoaded branch to the NoAmmo (dry fire) target in the live process.
    bool Apply(uint8_t* imageBase, const ScanResult& result, std::string& error);

    const char* StatusName(ScanStatus status);
}
