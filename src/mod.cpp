#include "patch.h"

#include <Windows.h>

#include <cstdio>
#include <filesystem>
#include <string>

namespace
{
    std::filesystem::path OwnDirectory()
    {
        HMODULE self = nullptr;
        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           reinterpret_cast<LPCWSTR>(&OwnDirectory), &self);
        wchar_t buffer[MAX_PATH] = {};
        GetModuleFileNameW(self, buffer, MAX_PATH);
        return std::filesystem::path(buffer).parent_path();
    }

    void Run()
    {
        FILE* log = nullptr;
        _wfopen_s(&log, (OwnDirectory() / L"ManualReload.log").c_str(), L"w");
        auto write = [log](const std::string& line) {
            if (log) std::fprintf(log, "%s\n", line.c_str());
        };

        auto* image = reinterpret_cast<uint8_t*>(GetModuleHandleW(nullptr));
        const manual_reload::ScanResult result = manual_reload::Scan(image);

        char header[160];
        std::snprintf(header, sizeof(header), "exe PE timestamp 0x%08X, matches %d, status %s", result.peTimestamp,
                      result.matchCount, manual_reload::StatusName(result.status));
        write(header);
        if (!result.detail.empty()) write("detail: " + result.detail);

        if (result.status == manual_reload::ScanStatus::ReadyToPatch)
        {
            char targets[160];
            std::snprintf(targets, sizeof(targets), "branch at rva 0x%X: reload 0x%X -> dry fire 0x%X", result.matchRva,
                          result.reloadTargetRva, result.dryFireTargetRva);
            write(targets);
            std::string error;
            write(manual_reload::Apply(image, result, error) ? "patched: empty magazine now dry-fires"
                                                             : "not patched: " + error);
        }
        else if (result.status != manual_reload::ScanStatus::AlreadyPatched)
        {
            write("not patched: vanilla auto-reload stays active");
        }

        if (log) std::fclose(log);
    }
}

// UE4SS entry point (Mods/ManualReload/dlls/main.dll). UE4SS refuses a C++ mod without both
// lifecycle exports. A null mod object counts as "not started" and UE4SS skips every later
// callback, so the mod needs no UE4SS headers.
extern "C" __declspec(dllexport) void* start_mod()
{
    Run();
    return nullptr;
}

// Ultimate ASI Loader entry point (same file renamed to ManualReload.asi), called outside the
// loader lock right after LoadLibrary.
extern "C" __declspec(dllexport) void InitializeASI()
{
    Run();
}

extern "C" __declspec(dllexport) void uninstall_mod(void*)
{
}
