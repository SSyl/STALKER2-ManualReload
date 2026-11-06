#include "patch.h"

#include <Windows.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <vector>

// Maps a PE file by section RVAs so Scan sees the same layout the loader produces.
static bool LoadImage(const wchar_t* path, std::vector<uint8_t>& image)
{
    std::ifstream file(path, std::ios::binary);
    if (!file) return false;
    std::vector<uint8_t> raw((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    if (raw.size() < sizeof(IMAGE_DOS_HEADER)) return false;

    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(raw.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(raw.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    image.assign(nt->OptionalHeader.SizeOfImage, 0);
    std::memcpy(image.data(), raw.data(), nt->OptionalHeader.SizeOfHeaders);
    auto sections = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i)
    {
        const auto& s = sections[i];
        const size_t size = (std::min)(static_cast<size_t>(s.SizeOfRawData), static_cast<size_t>(s.Misc.VirtualSize));
        if (s.PointerToRawData + size > raw.size() || s.VirtualAddress + size > image.size()) return false;
        std::memcpy(image.data() + s.VirtualAddress, raw.data() + s.PointerToRawData, size);
    }
    return true;
}

int wmain(int argc, wchar_t** argv)
{
    if (argc != 2)
    {
        std::fwprintf(stderr, L"usage: ManualReloadScan <Stalker2-Win64-Shipping.exe>\n");
        return 2;
    }
    std::vector<uint8_t> image;
    if (!LoadImage(argv[1], image))
    {
        std::fwprintf(stderr, L"could not read PE image: %s\n", argv[1]);
        return 2;
    }

    const manual_reload::ScanResult result = manual_reload::Scan(image.data());
    std::printf("PE timestamp 0x%08X\nmatches %d\nstatus %s\n", result.peTimestamp, result.matchCount,
                manual_reload::StatusName(result.status));
    if (!result.detail.empty()) std::printf("detail: %s\n", result.detail.c_str());
    if (result.matchCount == 1)
        std::printf("branch rva 0x%X\nreload target rva 0x%X\ndry fire target rva 0x%X\n", result.matchRva,
                    result.reloadTargetRva, result.dryFireTargetRva);
    return result.status == manual_reload::ScanStatus::ReadyToPatch ? 0 : 1;
}
