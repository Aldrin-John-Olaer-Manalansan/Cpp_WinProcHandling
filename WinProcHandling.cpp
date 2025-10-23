/*
 * @File: WinProcHandling.cpp
 * @Author: Aldrin John O. Manalansan (ajom)
 * @Email: aldrinjohnolaermanalansan@gmail.com
 * @Brief: Library for manipulating memory of windows processes
 * @LastUpdate: October 20, 2025
 *
 * Copyright (C) 2025  Aldrin John O. Manalansan  <aldrinjohnolaermanalansan@gmail.com>
 * 
 * This Source Code is served under Open-Source AJOM License
 * You should have received a copy of License_OS-AJOM
 * along with this source code. If not, see:
 * <https://raw.githubusercontent.com/Aldrin-John-Olaer-Manalansan/AJOM_License/refs/heads/main/LICENSE_AJOM-OS>
 */

#include "WinProcHandling.hpp"

#include <psapi.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <functional>

namespace WinProcHandling {
    DWORD FindProcessId(const char* processName) {
        PROCESSENTRY32 pe{};
        pe.dwSize = sizeof(pe);
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return 0;
        if (Process32First(snap, &pe)) {
            do {
                if (_stricmp(pe.szExeFile, processName) == 0) {
                    DWORD pid = pe.th32ProcessID;
                    CloseHandle(snap);
                    return pid;
                }
            } while (Process32Next(snap, &pe));
        }
        CloseHandle(snap);
        return 0;
    }

    // uintptr_t GetModuleBase(DWORD pid, const char* moduleName) {
    //     MODULEENTRY32 me{};
    //     me.dwSize = sizeof(me);
    //     HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    //     if (snap == INVALID_HANDLE_VALUE) return 0;
    //     uintptr_t base = 0;
    //     if (Module32First(snap, &me)) {
    //         do {
    //             if (_stricmp(me.szModule, moduleName) == 0) {
    //                 base = reinterpret_cast<uintptr_t>(me.modBaseAddr);
    //                 break;
    //             }
    //         } while (Module32Next(snap, &me));
    //     }
    //     CloseHandle(snap);
    //     return base;
    // }

    DWORD GetModuleBase(HANDLE hProcess, uintptr_t *const outBase) {
        MODULEINFO mi;
        HMODULE hMod = nullptr;

        // Local process fast path
        if (GetCurrentProcessId() == GetProcessId(hProcess)) {
            hMod = GetModuleHandleA(NULL); // main module of current process
            if (!hMod) return 0;
            if (!GetModuleInformation(hProcess, hMod, &mi, sizeof(mi))) return 0;
            if (outBase) *outBase = reinterpret_cast<uintptr_t>(mi.lpBaseOfDll);
            return mi.SizeOfImage;
        }

        // Remote process: enumerate modules (requires PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)
        HMODULE modules[1024];
        DWORD cbNeeded = 0;
        if (!EnumProcessModulesEx(hProcess, modules, sizeof(modules), &cbNeeded, LIST_MODULES_ALL)) {
            return 0;
        }
        if (cbNeeded == 0) return 0;
        // first returned module is usually the main module
        hMod = modules[0];
        if (!GetModuleInformation(hProcess, hMod, &mi, sizeof(mi))) return 0;
        if (outBase) *outBase = reinterpret_cast<uintptr_t>(mi.lpBaseOfDll);
        return mi.SizeOfImage;
    }

    DWORD GetModuleBase(DWORD pid, const char* moduleName, uintptr_t *const outBase) {
        MODULEENTRY32 me{};
        me.dwSize = sizeof(me);
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (snap == INVALID_HANDLE_VALUE) return 0;
        if (Module32First(snap, &me)) {
            do {
                if (_stricmp(me.szModule, moduleName) == 0) {
                    if (outBase) *outBase = reinterpret_cast<uintptr_t>(me.modBaseAddr);
                    CloseHandle(snap);
                    return me.modBaseSize;
                }
            } while (Module32Next(snap, &me));
        }
        CloseHandle(snap);
        return 0;
    }

    static bool IsReadableProtection(DWORD prot) {
        if (prot & PAGE_GUARD) return false;
        if (prot & PAGE_NOACCESS) return false;
        if (prot & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                    PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
            return true;
        return false;
    }


/**
 * @brief Scans a process' memory in chunks and calls a callback for each byte
 * @param processInfo Information about the process to scan
 * @param callbackData Data to pass to the callback function
 * @param callback Function to call for each byte in the process' memory
 * @return void
 *
 * This function will scan the memory of the process specified by processInfo in chunks
 * of at most 64KB at a time. For each byte in the process' memory, it will call the
 * callback function and pass the callbackData and the byteIndex and the byte itself.
 * If the callback function returns true, this function will stop iterating and return.
 * If ReadProcessMemory fails for a given chunk, this function will silently skip that chunk
 * and continue to the next region.
 * The callback function is called for each byte in the process' memory that is readable.
 * The callback controls the iteration. If the callback returns true, this function will stop iterating
 */

    void ForEachScanProcess(
        t_ProcessInfo* const processInfo,
        void* const callbackData, bool(*callback)(void* callbackData, size_t byteIndex, uint8_t& byte)
    ) {
        std::vector<uint8_t> buffer;
        SYSTEM_INFO si;
        GetSystemInfo(&si);

        const SIZE_T chunk = 64 * 1024; // 64KB
        uintptr_t seeker = processInfo->moduleBase + processInfo->searchedOffsetFromBase;
        uintptr_t end = std::min(seeker + processInfo->searchSize, processInfo->moduleBase + processInfo->moduleSize);

        while (seeker < end) {
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQueryEx(processInfo->handle, reinterpret_cast<LPCVOID>(seeker), &mbi, sizeof(mbi)) == 0) break;

            uintptr_t regionBase = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
            uintptr_t regionEnd = regionBase + mbi.RegionSize;

            // Clamp region to module's requested range
            if (regionEnd <= processInfo->moduleBase) { seeker = regionEnd; continue; }
            if (regionBase < processInfo->moduleBase) regionBase = processInfo->moduleBase;
            if (regionEnd > end) regionEnd = end;

            if (mbi.State == MEM_COMMIT && IsReadableProtection(mbi.Protect)) {
                SIZE_T offset = 0;
                SIZE_T regionSize = regionEnd - regionBase;
                while (offset < regionSize) {
                    SIZE_T toRead = regionSize - offset;
                    if (toRead > chunk) toRead = chunk;

                    buffer.resize(toRead);
                    SIZE_T actuallyRead = 0;
                    if (ReadProcessMemory(processInfo->handle,
                                          reinterpret_cast<LPCVOID>(regionBase + offset),
                                          buffer.data(),
                                          toRead,
                                          &actuallyRead) && actuallyRead > 0) {
                        for(size_t i = 0; i < actuallyRead; i++) {
                            if (callback(callbackData, regionBase - processInfo->moduleBase + offset + i, buffer[i])) {
                                return; // callback says we're done iterating
                            }
                        }
                    }
                    // if ReadProcessMemory fails, skip that chunk silently
                    offset += toRead;
                }
            }

            // Next region (avoid infinite loop)
            seeker = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        }
    }

    bool PatchMemory(HANDLE ph, LPVOID target, LPCVOID patchBytes, const SIZE_T patchSize) {
        // Read original bytes and save backup
        // std::vector<BYTE> orig(patchSize);
        // SIZE_T bytesRead = 0;
        // if (!ReadProcessMemory(ph, target, orig.data(), patchSize, &bytesRead) || bytesRead != patchSize) {
        //     std::cerr << "ReadProcessMemory failed. Error: " << GetLastError() << "\n";
        //     return false;
        // }
        // Save backup file
        // {
        //     std::ofstream out("orig_bytes.bin", std::ios::binary);
        //     if (out) out.write(reinterpret_cast<const char*>(orig.data()), orig.size());
        // }
        // std::cout << "Original bytes saved to orig_bytes.bin\n";

        DWORD oldProtect = 0;
        if (!VirtualProtectEx(ph, target, patchSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            std::cerr << "VirtualProtectEx failed. Error: " << GetLastError() << "\n";
            return 1;
        }

        SIZE_T written = 0;
        if (!WriteProcessMemory(ph, target, patchBytes, patchSize, &written) || written != patchSize) {
            std::cerr << "WriteProcessMemory failed. Error: " << GetLastError() << "\n";
            // try restore protection
            VirtualProtectEx(ph, target, patchSize, oldProtect, &oldProtect);
            return 1;
        }

        // Ensure CPU sees the change
        if (!FlushInstructionCache(ph, target, patchSize)) {
            std::cerr << "FlushInstructionCache failed. Error: " << GetLastError() << "\n";
        }

        // restore original protection
        DWORD tmp;
        VirtualProtectEx(ph, target, patchSize, oldProtect, &tmp);
        
        return true;
    }


    bool FillWithNOPs(HANDLE ph, LPVOID target, const SIZE_T patchSize) {
        DWORD oldProtect = 0;
        if (!VirtualProtectEx(ph, target, patchSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            std::cerr << "VirtualProtectEx failed. Error: " << GetLastError() << "\n";
            return 1;
        }
        
        SIZE_T totalWritten = 0;
        for (uint8_t* address = static_cast<uint8_t*>(target); address < static_cast<uint8_t*>(target) + patchSize; address++) {
            const uint8_t nop = 0x90;
            SIZE_T written = 0;
            if (!WriteProcessMemory(ph, reinterpret_cast<LPVOID>(address), &nop, 1, &written)) {
                std::cerr << "WriteProcessMemory failed. Error: " << GetLastError() << "\n";
                // try restore protection
                VirtualProtectEx(ph, reinterpret_cast<LPVOID>(address), patchSize, oldProtect, &oldProtect);
                return 1;
            }
            totalWritten += written;
        }
        if (totalWritten != patchSize) {
            std::cerr << "totalWritten != patchSize\n";
            // try restore protection
            VirtualProtectEx(ph, target, patchSize, oldProtect, &oldProtect);
            return 1;
        }

        // Ensure CPU sees the change
        if (!FlushInstructionCache(ph, target, patchSize)) {
            std::cerr << "FlushInstructionCache failed. Error: " << GetLastError() << "\n";
        }

        // restore original protection
        DWORD tmp;
        VirtualProtectEx(ph, target, patchSize, oldProtect, &tmp);
        
        return true;
    }

    bool ReadMemory(HANDLE ph, LPVOID destination, LPCVOID target, const SIZE_T size) {
        SIZE_T bytesRead = 0;
        if (!ReadProcessMemory(ph, target, destination, size, &bytesRead) || bytesRead != size) {
            std::cerr << "ReadProcessMemory failed. Error: " << GetLastError() << "\n";
            return false;
        }
        return true;
    }
}