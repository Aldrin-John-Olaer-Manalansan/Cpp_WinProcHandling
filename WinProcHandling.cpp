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
#include <cstring>

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

/**
 * @brief Fill a region of memory with NOPs (0x90) and
 * optionally change the protection to PAGE_EXECUTE_READWRITE
 * @param target Address of the region to fill with NOPs
 * @param patchSize Size of the region to fill with NOPs
 * @param virtualProtect If true, change protection of region to PAGE_EXECUTE_READWRITE
 * @return 1 if successful, -1 if failed
 * @throws std::runtime_error If VirtualProtectEx failed
 */
    int8_t FillWithNOPs(LPVOID target, const SIZE_T patchSize, const bool virtualProtect) {
        DWORD oldProtect = 0;
        if (virtualProtect && !VirtualProtect(target, patchSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            std::cerr << "VirtualProtectEx failed. Error: " << GetLastError() << "\n";
            return 0;
        }
        
        const std::vector<BYTE> nops(patchSize, 0x90); 
        std::memcpy(target, nops.data(), patchSize);

        // Ensure CPU sees the change
        int8_t result = FlushInstructionCache(GetCurrentProcess(), target, patchSize) ? 1 : -1;
        if (result == -1) {
            std::cerr << "FlushInstructionCache failed. Error: " << GetLastError() << "\n";
        }

        // restore original protection
        if (virtualProtect) {
            VirtualProtect(target, patchSize, oldProtect, &oldProtect);
        }

        return result;
    }

/**
 * @brief Fills a memory block at the process with NOPs (0x90)
 * @param processHandle Handle of the process to write to
 * @param target Address in the process to write to
 * @param patchSize Size of the patch to write
 * @return FlushInstructionCacheFailed = -1, WriteMemoryFailed = 0, Success = 1
 */
    int8_t FillWithNOPs(HANDLE processHandle, LPVOID target, const SIZE_T patchSize) {
        DWORD oldProtect = 0;
        if (!VirtualProtectEx(processHandle, target, patchSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            std::cerr << "VirtualProtectEx failed. Error: " << GetLastError() << "\n";
            return 0;
        }
        
        SIZE_T totalWritten = 0;
        const std::vector<BYTE> nops(patchSize, 0x90); 
        if (!WriteProcessMemory(processHandle, target, nops.data(), patchSize, &totalWritten)) {
            std::cerr << "WriteProcessMemory failed. Error: " << GetLastError() << "\n";
            // try restore protection
            VirtualProtectEx(processHandle, target, patchSize, oldProtect, &oldProtect);
            return 0;
        }
        if (totalWritten != patchSize) {
            std::cerr << "totalWritten != patchSize\n";
            // try restore protection
            VirtualProtectEx(processHandle, target, patchSize, oldProtect, &oldProtect);
            return 0;
        }

        // Ensure CPU sees the change
        int8_t result = FlushInstructionCache(processHandle, target, patchSize) ? 1 : -1;
        if (result == -1) {
            std::cerr << "FlushInstructionCache failed. Error: " << GetLastError() << "\n";
        }

        // restore original protection
        VirtualProtectEx(processHandle, target, patchSize, oldProtect, &oldProtect);
        
        return result;
    }

/**
 * @brief Locally writes the data from source with size, to the destination
 * @param destination address where to write to
 * @param source Address to where the data to write
 * @param size Size of the data to write
 * @return FlushInstructionCacheFailed = -1, WriteMemoryFailed = 0, Success = 1
 */
    int8_t WriteMemory(LPVOID destination, LPCVOID source, const SIZE_T size, const bool virtualProtect) {
        DWORD oldProtect = 0;
        if (virtualProtect && !VirtualProtect(destination, size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            std::cerr << "VirtualProtectEx failed. Error: " << GetLastError() << "\n";
            return 0;
        }

        std::memmove(destination, source, size);

        // Ensure CPU sees the change
        const int8_t result = FlushInstructionCache(GetCurrentProcess(), destination, size) ? 1 : -1; 
        if (result == -1) {
            std::cerr << "FlushInstructionCache failed. Error: " << GetLastError() << "\n";
        }

        if (virtualProtect) {
            // restore original protection
            VirtualProtect(destination, size, oldProtect, &oldProtect);
        }

        return result;
    }

/**
 * @brief Writes localSource to remoteDestination in processHandle
 * @param processHandle Handle of the process to write to
 * @param remoteDestination Address in the process to write to
 * @param localSource Address of the local data to write
 * @param size Size of the data to write
 * @return FlushInstructionCacheFailed = -1, WriteMemoryFailed = 0, Success = 1
 */
    int8_t WriteMemory(HANDLE processHandle, LPVOID remoteDestination, LPCVOID localSource, const SIZE_T size) {
        DWORD oldProtect = 0;
        if (!VirtualProtectEx(processHandle, remoteDestination, size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            std::cerr << "VirtualProtectEx failed. Error: " << GetLastError() << "\n";
            return 0;
        }

        SIZE_T written = 0;
        if (!WriteProcessMemory(processHandle, remoteDestination, localSource, size, &written) || written != size) {
            std::cerr << "WriteProcessMemory failed. Error: " << GetLastError() << "\n";
            // try restore protection
            VirtualProtectEx(processHandle, remoteDestination, size, oldProtect, &oldProtect);
            return 0;
        }

        // Ensure CPU sees the change
        const int8_t result = FlushInstructionCache(processHandle, remoteDestination, size) ? 1 : -1; 
        if (result == -1) {
            std::cerr << "FlushInstructionCache failed. Error: " << GetLastError() << "\n";
        }

        // restore original protection
        VirtualProtectEx(processHandle, remoteDestination, size, oldProtect, &oldProtect);
        
        return result;
    }

    bool ReadMemory(LPVOID destination, LPCVOID source, const SIZE_T size, const bool virtualProtect) {
        DWORD oldProtect = 0;
        if (virtualProtect &&!VirtualProtect(destination, size, PAGE_EXECUTE_READ, &oldProtect)) {
            return false; // VirtualProtectEx failed
        }

        std::memmove(destination, source, size);

        if (virtualProtect) {
            // restore original protection
            VirtualProtect(destination, size, oldProtect, &oldProtect);
        }

        return true;
    }

/**
 * @brief Reads remoteSource from processHandle into localDestination
 * @param processHandle Handle of the process to read from
 * @param localDestination Address of the local data to read into
 * @param remoteSource Address in the process to read from
 * @param size Size of the data to read
 * @return false if VirtualProtectEx failed or ReadProcessMemory failed, true if successful
 */
    bool ReadMemory(HANDLE processHandle, LPVOID localDestination, LPCVOID remoteSource, const SIZE_T size) {
        DWORD oldProtect = 0;
        if (!VirtualProtectEx(processHandle, localDestination, size, PAGE_EXECUTE_READ, &oldProtect)) {
            return false; // VirtualProtectEx failed
        }

        SIZE_T bytesRead = 0;
        if (!ReadProcessMemory(processHandle, remoteSource, localDestination, size, &bytesRead) || bytesRead != size) {
            return false; // ReadProcessMemory failed
        }

        // restore original protection
        VirtualProtectEx(processHandle, localDestination, size, oldProtect, &oldProtect);

        return true;
    }
}