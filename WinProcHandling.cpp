/*
 * @File: WinProcHandling.cpp
 * @Author: Aldrin John O. Manalansan (ajom)
 * @Email: aldrinjohnolaermanalansan@gmail.com
 * @Brief: Library for manipulating memory of windows processes
 * @LastUpdate: November 5, 2025
 *
 * Copyright (C) 2025  Aldrin John O. Manalansan  <aldrinjohnolaermanalansan@gmail.com>
 * 
 * This Source Code is served under Open-Source AJOM License
 * You should have received a copy of License_OS-AJOM
 * along with this source code. If not, see:
 * <https://raw.githubusercontent.com/Aldrin-John-Olaer-Manalansan/AJOM_License/refs/heads/main/LICENSE_AJOM-OS>
 */

#include "WinProcHandling.hpp"

#include <cstring>
#include <functional>
#include <iostream>
#include <psapi.h>
#include <tlhelp32.h>
#include <vector>

namespace WinProcHandling {
    struct PageProtectEntry {
        LPVOID base;
        SIZE_T size;
        DWORD oldProtect;
    };

    constexpr DWORD c_WritableFlags = PAGE_READWRITE | PAGE_EXECUTE_READWRITE;
    constexpr DWORD c_ReadableFlags = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    
/**
 * @brief Restore the original page protection for a range of entries in the given vector.
 * @param entries The vector of PageProtectEntry to restore the original protection.
 * @param startIndex The starting index of the range to restore (inclusive). Default is 0.
 * @details This function will restore the original page protection in reverse order (not strictly required but logical)
 * and erase the restored entries from the vector.
 * @note The function does not check if the restoration was successful or not. It is assumed that the restoration will always succeed.
 */
    static void RestorePageProtections(std::vector<PageProtectEntry>& entries, const size_t startIndex = 0) {
        // Restore in reverse order (not strictly required but logical)
        for (size_t i = entries.size(); i-- >= startIndex + 1;) {
            auto &entry = entries[i];
            DWORD tmp;
            VirtualProtect(entry.base, entry.size, entry.oldProtect, &tmp);
        }
        entries.erase(entries.begin() + startIndex, entries.end());
    }

/**
 * @brief Restore the original page protection for a range of entries in the given vector for a specific process handle.
 * @param processHandle The handle of the process to restore the page protection.
 * @param entries The vector of PageProtectEntry to restore the original protection.
 * @param startIndex The starting index of the range to restore (inclusive). Default is 0.
 * @details This function will restore the original page protection in reverse order (not strictly required but logical)
 * and erase the restored entries from the vector.
 * @note The function does not check if the restoration was successful or not. It is assumed that the restoration will always succeed.
 */
    static void RestorePageProtections(HANDLE processHandle, std::vector<PageProtectEntry>& entries, const size_t startIndex = 0) {
        // Restore in reverse order (not strictly required but logical)
        for (size_t i = entries.size(); i-- >= startIndex + 1;) {
            auto &entry = entries[i];
            DWORD tmp;
            VirtualProtectEx(processHandle, entry.base, entry.size, entry.oldProtect, &tmp);
        }
        entries.erase(entries.begin() + startIndex, entries.end());
    }

/**
 * @brief Make a memory block writable by patching the virtual protection of the pages.
 *
 * This function takes a region of memory and makes it writable by patching the virtual protection of the pages.
 * The function is useful for making memory dumps of processes that use copy-on-write memory management techniques.
 *
 * @param address Address of the memory region to make writable.
 * @param size Size of the memory region to make writable.
 * @param out Vector to store the patched page protection information.
 * @return True if the operation was successful, false otherwise.
 */
    static bool MakeAddressWritable(
        const LPVOID address, const SIZE_T size,
        std::vector<PageProtectEntry>& out
    ) {
        const auto& patchedEntryStart = out.size();
        uintptr_t seeker = reinterpret_cast<uintptr_t>(address);
        const uintptr_t end  = seeker + size;
        while (seeker < end) {
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(reinterpret_cast<LPCVOID>(seeker), &mbi, sizeof(mbi)) == 0) {
                RestorePageProtections(out, patchedEntryStart);
                return false; // failed to get memory info
            }

            const uintptr_t regionStart = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
            const uintptr_t  regionEnd   = regionStart + mbi.RegionSize;

            // clamp to our [start,end)
            const uintptr_t patchStart = std::max(regionStart, reinterpret_cast<uintptr_t>(address));
            const uintptr_t patchEnd   = std::min(regionEnd, end);

            if (patchStart < patchEnd) { // region is in bounds
                if ((mbi.State != MEM_COMMIT) // region does not allow commit operations
                || (mbi.Protect & PAGE_GUARD)) { // region has PAGE_GUARD protection
                    RestorePageProtections(out, patchedEntryStart);
                    return false; // a region cannot be read, therefore cancel the operation
                }

                if ((mbi.Protect & c_WritableFlags) == 0) { // region isn't writable yet
                    DWORD oldProtect = 0;
                    SIZE_T regionSizeForProtect = patchEnd - patchStart;
                    if (!VirtualProtect(
                        reinterpret_cast<LPVOID>(patchStart), regionSizeForProtect,
                        (mbi.Protect & PAGE_EXECUTE) ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE, 
                        &oldProtect))
                    {
                        RestorePageProtections(out, patchedEntryStart);
                        return false; // report failure
                    }
                    out.push_back({ reinterpret_cast<LPVOID>(patchStart), regionSizeForProtect, oldProtect });
                }
            }

            seeker = regionEnd;
        }

        return true;
    }

/**
 * @brief Make a memory block found inside a remote process writable by patching the virtual protection of the pages.
 *
 * This function takes a region of memory and makes it writable by patching the virtual protection of the pages.
 * The function is useful for making memory dumps of processes that use copy-on-write memory management techniques.
 *
 * @param processHandle The handle of the process that owns the memory to make writable.
 * @param address The address of the memory region to make writable.
 * @param size The size of the memory region to make writable.
 * @param out Vector to store the patched page protection information.
 * @return True if the operation was successful, false otherwise.
 */
    static bool MakeAddressWritable(
        HANDLE processHandle, const LPVOID address, const SIZE_T size,
        std::vector<PageProtectEntry>& out
    ) {
        const auto& patchedEntryStart = out.size();
        uintptr_t seeker = reinterpret_cast<uintptr_t>(address);
        const uintptr_t end  = seeker + size;
        while (seeker < end) {
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQueryEx(processHandle, reinterpret_cast<LPCVOID>(seeker), &mbi, sizeof(mbi)) == 0) {
                RestorePageProtections(processHandle, out, patchedEntryStart);
                return false; // failed to get memory info
            }

            const uintptr_t regionStart = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
            const uintptr_t  regionEnd   = regionStart + mbi.RegionSize;

            // clamp to our [start,end)
            const uintptr_t patchStart = std::max(regionStart, reinterpret_cast<uintptr_t>(address));
            const uintptr_t patchEnd   = std::min(regionEnd, end);

            if (patchStart < patchEnd) { // region is in bounds
                if ((mbi.State != MEM_COMMIT) // region does not allow commit operations
                || (mbi.Protect & PAGE_GUARD)) { // region has PAGE_GUARD protection
                    RestorePageProtections(processHandle, out, patchedEntryStart);
                    return false; // a region cannot be read, therefore cancel the operation
                }

                if ((mbi.Protect & c_WritableFlags) == 0) { // region isn't writable yet
                    DWORD oldProtect = 0;
                    SIZE_T regionSizeForProtect = patchEnd - patchStart;
                    if (!VirtualProtectEx(
                        processHandle, reinterpret_cast<LPVOID>(patchStart), regionSizeForProtect,
                        (mbi.Protect & PAGE_EXECUTE) ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE, 
                        &oldProtect))
                    {
                        RestorePageProtections(processHandle, out, patchedEntryStart);
                        return false; // report failure
                    }
                    out.push_back({ reinterpret_cast<LPVOID>(patchStart), regionSizeForProtect, oldProtect });
                }
            }

            seeker = regionEnd;
        }

        return true;
    }

/**
 * @brief Make a region of memory readable.
 * @details This function makes a region of memory readable by changing the protection flags of the memory region.
 *          It iterates over all the memory regions in the given range and, if the region is not readable, it changes the protection flags
 *          to make it readable. It records the original protection flags of the regions in the given out vector so that they can be restored later.
 * @param address The start address of the memory region to make readable.
 * @param size The size of the memory region to make readable.
 * @param out A vector to store the original protection flags of the regions that were made readable.
 * @return true on success, false on failure.
 */
    static bool MakeAddressReadable(
        const LPVOID address, const SIZE_T size,
        std::vector<PageProtectEntry>& out
    ) {
        const auto& patchedEntryStart = out.size();
        uintptr_t seeker = reinterpret_cast<uintptr_t>(address);
        const uintptr_t end  = seeker + size;
        while (seeker < end) {
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(reinterpret_cast<LPCVOID>(seeker), &mbi, sizeof(mbi)) == 0) {
                RestorePageProtections(out, patchedEntryStart);
                return false; // failed to get memory info
            }

            const uintptr_t regionStart = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
            const uintptr_t  regionEnd   = regionStart + mbi.RegionSize;

            // clamp to our [start,end)
            const uintptr_t patchStart = std::max(regionStart, reinterpret_cast<uintptr_t>(address));
            const uintptr_t patchEnd   = std::min(regionEnd, end);

            if (patchStart < patchEnd) { // not out of bounds
                if ((mbi.State != MEM_COMMIT) // region does not allow commit operations
                || (mbi.Protect & PAGE_GUARD)) { // region has PAGE_GUARD protection
                    RestorePageProtections(out, patchedEntryStart);
                    return false; // a region cannot be read, therefore cancel the operation
                }

                if ((mbi.Protect & c_ReadableFlags) == 0) { // region isn't readable yet
                    DWORD oldProtect = 0;
                    SIZE_T regionSizeForProtect = patchEnd - patchStart;
                    if (!VirtualProtect(
                        reinterpret_cast<LPVOID>(patchStart), regionSizeForProtect,
                        (mbi.Protect & PAGE_EXECUTE) ? PAGE_EXECUTE_READ : PAGE_READONLY, 
                        &oldProtect))
                    {
                        RestorePageProtections(out, patchedEntryStart);
                        return false; // report failure
                    }
                    out.push_back({ reinterpret_cast<LPVOID>(patchStart), regionSizeForProtect, oldProtect });
                }
            }

            seeker = regionEnd;
        }

        return true;
    }

/**
 * @brief Make a region of memory inside a remote process readable.
 * @details This function makes a region of memory inside a remote process readable by changing the protection flags of the memory region.
 *          It iterates over all the memory regions in the given range and, if the region is not readable, it changes the protection flags
 *          to make it readable. It records the original protection flags of the regions in the given out vector so that they can be restored later.
 * @param processHandle The handle of the process that owns the memory to make readable.
 * @param address The start address of the memory region to make readable.
 * @param size The size of the memory region to make readable.
 * @param out A vector to store the original protection flags of the regions that were made readable.
 * @return true on success, false on failure.
 */
    static bool MakeAddressReadable(
        HANDLE processHandle, const LPVOID address, const SIZE_T size,
        std::vector<PageProtectEntry>& out
    ) {
        const auto& patchedEntryStart = out.size();
        uintptr_t seeker = reinterpret_cast<uintptr_t>(address);
        const uintptr_t end  = seeker + size;
        while (seeker < end) {
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQueryEx(processHandle, reinterpret_cast<LPCVOID>(seeker), &mbi, sizeof(mbi)) == 0) {
                RestorePageProtections(processHandle, out, patchedEntryStart);
                return false; // failed to get memory info
            }

            const uintptr_t regionStart = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
            const uintptr_t  regionEnd   = regionStart + mbi.RegionSize;

            // clamp to our [start,end)
            const uintptr_t patchStart = std::max(regionStart, reinterpret_cast<uintptr_t>(address));
            const uintptr_t patchEnd   = std::min(regionEnd, end);

            if (patchStart < patchEnd) { // not out of bounds
                if ((mbi.State != MEM_COMMIT) // region does not allow commit operations
                || (mbi.Protect & PAGE_GUARD)) { // region has PAGE_GUARD protection
                    RestorePageProtections(processHandle, out, patchedEntryStart);
                    return false; // a region cannot be read, therefore cancel the operation
                }

                if ((mbi.Protect & c_ReadableFlags) == 0) { // region isn't readable yet
                    DWORD oldProtect = 0;
                    SIZE_T regionSizeForProtect = patchEnd - patchStart;
                    if (!VirtualProtectEx(
                        processHandle, reinterpret_cast<LPVOID>(patchStart), regionSizeForProtect,
                        (mbi.Protect & PAGE_EXECUTE) ? PAGE_EXECUTE_READ : PAGE_READONLY, 
                        &oldProtect))
                    {
                        RestorePageProtections(processHandle, out, patchedEntryStart);
                        return false; // report failure
                    }
                    out.push_back({ reinterpret_cast<LPVOID>(patchStart), regionSizeForProtect, oldProtect });
                }
            }

            seeker = regionEnd;
        }

        return true;
    }

/**
 * @brief Find the process ID of a process given its name.
 * @param processName The name of the process to find.
 * @return The process ID of the found process, or 0 if the process is not found.
 * @details This function takes a snapshot of all running processes, then iterates through the processes until it finds one with the given name. If the process is found, its process ID is returned. Otherwise, 0 is returned.
 */
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

/**
 * @brief Retrieves the base address of a module in a process.
 * @param processHandle The handle of the process that owns the module.
 * @param outBase A pointer to store the base address of the module.
 * @return The size of the module's image in memory, or 0 on failure.
 * @details This function retrieves the base address of a module in a process. For local processes, it takes a fast path using GetModuleHandleA and GetModuleInformation. For remote processes, it enumerates the modules using EnumProcessModulesEx and then uses GetModuleInformation to retrieve the base address of the first module (which is usually the main module).
 */
    DWORD GetModuleBase(HANDLE processHandle, uintptr_t *const outBase) {
        MODULEINFO mi;
        HMODULE hMod = nullptr;

        // Local process fast path
        if (GetCurrentProcessId() == GetProcessId(processHandle)) {
            hMod = GetModuleHandleA(NULL); // main module of current process
            if (!hMod) return 0;
            if (!GetModuleInformation(processHandle, hMod, &mi, sizeof(mi))) return 0;
            if (outBase) *outBase = reinterpret_cast<uintptr_t>(mi.lpBaseOfDll);
            return mi.SizeOfImage;
        }

        // Remote process: enumerate modules (requires PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)
        HMODULE modules[1024];
        DWORD cbNeeded = 0;
        if (!EnumProcessModulesEx(processHandle, modules, sizeof(modules), &cbNeeded, LIST_MODULES_ALL)) {
            return 0;
        }
        if (cbNeeded == 0) return 0;
        // first returned module is usually the main module
        hMod = modules[0];
        if (!GetModuleInformation(processHandle, hMod, &mi, sizeof(mi))) return 0;
        if (outBase) *outBase = reinterpret_cast<uintptr_t>(mi.lpBaseOfDll);
        return mi.SizeOfImage;
    }

/**
 * @brief Retrieves the base address of a module in a process.
 * @param pid The process ID of the process that owns the module.
 * @param moduleName The name of the module to find.
 * @param outBase A pointer to store the base address of the module.
 * @return The size of the module's image in memory, or 0 on failure.
 * @details This function retrieves the base address of a module in a process. It takes a snapshot of all the modules in the process, then iterates through the modules until it finds one with the given name. If the module is found, its base address and size are returned. Otherwise, 0 is returned.
 */
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

        const SIZE_T chunkSize = 64 * 1024; // 64KB
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

            if (mbi.State == MEM_COMMIT && ((mbi.Protect & PAGE_GUARD) == 0)) {
                

                SIZE_T offset = 0;
                SIZE_T regionSize = regionEnd - regionBase;
                while (offset < regionSize) {
                    SIZE_T toRead = regionSize - offset;
                    if (toRead > chunkSize) toRead = chunkSize;
                    LPVOID readAddress = reinterpret_cast<LPVOID>(regionBase + offset);
                    std::vector<PageProtectEntry> patchedEntries{};
                    if (MakeAddressReadable(processInfo->handle, readAddress, toRead, patchedEntries)) {
                        buffer.resize(toRead);
                        SIZE_T actuallyRead = 0;
                        if (ReadProcessMemory(processInfo->handle,
                                            readAddress,
                                            buffer.data(),
                                            toRead,
                                            &actuallyRead) && actuallyRead > 0) {
                            for(size_t i = 0; i < actuallyRead; i++) {
                                if (callback(callbackData, reinterpret_cast<uintptr_t>(readAddress) - processInfo->moduleBase + i, buffer[i])) {
                                    return; // callback says we're done iterating
                                }
                            }
                        }
                        RestorePageProtections(patchedEntries);
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
 * @return FlushInstructionCache Failed = -1, WriteMemory Failed = 0, Success = 1
 */
    int8_t FillWithNOPs(LPVOID target, const SIZE_T patchSize, const bool virtualProtect) {
        std::vector<PageProtectEntry> patchedEntries{};
        if (!MakeAddressWritable(target, patchSize, patchedEntries)) {
            return 0; // VirtualProtectEx failed
        }
        
        const std::vector<BYTE> nops(patchSize, 0x90); 
        std::memcpy(target, nops.data(), patchSize);

        // Ensure CPU sees the change
        int8_t result = FlushInstructionCache(GetCurrentProcess(), target, patchSize) ? 1 : -1;
        // if (result == -1) {
        //     std::cerr << "FlushInstructionCache failed. Error: " << GetLastError() << "\n";
        // }

        if (virtualProtect) {
            // restore original protection
            RestorePageProtections(patchedEntries);
        }

        return result;
    }

/**
 * @brief Fills a memory block at the process with NOPs (0x90)
 * @param processHandle Handle of the process to write to
 * @param target Address in the process to write to
 * @param patchSize Size of the patch to write
 * @return FlushInstructionCache Failed = -1, WriteProcessMemory Failed = 0, Success = 1
 */
    int8_t FillWithNOPs(HANDLE processHandle, LPVOID target, const SIZE_T patchSize) {
        std::vector<PageProtectEntry> patchedEntries{};
        if (!MakeAddressWritable(processHandle, target, patchSize, patchedEntries)) {
            return 0; // VirtualProtectEx failed
        }
        
        SIZE_T bytesWritten = 0;
        const std::vector<BYTE> nops(patchSize, 0x90); 
        if (!WriteProcessMemory(processHandle, target, nops.data(), patchSize, &bytesWritten) || (bytesWritten != patchSize)) {
            // restore original protection
            RestorePageProtections(processHandle, patchedEntries);
            return 0; // WriteProcessMemory failed
        }

        // Ensure CPU sees the change
        int8_t result = FlushInstructionCache(processHandle, target, patchSize) ? 1 : -1;
        // if (result == -1) {
        //     std::cerr << "FlushInstructionCache failed. Error: " << GetLastError() << "\n";
        // }

        // restore original protection
        RestorePageProtections(processHandle, patchedEntries);
        
        return result;
    }

/**
 * @brief Locally writes the data from source with size, to the destination
 * @param destination address where to write to
 * @param source Address to where the data to write
 * @param size Size of the data to write
 * @return FlushInstructionCache Failed = -1, WriteMemory Failed = 0, Success = 1
 */
    int8_t WriteMemory(LPVOID destination, LPCVOID source, const SIZE_T size, const bool virtualProtect) {
        std::vector<PageProtectEntry> patchedEntries{};
        if (virtualProtect && !MakeAddressWritable(destination, size, patchedEntries)) {
            return 0; // VirtualProtectEx failed
        }

        std::memmove(destination, source, size);

        // Ensure CPU sees the change
        const int8_t result = FlushInstructionCache(GetCurrentProcess(), destination, size) ? 1 : -1; 
        // if (result == -1) {
        //     std::cerr << "FlushInstructionCache failed. Error: " << GetLastError() << "\n";
        // }

        if (virtualProtect) {
            // restore original protection
            RestorePageProtections(patchedEntries);
        }

        return result;
    }

/**
 * @brief Writes localSource to remoteDestination in processHandle
 * @param processHandle Handle of the process to write to
 * @param remoteDestination Address in the process to write to
 * @param localSource Address of the local data to write
 * @param size Size of the data to write
 * @return FlushInstructionCacheFailed = -1, WriteProcessMemory Failed = 0, Success = 1
 */
    int8_t WriteMemory(HANDLE processHandle, LPVOID remoteDestination, LPCVOID localSource, const SIZE_T size) {
        std::vector<PageProtectEntry> patchedEntries{};
        if (!MakeAddressWritable(processHandle, remoteDestination, size, patchedEntries)) {
            return 0; // VirtualProtectEx failed
        }

        SIZE_T bytesWritten = 0;
        if (!WriteProcessMemory(processHandle, remoteDestination, localSource, size, &bytesWritten) || (bytesWritten != size)) {
            // restore original protection
            RestorePageProtections(processHandle, patchedEntries);
            return 0; // WriteProcessMemory failed
        }

        // Ensure CPU sees the change
        const int8_t result = FlushInstructionCache(processHandle, remoteDestination, size) ? 1 : -1; 
        // if (result == -1) {
        //     std::cerr << "FlushInstructionCache failed. Error: " << GetLastError() << "\n";
        // }

        // restore original protection
        RestorePageProtections(processHandle, patchedEntries);
        
        return result;
    }

/**
 * @brief Copies data from source to destination in process
 * @param destination Address in the process to copy to
 * @param source Address in the process to copy from
 * @param size Size of the data to copy
 * @param virtualProtect If true, the function will attempt to make the source address readable by changing its memory protection
 * @return FlushInstructionCacheFailed = -1, ReadMemory Failed = 0, Success = 1
 */
    bool ReadMemory(LPVOID destination, LPCVOID source, const SIZE_T size, const bool virtualProtect) {
        std::vector<PageProtectEntry> patchedEntries{};
        if (virtualProtect && !MakeAddressReadable(const_cast<LPVOID>(source), size, patchedEntries)) {
            return false; // VirtualProtectEx failed
        }

        std::memmove(destination, source, size);

        if (virtualProtect) {
            // restore original protection
            RestorePageProtections(patchedEntries);
        }

        return true;
    }

/**
 * @brief Reads remoteSource from processHandle into localDestination
 * @param processHandle Handle of the process to read from
 * @param localDestination Address of the local data to read into
 * @param remoteSource Address in the process to read from
 * @param size Size of the data to read
 * @return FlushInstructionCacheFailed = -1, ReadProcessMemory Failed = 0, Success = 1
 */
    bool ReadMemory(HANDLE processHandle, LPVOID localDestination, LPCVOID remoteSource, const SIZE_T size) {
        std::vector<PageProtectEntry> patchedEntries{};
        if (!MakeAddressReadable(processHandle, const_cast<LPVOID>(remoteSource), size, patchedEntries)) {
            return false; // VirtualProtectEx failed
        }

        SIZE_T bytesRead = 0;
        if (!ReadProcessMemory(processHandle, remoteSource, localDestination, size, &bytesRead) || (bytesRead != size)) {
            return false; // ReadProcessMemory failed
        }

        // restore original protection
        RestorePageProtections(processHandle, patchedEntries);

        return true;
    }
}