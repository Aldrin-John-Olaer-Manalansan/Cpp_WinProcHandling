/*
 * @File: WinProcHandling.cpp
 * @Author: Aldrin John O. Manalansan (ajom)
 * @Email: aldrinjohnolaermanalansan@gmail.com
 * @Brief: Library for manipulating memory of windows processes
 * @LastUpdate: August 29, 2026
 *
 * Copyright (C) 2026  Aldrin John O. Manalansan  <aldrinjohnolaermanalansan@gmail.com>
 * 
 * This Source Code is served under Open-Source AJOM License
 * You should have received a copy of License_OS-AJOM
 * along with this source code. If not, see:
 * <https://raw.githubusercontent.com/Aldrin-John-Olaer-Manalansan/AJOM_License/refs/heads/main/LICENSE_AJOM-OS>
 */

#include "WinProcHandling.hpp"

#include <algorithm>
#include <cstring>
#include <limits>
#include <psapi.h>
#include <tlhelp32.h>
#include <vector>

namespace WinProcHandling {
    /**
     * @struct PageProtectEntry
     * @brief Records one successful temporary page-protection change.
     *
     * The entry stores exactly the information required to call VirtualProtect or
     * VirtualProtectEx again during cleanup. Keeping these records per operation
     * prevents one WriteMemory call from accidentally sharing protection state with
     * a later call.
     */
    struct PageProtectEntry {
        /** First byte of the range whose protection was changed. */
        LPVOID base{};
        /** Number of bytes covered by the protection-changing API call. */
        SIZE_T size{};
        /** Protection reported by the original protection-changing call. */
        DWORD oldProtect{};
    };

    constexpr DWORD kBaseProtectionMask = 0xFFu;
    constexpr DWORD kCacheModifiers = PAGE_NOCACHE | PAGE_WRITECOMBINE;

    /**
     * @brief Returns only the base protection bits from a Win32 protection value.
     *
     * Protection modifiers such as PAGE_GUARD are intentionally excluded from
     * this classification step because callers handle those modifiers separately.
     */
    static DWORD BaseProtection(DWORD protect) noexcept {
        return protect & kBaseProtectionMask;
    }

    /** @brief Returns true when the base protection permits normal reads. */
    static bool IsReadableProtection(DWORD protect) noexcept {
        switch (BaseProtection(protect)) {
        case PAGE_READONLY:
        case PAGE_READWRITE:
        case PAGE_WRITECOPY:
        case PAGE_EXECUTE_READ:
        case PAGE_EXECUTE_READWRITE:
        case PAGE_EXECUTE_WRITECOPY:
            return true;
        default:
            return false;
        }
    }

    /** @brief Returns true when the base protection permits normal writes. */
    static bool IsWritableProtection(DWORD protect) noexcept {
        switch (BaseProtection(protect)) {
        case PAGE_READWRITE:
        case PAGE_WRITECOPY:
        case PAGE_EXECUTE_READWRITE:
        case PAGE_EXECUTE_WRITECOPY:
            return true;
        default:
            return false;
        }
    }

    /** @brief Returns true when the base protection permits instruction execution. */
    static bool IsExecutableProtection(DWORD protect) noexcept {
        switch (BaseProtection(protect)) {
        case PAGE_EXECUTE:
        case PAGE_EXECUTE_READ:
        case PAGE_EXECUTE_READWRITE:
        case PAGE_EXECUTE_WRITECOPY:
            return true;
        default:
            return false;
        }
    }

    /**
     * @brief Produces a writable equivalent while preserving execute/cache intent.
     */
    static DWORD WritableProtection(DWORD oldProtect) noexcept {
        DWORD result = IsExecutableProtection(oldProtect)
            ? PAGE_EXECUTE_READWRITE
            : PAGE_READWRITE;
        return result | (oldProtect & kCacheModifiers);
    }

    /**
     * @brief Produces a readable equivalent while preserving execute/cache intent.
     */
    static DWORD ReadableProtection(DWORD oldProtect) noexcept {
        DWORD result = IsExecutableProtection(oldProtect)
            ? PAGE_EXECUTE_READ
            : PAGE_READONLY;
        return result | (oldProtect & kCacheModifiers);
    }

    /**
     * @brief Walks every virtual-memory region intersecting a requested range.
     *
     * VirtualProtect/VirtualProtectEx cannot be treated as if an arbitrary request
     * were one homogeneous allocation. This helper therefore queries each region,
     * changes only the intersecting portion, and records successful changes.
     *
     * The query/protection callables allow the same algorithm to serve local and
     * remote memory without duplicating the range-walking logic.
     */
    template <typename QueryFn, typename ProtectFn>
    static bool MakeRangeAccessible(
        LPVOID address,
        SIZE_T size,
        std::vector<PageProtectEntry>& out,
        QueryFn query,
        ProtectFn protect,
        DWORD (*newProtection)(DWORD),
        bool rejectGuardPages)
    {
        if (size == 0)
            return true;
        if (address == nullptr)
            return false;

        const uintptr_t rangeStart = reinterpret_cast<uintptr_t>(address);

        if (size > std::numeric_limits<uintptr_t>::max() - rangeStart)
            return false;

        const uintptr_t rangeEnd = rangeStart + size;
        uintptr_t currentAddress = rangeStart;

        while (currentAddress < rangeEnd) {
            MEMORY_BASIC_INFORMATION memoryInformation{};
            if (query(reinterpret_cast<LPCVOID>(currentAddress), &memoryInformation, sizeof(memoryInformation)) == 0) {
                return false;
            }

            const uintptr_t regionStart = reinterpret_cast<uintptr_t>(memoryInformation.BaseAddress);
            if (memoryInformation.RegionSize == 0 ||
                memoryInformation.RegionSize > std::numeric_limits<uintptr_t>::max() - regionStart) {
                return false;
            }

            const uintptr_t regionEnd = regionStart + memoryInformation.RegionSize;
            const uintptr_t patchStart = std::max(rangeStart, regionStart);
            const uintptr_t patchEnd = std::min(rangeEnd, regionEnd);

            if (patchStart >= patchEnd) {
                // A successful query must make forward progress.
                return false;
            }

            if (memoryInformation.State != MEM_COMMIT ||
                (rejectGuardPages && (memoryInformation.Protect & PAGE_GUARD))) {
                return false;
            }

            const DWORD originalProtection = memoryInformation.Protect;
            const DWORD requestedProtection = newProtection(originalProtection);

            if (requestedProtection != originalProtection) {
                DWORD previousProtection = 0;
                const SIZE_T protectedSize = static_cast<SIZE_T>(patchEnd - patchStart);

                if (!protect(
                        reinterpret_cast<LPVOID>(patchStart),
                        protectedSize,
                        requestedProtection,
                        &previousProtection)) {
                    return false;
                }

                out.push_back({
                    reinterpret_cast<LPVOID>(patchStart),
                    protectedSize,
                    previousProtection
                });
            }

            currentAddress = regionEnd;
        }

        return true;
    }

    /**
     * @brief Restores local protections in reverse order and reports failures.
     *
     * Cleanup is deliberately best-effort across all recorded entries: one failed
     * VirtualProtect call must not prevent the remaining entries from being restored.
     */
    static bool RestoreLocal(
        std::vector<PageProtectEntry>& entries,
        size_t startIndex)
    {
        bool allSucceeded = true;

        for (size_t entryIndex = entries.size(); entryIndex > startIndex; ) {
            --entryIndex;
            DWORD ignoredPreviousProtection = 0;
            if (!VirtualProtect(
                    entries[entryIndex].base,
                    entries[entryIndex].size,
                    entries[entryIndex].oldProtect,
                    &ignoredPreviousProtection))
                allSucceeded = false;
        }

        entries.erase(entries.begin() + static_cast<std::ptrdiff_t>(startIndex), entries.end());
        return allSucceeded;
    }

    /**
     * @brief Restores remote protections in reverse order and reports failures.
     */
    static bool RestoreRemote(
        HANDLE processHandle,
        std::vector<PageProtectEntry>& entries,
        size_t startIndex)
    {
        bool allSucceeded = true;

        for (size_t i = entries.size(); i > startIndex; ) {
            --i;
            DWORD ignored = 0;
            if (!VirtualProtectEx(
                    processHandle,
                    entries[i].base,
                    entries[i].size,
                    entries[i].oldProtect,
                    &ignored)) {
                allSucceeded = false;
            }
        }

        entries.erase(entries.begin() + static_cast<std::ptrdiff_t>(startIndex), entries.end());
        return allSucceeded;
    }

    /**
     * @brief Makes a local memory range writable and records every protection change.
     *
     * This helper is the local-process counterpart of MakeRemoteWritable. It uses
     * VirtualQuery/VirtualProtect because the target address belongs to the current
     * process rather than a remote address space.
     */
    static bool MakeLocalWritable(
        LPVOID address, SIZE_T size, std::vector<PageProtectEntry>& out)
    {
        return MakeRangeAccessible(
            address, size, out,
            [](LPCVOID queryAddress, PMEMORY_BASIC_INFORMATION memoryInformation, SIZE_T informationSize) {
                return VirtualQuery(queryAddress, memoryInformation, informationSize);
            },
            [](LPVOID protectionAddress, SIZE_T protectionSize, DWORD newProtection, PDWORD oldProtection) {
                return VirtualProtect(protectionAddress, protectionSize, newProtection, oldProtection);
            },
            WritableProtection,
            true);
    }

    /**
     * @brief Makes a remote memory range writable and records its original protections.
     *
     * @param processHandle Handle of the process whose address space is changed.
     * @param address First byte of the requested range.
     * @param size Number of requested bytes.
     * @param out Receives each successful protection change for later restoration.
     * @param rejectGuardPages If true, PAGE_GUARD regions are rejected.
     */
    static bool MakeRemoteWritable(
        HANDLE processHandle, LPVOID address, SIZE_T size,
        std::vector<PageProtectEntry>& out,
        bool rejectGuardPages)
    {
        if (processHandle == nullptr || processHandle == INVALID_HANDLE_VALUE)
            return false;

        return MakeRangeAccessible(
            address, size, out,
            [processHandle](LPCVOID queryAddress, PMEMORY_BASIC_INFORMATION memoryInformation, SIZE_T informationSize) {
                return VirtualQueryEx(processHandle, queryAddress, memoryInformation, informationSize);
            },
            [processHandle](LPVOID protectionAddress, SIZE_T protectionSize, DWORD newProtection, PDWORD oldProtection) {
                return VirtualProtectEx(processHandle, protectionAddress, protectionSize, newProtection, oldProtection);
            },
            WritableProtection,
            rejectGuardPages);
    }

    /**
     * @brief Makes a local memory range readable and records every protection change.
     */
    static bool MakeLocalReadable(
        LPVOID address, SIZE_T size, std::vector<PageProtectEntry>& out)
    {
        return MakeRangeAccessible(
            address, size, out,
            [](LPCVOID queryAddress, PMEMORY_BASIC_INFORMATION memoryInformation, SIZE_T informationSize) {
                return VirtualQuery(queryAddress, memoryInformation, informationSize);
            },
            [](LPVOID protectionAddress, SIZE_T protectionSize, DWORD newProtection, PDWORD oldProtection) {
                return VirtualProtect(protectionAddress, protectionSize, newProtection, oldProtection);
            },
            ReadableProtection,
            true);
    }

    /**
     * @brief Makes a remote memory range readable and records its original protections.
     *
     * @param processHandle Handle of the target process.
     * @param address First byte of the requested range.
     * @param size Number of requested bytes.
     * @param out Receives successful protection changes.
     * @param rejectGuardPages Whether PAGE_GUARD should be rejected.
     */
    static bool MakeRemoteReadable(
        HANDLE processHandle, LPVOID address, SIZE_T size,
        std::vector<PageProtectEntry>& out,
        bool rejectGuardPages)
    {
        if (processHandle == nullptr || processHandle == INVALID_HANDLE_VALUE)
            return false;

        return MakeRangeAccessible(
            address, size, out,
            [processHandle](LPCVOID queryAddress, PMEMORY_BASIC_INFORMATION memoryInformation, SIZE_T informationSize) {
                return VirtualQueryEx(processHandle, queryAddress, memoryInformation, informationSize);
            },
            [processHandle](LPVOID protectionAddress, SIZE_T protectionSize, DWORD newProtection, PDWORD oldProtection) {
                return VirtualProtectEx(processHandle, protectionAddress, protectionSize, newProtection, oldProtection);
            },
            ReadableProtection,
            rejectGuardPages);
    }

    /**
     * @brief Checks whether a process handle is non-null and not INVALID_HANDLE_VALUE.
     */
    static bool IsValidProcessHandle(HANDLE processHandle) noexcept {
        return processHandle != nullptr && processHandle != INVALID_HANDLE_VALUE;
    }

    /**
     * @brief Creates a process snapshot and searches executable filenames.
     *
     * The snapshot handle is closed before the function returns. A process ID of
     * zero is used as the failure/not-found sentinel, matching the public API.
     */
    DWORD FindProcessId(const char* processName) {
        if (processName == nullptr || *processName == '\0')
            return 0;

        PROCESSENTRY32 pe{};
        pe.dwSize = sizeof(pe);

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE)
            return 0;

        DWORD result = 0;
        if (Process32First(snapshot, &pe)) {
            do {
                if (_stricmp(pe.szExeFile, processName) == 0) {
                    result = pe.th32ProcessID;
                    break;
                }
            } while (Process32Next(snapshot, &pe));
        }

        CloseHandle(snapshot);
        return result;
    }

    /**
     * @brief Obtains the executable module information for an open process.
     *
     * The current-process case uses GetModuleHandle/GetModuleInformation directly;
     * a remote process is inspected through EnumProcessModulesEx.
     */
    DWORD GetModuleBase(HANDLE processHandle, uintptr_t* const outBase) {
        if (!IsValidProcessHandle(processHandle))
            return 0;

        MODULEINFO mi{};

        if (GetCurrentProcessId() == GetProcessId(processHandle)) {
            HMODULE module = GetModuleHandleA(nullptr);
            if (!module)
                return 0;

            if (!GetModuleInformation(processHandle, module, &mi, sizeof(mi)))
                return 0;

            if (outBase)
                *outBase = reinterpret_cast<uintptr_t>(mi.lpBaseOfDll);

            return mi.SizeOfImage;
        }

        HMODULE modules[1024]{};
        DWORD cbNeeded = 0;

        if (!EnumProcessModulesEx(
                processHandle, modules, sizeof(modules), &cbNeeded, LIST_MODULES_ALL)) {
            return 0;
        }

        if (cbNeeded < sizeof(HMODULE))
            return 0;

        // Microsoft documents that the first module is the executable file.
        HMODULE mainModule = modules[0];
        if (!GetModuleInformation(processHandle, mainModule, &mi, sizeof(mi)))
            return 0;

        if (outBase)
            *outBase = reinterpret_cast<uintptr_t>(mi.lpBaseOfDll);

        return mi.SizeOfImage;
    }

    /**
     * @brief Enumerates process modules until the requested filename is found.
     *
     * ERROR_BAD_LENGTH is retried because Microsoft documents that module snapshots
     * can transiently report that condition while the module list changes.
     */
    DWORD GetModuleBase(DWORD pid, const char* moduleName, uintptr_t* const outBase) {
        if (pid == 0 || moduleName == nullptr || *moduleName == '\0')
            return 0;

        // Retry ERROR_BAD_LENGTH as documented for module snapshots.
        HANDLE snapshot = INVALID_HANDLE_VALUE;
        for (int attempt = 0; attempt < 8; ++attempt) {
            snapshot = CreateToolhelp32Snapshot(
                TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);

            if (snapshot != INVALID_HANDLE_VALUE)
                break;

            if (GetLastError() != ERROR_BAD_LENGTH)
                return 0;
        }

        if (snapshot == INVALID_HANDLE_VALUE)
            return 0;

        MODULEENTRY32 me{};
        me.dwSize = sizeof(me);

        DWORD result = 0;
        if (Module32First(snapshot, &me)) {
            do {
                if (_stricmp(me.szModule, moduleName) == 0) {
                    if (outBase)
                        *outBase = reinterpret_cast<uintptr_t>(me.modBaseAddr);
                    result = me.modBaseSize;
                    break;
                }
            } while (Module32Next(snapshot, &me));
        }

        CloseHandle(snapshot);
        return result;
    }

    /**
     * @brief Scans the configured module range in readable chunks.
     *
     * VirtualQueryEx is used for each region so the scanner does not assume that an
     * entire module has one protection value. The callback receives module-relative
     * byte indexes and can stop the scan by returning true.
     */
    void ForEachScanProcess(
        t_ProcessInfo* const processInfo,
        void* const callbackData,
        bool(*callback)(void* callbackData, size_t byteIndex, uint8_t& byte))
    {
        if (processInfo == nullptr || callback == nullptr || !IsValidProcessHandle(processInfo->handle))
            return;

        if (processInfo->moduleBase == 0 || processInfo->moduleSize == 0)
            return;

        const uintptr_t moduleEnd =
            processInfo->moduleBase +
            std::min<uintptr_t>(
                processInfo->moduleSize,
                std::numeric_limits<uintptr_t>::max() - processInfo->moduleBase);

        if (processInfo->searchedOffsetFromBase >= processInfo->moduleSize)
            return;

        const uintptr_t requestedStart =
            processInfo->moduleBase + processInfo->searchedOffsetFromBase;

        const uintptr_t requestedEnd = std::min(
            moduleEnd,
            requestedStart + std::min<uintptr_t>(
                processInfo->searchSize,
                std::numeric_limits<uintptr_t>::max() - requestedStart));

        constexpr SIZE_T chunkSize = 64 * 1024;
        std::vector<uint8_t> buffer;
        MEMORY_BASIC_INFORMATION mbi{};

        uintptr_t seeker = requestedStart;

        while (seeker < requestedEnd) {
            if (VirtualQueryEx(
                    processInfo->handle,
                    reinterpret_cast<LPCVOID>(seeker),
                    &mbi,
                    sizeof(mbi)) == 0) {
                return;
            }

            const uintptr_t regionBase = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
            if (mbi.RegionSize == 0 ||
                mbi.RegionSize > std::numeric_limits<uintptr_t>::max() - regionBase) {
                return;
            }

            const uintptr_t regionEnd = regionBase + mbi.RegionSize;
            const uintptr_t readBegin = std::max(requestedStart, regionBase);
            const uintptr_t readEnd = std::min(requestedEnd, regionEnd);

            if (readBegin >= readEnd) {
                if (regionEnd <= seeker)
                    return;
                continue;
            }

            if (mbi.State == MEM_COMMIT && !(mbi.Protect & PAGE_GUARD)) {
                const bool readable = IsReadableProtection(mbi.Protect);

                for (uintptr_t current = readBegin; current < readEnd; ) {
                    const SIZE_T remaining = static_cast<SIZE_T>(readEnd - current);
                    const SIZE_T toRead = std::min<SIZE_T>(remaining, chunkSize);

                    buffer.resize(toRead);
                    SIZE_T actuallyRead = 0;
                    DWORD oldProtect = 0;
                    bool changedProtection = false;

                    if (!readable) {
                        const DWORD newProtection = ReadableProtection(mbi.Protect);
                        if (!VirtualProtectEx(
                                processInfo->handle,
                                reinterpret_cast<LPVOID>(current),
                                toRead,
                                newProtection,
                                &oldProtect)) {
                            current += toRead;
                            continue;
                        }
                        changedProtection = true;
                    }

                    const bool readSuccess =
                        ReadProcessMemory(
                            processInfo->handle,
                            reinterpret_cast<LPCVOID>(current),
                            buffer.data(),
                            toRead,
                            &actuallyRead) &&
                        actuallyRead == toRead;

                    if (changedProtection) {
                        DWORD ignored = 0;
                        (void)VirtualProtectEx(
                            processInfo->handle,
                            reinterpret_cast<LPVOID>(current),
                            toRead,
                            oldProtect,
                            &ignored);
                    }

                    if (readSuccess) {
                        for (SIZE_T byteOffset = 0; byteOffset < actuallyRead; ++byteOffset) {
                            const size_t byteIndex =
                                static_cast<size_t>(current - processInfo->moduleBase) + byteOffset;
                            if (callback(callbackData, byteIndex, buffer[byteOffset]))
                                return;
                        }
                    }

                    current += toRead;
                }
            }

            if (regionEnd <= seeker)
                return;
        }
    }

    /**
     * @brief Performs a local write, optional temporary protection change, cache flush,
     * and protection restoration.
     *
     * The byte contents are intentionally not rolled back on failure: this function
     * has no caller-supplied original-byte backup. Protection state is rolled back.
     */
    e_WriteStatus WriteMemory(
        LPVOID destination,
        LPCVOID source,
        SIZE_T size,
        e_VirtualProtectMode virtualProtectMode,
        bool flushInstructionCache)
    {
        if (size == 0)
            return e_WriteStatus::Success;
        if (destination == nullptr || source == nullptr)
            return e_WriteStatus::WriteMemoryFailed;

        std::vector<PageProtectEntry> changedPages;
        const bool protectionRequested =
            virtualProtectMode != e_VirtualProtectMode::DontChange;

        if (virtualProtectMode == e_VirtualProtectMode::SafelyChange ||
            virtualProtectMode == e_VirtualProtectMode::ForceChange) {
            if (!MakeLocalWritable(destination, size, changedPages)) {
                (void)RestoreLocal(changedPages, 0);
                return e_WriteStatus::WriteMemoryFailed;
            }
        }

        std::memmove(destination, source, size);

        if (flushInstructionCache &&
            !FlushInstructionCache(GetCurrentProcess(), destination, size)) {
            if (protectionRequested) {
                const bool restored = RestoreLocal(changedPages, 0);
                return restored
                    ? e_WriteStatus::FlushInstructionCacheFailed
                    : e_WriteStatus::ProtectionRestoreFailed;
            }
            return e_WriteStatus::FlushInstructionCacheFailed;
        }

        if (protectionRequested) {
            if (!RestoreLocal(changedPages, 0))
                return e_WriteStatus::ProtectionRestoreFailed;
        }

        return e_WriteStatus::Success;
    }

    /**
     * @brief Performs a remote write and restores all protections changed by this call.
     *
     * The remote write is considered complete only when WriteProcessMemory reports
     * success and the requested byte count was written.
     */
    e_WriteStatus WriteMemory(
        HANDLE processHandle,
        LPVOID remoteDestination,
        LPCVOID localSource,
        SIZE_T size,
        e_VirtualProtectMode virtualProtectMode,
        bool flushInstructionCache)
    {
        if (!IsValidProcessHandle(processHandle))
            return e_WriteStatus::WriteMemoryFailed;
        if (size == 0)
            return e_WriteStatus::Success;
        if (remoteDestination == nullptr || localSource == nullptr)
            return e_WriteStatus::WriteMemoryFailed;

        std::vector<PageProtectEntry> changedPages;
        const bool protectionRequested =
            virtualProtectMode != e_VirtualProtectMode::DontChange;

        if (protectionRequested) {
            if (!MakeRemoteWritable(
                    processHandle, remoteDestination, size, changedPages,
                    virtualProtectMode == e_VirtualProtectMode::SafelyChange)) {
                (void)RestoreRemote(processHandle, changedPages, 0);
                return e_WriteStatus::WriteMemoryFailed;
            }
        }

        SIZE_T bytesWritten = 0;
        const bool writeSuccess =
            WriteProcessMemory(
                processHandle,
                remoteDestination,
                localSource,
                size,
                &bytesWritten) &&
            bytesWritten == size;

        if (!writeSuccess) {
            const bool restored = protectionRequested
                ? RestoreRemote(processHandle, changedPages, 0)
                : true;
            return restored
                ? e_WriteStatus::WriteMemoryFailed
                : e_WriteStatus::ProtectionRestoreFailed;
        }

        if (flushInstructionCache &&
            !FlushInstructionCache(processHandle, remoteDestination, size)) {
            if (protectionRequested) {
                const bool restored = RestoreRemote(processHandle, changedPages, 0);
                return restored
                    ? e_WriteStatus::FlushInstructionCacheFailed
                    : e_WriteStatus::ProtectionRestoreFailed;
            }
            return e_WriteStatus::FlushInstructionCacheFailed;
        }

        if (protectionRequested) {
            if (!RestoreRemote(processHandle, changedPages, 0))
                return e_WriteStatus::ProtectionRestoreFailed;
        }

        return e_WriteStatus::Success;
    }

    e_WriteStatus FillWithNOPs(
        LPVOID target,
        SIZE_T patchSize,
        e_VirtualProtectMode virtualProtectMode,
        bool flushInstructionCache)
    {
        if (patchSize == 0)
            return e_WriteStatus::Success;
        if (target == nullptr)
            return e_WriteStatus::WriteMemoryFailed;

        std::vector<uint8_t> nops(patchSize, 0x90);
        return WriteMemory(
            target, nops.data(), patchSize, virtualProtectMode, flushInstructionCache);
    }

    e_WriteStatus FillWithNOPs(
        HANDLE processHandle,
        LPVOID target,
        SIZE_T patchSize,
        e_VirtualProtectMode virtualProtectMode,
        bool flushInstructionCache)
    {
        if (patchSize == 0)
            return e_WriteStatus::Success;
        if (!IsValidProcessHandle(processHandle) || target == nullptr)
            return e_WriteStatus::WriteMemoryFailed;

        std::vector<uint8_t> nops(patchSize, 0x90);
        return WriteMemory(
            processHandle, target, nops.data(), patchSize,
            virtualProtectMode, flushInstructionCache);
    }

    /**
     * @brief Copies bytes from the current process and restores temporary protections.
     */
    bool ReadMemory(
        LPVOID destination,
        LPCVOID source,
        SIZE_T size,
        e_VirtualProtectMode virtualProtectMode)
    {
        if (size == 0)
            return true;
        if (destination == nullptr || source == nullptr)
            return false;

        std::vector<PageProtectEntry> changedPages;
        const bool protectionRequested =
            virtualProtectMode != e_VirtualProtectMode::DontChange;

        if (protectionRequested) {
            if (!MakeLocalReadable(
                    const_cast<LPVOID>(source), size, changedPages)) {
                (void)RestoreLocal(changedPages, 0);
                return false;
            }
        }

        std::memmove(destination, source, size);

        if (protectionRequested)
            return RestoreLocal(changedPages, 0);

        return true;
    }

    /**
     * @brief Reads a complete remote range and restores temporary protections even when
     * ReadProcessMemory fails.
     */
    bool ReadMemory(
        HANDLE processHandle,
        LPVOID localDestination,
        LPCVOID remoteSource,
        SIZE_T size,
        e_VirtualProtectMode virtualProtectMode)
    {
        if (!IsValidProcessHandle(processHandle))
            return false;
        if (size == 0)
            return true;
        if (localDestination == nullptr || remoteSource == nullptr)
            return false;

        std::vector<PageProtectEntry> changedPages;
        const bool protectionRequested =
            virtualProtectMode != e_VirtualProtectMode::DontChange;

        if (protectionRequested) {
            if (!MakeRemoteReadable(
                    processHandle, const_cast<LPVOID>(remoteSource),
                    size, changedPages,
                    virtualProtectMode == e_VirtualProtectMode::SafelyChange)) {
                (void)RestoreRemote(processHandle, changedPages, 0);
                return false;
            }
        }

        SIZE_T bytesRead = 0;
        const bool success =
            ReadProcessMemory(
                processHandle,
                remoteSource,
                localDestination,
                size,
                &bytesRead) &&
            bytesRead == size;

        const bool restored =
            protectionRequested
                ? RestoreRemote(processHandle, changedPages, 0)
                : true;

        return success && restored;
    }
} // namespace WinProcHandling
