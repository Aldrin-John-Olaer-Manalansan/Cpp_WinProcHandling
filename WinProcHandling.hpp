/*
 * @File: WinProcHandling.hpp
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

#pragma once

#ifndef NOMINMAX
#define NOMINMAX 1
#endif

#include <windows.h>
#include <cstdint>
#include <cstddef>

namespace WinProcHandling {

/**
 * @struct t_ProcessInfo
 * @brief Describes the module range and process handle used by the scanner.
 */
struct t_ProcessInfo {
    /** Byte offset from moduleBase at which the scan begins. */
    size_t searchedOffsetFromBase{};
    /** Maximum number of bytes to scan. */
    size_t searchSize{};
    /** Process identifier associated with handle. */
    DWORD id{};
    /** Caller-owned process handle used for remote reads. */
    HANDLE handle{};
    /** Base virtual address of the module being scanned. */
    uintptr_t moduleBase{};
    /** Image size of the module in bytes. */
    size_t moduleSize{};
};

/**
 * @enum e_WriteStatus
 * @brief Result of a write operation and its required cleanup.
 */
enum class e_WriteStatus : std::int8_t {
    /** The operation changed protection, but restoration failed. */
    ProtectionRestoreFailed = -2,
    /** The write completed, but FlushInstructionCache failed. */
    FlushInstructionCacheFailed = -1,
    /** The requested write or protection transition failed. */
    WriteMemoryFailed = 0,
    /** The requested operation and cleanup completed successfully. */
    Success = 1
};

/**
 * @enum e_VirtualProtectMode
 * @brief Controls temporary page-protection changes.
 */
enum class e_VirtualProtectMode : std::uint8_t {
    /** Leave the existing page protection unchanged. */
    DontChange,
    /** Change normal committed pages, but reject PAGE_GUARD regions. */
    SafelyChange,
    /** Allow temporary changes to committed guarded pages and restore them later. */
    ForceChange
};

/**
 * @brief Finds a process ID by case-insensitive executable filename.
 * @param processName Executable filename, not a full path.
 * @return Matching process ID, or 0 when no match/snapshot failure occurs.
 */
DWORD FindProcessId(const char* processName);

/**
 * @brief Gets the executable module base address and image size from a process handle.
 * @param processHandle Open process handle.
 * @param[out] outBase Receives the module base when non-null.
 * @return Image size in bytes, or 0 on failure.
 */
DWORD GetModuleBase(HANDLE processHandle, uintptr_t* const outBase);

/**
 * @brief Gets a named module's base address and image size by process ID.
 * @param pid Target process identifier.
 * @param moduleName Module filename to find.
 * @param[out] outBase Receives the module base when non-null.
 * @return Image size in bytes, or 0 when the module is not found.
 */
DWORD GetModuleBase(DWORD pid, const char* moduleName, uintptr_t* const outBase);

/**
 * @brief Iterates over successfully readable bytes in a module-relative range.
 *
 * The callback receives the byte's offset from moduleBase. Returning true stops
 * the scan. Unreadable, uncommitted, and guarded regions are skipped.
 *
 * @param processInfo Scan configuration and target process handle.
 * @param callbackData Opaque caller-owned state passed to callback.
 * @param callback Callback invoked for each successfully read byte.
 */
void ForEachScanProcess(
    t_ProcessInfo* const processInfo,
    void* const callbackData,
    bool(*callback)(void* callbackData, size_t byteIndex, uint8_t& byte)
);

/**
 * @brief Fills memory in the current process with 0x90 NOP bytes.
 * @param target Destination address in the current process.
 * @param patchSize Number of bytes to fill.
 * @param virtualProtectMode Protection policy used before writing.
 * @param flushInstructionCache Whether to flush the current-process instruction cache.
 * @return Operation status.
 */
e_WriteStatus FillWithNOPs(
    LPVOID target,
    SIZE_T patchSize,
    e_VirtualProtectMode virtualProtectMode = e_VirtualProtectMode::DontChange,
    bool flushInstructionCache = true);

/**
 * @brief Fills memory in another process with 0x90 NOP bytes.
 * @param processHandle Target process handle.
 * @param target Destination address in the target process.
 * @param patchSize Number of bytes to fill.
 * @param virtualProtectMode Protection policy used before writing.
 * @param flushInstructionCache Whether to flush the target instruction cache.
 * @return Operation status.
 */
e_WriteStatus FillWithNOPs(
    HANDLE processHandle,
    LPVOID target,
    SIZE_T patchSize,
    e_VirtualProtectMode virtualProtectMode = e_VirtualProtectMode::SafelyChange,
    bool flushInstructionCache = true);

/**
 * @brief Writes bytes in the current process.
 * @param destination Destination address.
 * @param source Source buffer.
 * @param size Number of bytes to write.
 * @param virtualProtectMode Protection policy.
 * @param flushInstructionCache Whether to flush the instruction cache.
 * @return Operation status.
 */
e_WriteStatus WriteMemory(
    LPVOID destination,
    LPCVOID source,
    SIZE_T size,
    e_VirtualProtectMode virtualProtectMode = e_VirtualProtectMode::DontChange,
    bool flushInstructionCache = true);

/**
 * @brief Writes bytes into another process.
 * @param processHandle Target process handle.
 * @param remoteDestination Destination address in the target process.
 * @param localSource Source buffer in the caller's process.
 * @param size Number of bytes to write.
 * @param virtualProtectMode Protection policy.
 * @param flushInstructionCache Whether to flush the target instruction cache.
 * @return Operation status.
 */
e_WriteStatus WriteMemory(
    HANDLE processHandle,
    LPVOID remoteDestination,
    LPCVOID localSource,
    SIZE_T size,
    e_VirtualProtectMode virtualProtectMode = e_VirtualProtectMode::SafelyChange,
    bool flushInstructionCache = true);

/**
 * @brief Reads bytes from the current process.
 * @param destination Local destination buffer.
 * @param source Source address.
 * @param size Number of bytes to read.
 * @param virtualProtectMode Protection policy for the source.
 * @return true when all bytes are copied and cleanup succeeds.
 */
bool ReadMemory(
    LPVOID destination,
    LPCVOID source,
    SIZE_T size,
    e_VirtualProtectMode virtualProtectMode = e_VirtualProtectMode::DontChange);

/**
 * @brief Reads bytes from another process.
 * @param processHandle Target process handle.
 * @param localDestination Destination buffer in the caller's process.
 * @param remoteSource Source address in the target process.
 * @param size Number of bytes to read.
 * @param virtualProtectMode Protection policy for the source.
 * @return true only when all bytes are read and cleanup succeeds.
 */
bool ReadMemory(
    HANDLE processHandle,
    LPVOID localDestination,
    LPCVOID remoteSource,
    SIZE_T size,
    e_VirtualProtectMode virtualProtectMode = e_VirtualProtectMode::SafelyChange);

} // namespace WinProcHandling
