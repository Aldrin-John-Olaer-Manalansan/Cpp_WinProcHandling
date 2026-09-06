/*
 * @File: WinProcHandling.hpp
 * @Author: Aldrin John O. Manalansan (ajom)
 * @Email: aldrinjohnolaermanalansan@gmail.com
 * @Brief: Library for manipulating memory of windows processes
 * @LastUpdate: September 6, 2026
 *
 * Copyright (C) 2026  Aldrin John O. Manalansan  <aldrinjohnolaermanalansan@gmail.com>
 *
 * This Source Code is served under Open-Source AJOM License
 * You should have received a copy of License_OS-AJOM
 * along with this source code. If not, see:
 * <https://raw.githubusercontent.com/Aldrin-John-Olaer-Manalansan/AJOM_License/refs/heads/main/LICENSE_AJOM-OS>
 *
 * ---------------------------------------------------------------------------
 * Header inclusion note:
 * Define NOMINMAX (or include this header) BEFORE the first
 * #include <windows.h> of each translation unit. If <windows.h> was already
 * included without NOMINMAX, the min/max macros are already in effect for
 * that translation unit and cannot be undone from here. This library itself
 * does not depend on the macros (it uses std::min/std::max internally).
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
    /** Maximum number of bytes to scan. The scan is additionally clamped to
     *  the module range [moduleBase, moduleBase + moduleSize). */
    size_t searchSize{};
    /** Process identifier associated with handle.
     *  @note Informational only: ForEachScanProcess never reads this member.
     *        It exists so callers can log, or assert, that handle and id refer
     *        to the same process. */
    DWORD id{};
    /** Caller-owned process handle used for remote reads.
     *  ForEachScanProcess requires PROCESS_VM_READ, PROCESS_VM_OPERATION
     *  (only when unreadable regions should be force-flipped) and
     *  PROCESS_QUERY_INFORMATION rights on this handle. */
    HANDLE handle{};
    /** Base virtual address of the module being scanned. Must be non-zero. */
    uintptr_t moduleBase{};
    /** Image size of the module in bytes. Must be non-zero. */
    size_t moduleSize{};
};

/**
 * @enum e_WriteStatus
 * @brief Result of a write operation and its required cleanup.
 */
enum class e_WriteStatus : std::int8_t {
    /** The operation changed protection, but restoration failed. At least one
     *  affected page may still carry the temporary (more permissive)
     *  protection. Restoration is best-effort: every recorded page is
     *  attempted once, in reverse order, even if earlier restores fail. */
    ProtectionRestoreFailed = -2,
    /** The write completed, but FlushInstructionCache failed. Protection
     *  state (when it was changed) has been restored. */
    FlushInstructionCacheFailed = -1,
    /** The requested write or protection transition failed. Written bytes are
     *  intentionally NOT rolled back (the library has no caller-supplied
     *  original-byte backup); protection state IS rolled back. */
    WriteMemoryFailed = 0,
    /** The requested operation and cleanup completed successfully. */
    Success = 1
};

/**
 * @enum e_VirtualProtectMode
 * @brief Controls temporary page-protection changes.
 *
 * Semantics are identical for the local-process and remote-process overloads:
 * - DontChange:    the library never calls VirtualProtect(Ex).
 * - SafelyChange:  committed non-guarded regions are temporarily adjusted;
 *                  any region carrying PAGE_GUARD causes the call to fail
 *                  with the guard modifier left untouched.
 * - ForceChange:   committed guarded regions are also temporarily adjusted
 *                  (the PAGE_GUARD modifier is stripped for the operation and
 *                  re-applied on restoration).
 */
enum class e_VirtualProtectMode : std::uint8_t {
    /** Leave the existing page protection unchanged.
     *  - Local overloads: the raw copy runs against the pages as-is; writing
     *    to a non-writable page therefore raises an access violation in the
     *    caller's own process. Only use DontChange on memory you know is
     *    already accessible for the operation.
     *  - Remote overloads: the operation is delegated to
     *    WriteProcessMemory/ReadProcessMemory, which may internally manage
     *    page protection on the caller's behalf. Microsoft documents this
     *    behavior as "a courtesy, not a contractual obligation" (Raymond
     *    Chen, The Old New Thing); it is NOT guaranteed. Use SafelyChange or
     *    ForceChange when patching protected pages must be guaranteed to
     *    succeed. */
    DontChange,
    /** Change normal committed pages, but reject PAGE_GUARD regions. */
    SafelyChange,
    /** Allow temporary changes to committed guarded pages and restore them
     *  later (including the PAGE_GUARD modifier itself). */
    ForceChange
};

/**
 * @brief Finds a process ID by case-insensitive executable filename.
 * @param processName Executable filename, not a full path. Matched against
 *        the snapshot's executable names (szExeFile) without path
 *        components. Interpreted using the system ANSI code page.
 * @return Matching process ID, or 0 when no match/snapshot failure occurs.
 * @note If several processes carry the same executable name, the first match
 *       in snapshot order wins. Pass nullptr or an empty string to get 0.
 */
DWORD FindProcessId(const char* processName);

/**
 * @brief Gets the executable module base address and image size from a process handle.
 *
 * The main executable is identified by matching each enumerated module's full
 * path (GetModuleFileNameEx) against the process executable path
 * (GetModuleFileNameEx with hModule = NULL). If paths cannot be queried with
 * the handle's access rights, the first enumerated module is used as a
 * fallback (a stable de-facto behavior, not a documented contract).
 *
 * @param processHandle Open process handle. The remote path requires
 *        PROCESS_QUERY_INFORMATION and PROCESS_VM_READ rights; a
 *        pseudo-handle from GetCurrentProcess() is always accepted.
 * @param[out] outBase Receives the module base when non-null.
 * @return Image size in bytes, or 0 on failure.
 */
DWORD GetModuleBase(HANDLE processHandle, uintptr_t* const outBase);

/**
 * @brief Gets a named module's base address and image size by process ID.
 *
 * Uses a ToolHelp module snapshot with TH32CS_SNAPMODULE |
 * TH32CS_SNAPMODULE32. ERROR_BAD_LENGTH failures are retried as documented
 * by Microsoft. The module list can legitimately fail or return incomplete
 * information while the target loads/unloads DLLs; callers should treat a
 * 0 result as retryable.
 *
 * @param pid Target process identifier.
 * @param moduleName Module filename to find (e.g. "kernel32.dll"), matched
 *        case-insensitively against module snapshot names. Interpreted using
 *        the system ANSI code page.
 * @param[out] outBase Receives the module base when non-null.
 * @return Image size in bytes, or 0 when the module is not found.
 */
DWORD GetModuleBase(DWORD pid, const char* moduleName, uintptr_t* const outBase);

/**
 * @brief Iterates over successfully readable bytes in a module-relative range.
 *
 * The callback receives the byte's offset from moduleBase. Returning true
 * stops the scan immediately.
 *
 * Region handling inside the requested range:
 * - Free or uncommitted (State != MEM_COMMIT) regions are skipped.
 * - Regions carrying the PAGE_GUARD modifier are skipped.
 * - Readable committed regions are read with ReadProcessMemory.
 * - Committed non-guarded regions whose protection does not permit reads
 *   (e.g. PAGE_NOACCESS or PAGE_EXECUTE) are TEMPORARILY made readable in
 *   the target process: VirtualProtectEx flips them to the nearest readable
 *   protection (executable regions keep their execute intent), each flip is
 *   restored before the affected bytes are delivered to the callback, and
 *   the restore is best-effort. Use this function accordingly on
 *   anti-cheat-sensitive targets where temporary protection flips are
 *   unacceptable.
 *
 * Chunks of at most 64 KiB are read per VirtualQueryEx region. When a chunk
 * read transfers only part of the requested bytes, the transferred prefix is
 * still delivered. The callback never observes raised page protections.
 *
 * @param processInfo Scan configuration and target process handle. May be
 *        null (no-op). moduleBase and moduleSize must be non-zero.
 * @param callbackData Opaque caller-owned state passed to callback.
 * @param callback Callback invoked for each successfully read byte. May be
 *        null (no-op).
 */
void ForEachScanProcess(
    t_ProcessInfo* const processInfo,
    void* const callbackData,
    bool(*callback)(void* callbackData, size_t byteIndex, uint8_t& byte)
);

/**
 * @brief Fills memory in the current process with 0x90 NOP bytes.
 * @param target Destination address in the current process.
 * @param patchSize Number of bytes to fill. Zero is a successful no-op
 *        (checked before the target pointer is validated).
 * @param virtualProtectMode Protection policy used before writing.
 *        Defaults to DontChange: the caller is responsible for the target
 *        being writable, otherwise the copy raises an access violation.
 * @param flushInstructionCache Whether to flush the current-process instruction cache.
 * @return Operation status. Byte contents are not rolled back on failure;
 *         protection state is.
 */
e_WriteStatus FillWithNOPs(
    LPVOID target,
    SIZE_T patchSize,
    e_VirtualProtectMode virtualProtectMode = e_VirtualProtectMode::DontChange,
    bool flushInstructionCache = true);

/**
 * @brief Fills memory in another process with 0x90 NOP bytes.
 * @param processHandle Target process handle (nullptr and
 *        INVALID_HANDLE_VALUE are rejected).
 * @param target Destination address in the target process.
 * @param patchSize Number of bytes to fill. Zero is a successful no-op
 *        (validated after the handle, see below).
 * @param virtualProtectMode Protection policy used before writing.
 *        Defaults to SafelyChange so guarded pages are not disturbed.
 * @param flushInstructionCache Whether to flush the target instruction cache.
 * @return Operation status.
 * @note Validation order: the process handle is validated first; a zero-size
 *       request with an invalid handle therefore reports WriteMemoryFailed,
 *       while a zero-size request with a valid handle reports Success.
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
 * @param source Source buffer. May overlap destination (memmove semantics).
 * @param size Number of bytes to write. Zero is a successful no-op (checked
 *        before the pointers are validated).
 * @param virtualProtectMode Protection policy.
 * @param flushInstructionCache Whether to flush the instruction cache.
 * @return Operation status. On failure, already-written bytes are NOT rolled
 *         back; temporary protection changes are.
 * @note Validation order: size is checked before destination/source, so a
 *       zero-size request succeeds even with null pointers.
 */
e_WriteStatus WriteMemory(
    LPVOID destination,
    LPCVOID source,
    SIZE_T size,
    e_VirtualProtectMode virtualProtectMode = e_VirtualProtectMode::DontChange,
    bool flushInstructionCache = true);

/**
 * @brief Writes bytes into another process.
 * @param processHandle Target process handle (nullptr and
 *        INVALID_HANDLE_VALUE are rejected).
 * @param remoteDestination Destination address in the target process.
 * @param localSource Source buffer in the caller's process.
 * @param size Number of bytes to write. Zero is a successful no-op.
 * @param virtualProtectMode Protection policy.
 * @param flushInstructionCache Whether to flush the target instruction cache.
 * @return Operation status. On failure, already-written bytes are NOT rolled
 *         back; temporary protection changes are.
 * @note Validation order: the process handle is validated first; a zero-size
 *       request with an invalid handle therefore reports WriteMemoryFailed,
 *       while a zero-size request with a valid handle reports Success.
 * @note With DontChange, protection management is delegated to
 *       WriteProcessMemory, whose internal protection handling is not
 *       contractually guaranteed (see e_VirtualProtectMode::DontChange).
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
 * @param destination Local destination buffer. May overlap source (memmove
 *        semantics).
 * @param source Source address.
 * @param size Number of bytes to read. Zero is a successful no-op (checked
 *        before the pointers are validated).
 * @param virtualProtectMode Protection policy for the source.
 * @return true when all bytes are copied and cleanup succeeds.
 * @note Validation order: size is checked before destination/source, so a
 *       zero-size request succeeds even with null pointers.
 */
bool ReadMemory(
    LPVOID destination,
    LPCVOID source,
    SIZE_T size,
    e_VirtualProtectMode virtualProtectMode = e_VirtualProtectMode::DontChange);

/**
 * @brief Reads bytes from another process.
 * @param processHandle Target process handle (nullptr and
 *        INVALID_HANDLE_VALUE are rejected).
 * @param localDestination Destination buffer in the caller's process.
 * @param remoteSource Source address in the target process.
 * @param size Number of bytes to read. Zero is a successful no-op.
 * @param virtualProtectMode Protection policy for the source.
 * @return true only when all bytes are read and cleanup succeeds.
 * @note Validation order: the process handle is validated first; a zero-size
 *       request with an invalid handle therefore reports false, while a
 *       zero-size request with a valid handle reports true.
 */
bool ReadMemory(
    HANDLE processHandle,
    LPVOID localDestination,
    LPCVOID remoteSource,
    SIZE_T size,
    e_VirtualProtectMode virtualProtectMode = e_VirtualProtectMode::SafelyChange);

} // namespace WinProcHandling
