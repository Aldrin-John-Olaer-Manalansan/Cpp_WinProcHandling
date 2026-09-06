/*
 * @File: UnitTests.cpp
 * @Author: Aldrin John O. Manalansan (ajom)
 * @Email: aldrinjohnolaermanalansan@gmail.com
 * @LastUpdate: September 6, 2026
 * @Brief: Catch2 v3 test suite for WinProcHandling (public API + TESTABLE_STATIC internals).
 *
 * Remote tests target Battle_Realms_F.exe when it is running and are reported
 * as SKIPPED (not failed) on machines where the game is absent, per the
 * Catch2 documented SKIP() mechanism. Remote tests allocate temporary memory
 * inside that process rather than modifying arbitrary game instructions.
 * Every test restores bytes/protections it changes before returning.
 *
 * Tests tagged [local] run on any Windows machine without the game.
 *
 * TESTABLE_STATIC INTERNALS
 * -------------------------
 * WinProcHandling.cpp marks its file-local helpers with TESTABLE_STATIC, which
 * expands to `static` in production builds and to nothing when IS_TESTING is
 * defined. This file defines IS_TESTING and unity-includes WinProcHandling.cpp
 * so every internal helper gains external linkage inside this test binary.
 *
 * Build recipe for the test binary:
 *   - Compile UnitTests.cpp (this file) as ONE translation unit together with
 *     Catch2 v3 (prebuilt library or amalgamated main).
 *   - Do NOT additionally compile/link WinProcHandling.cpp into the same test
 *     binary: it is already compiled here, and a second copy would produce
 *     duplicate external symbols for the public functions.
 *   - Production builds are unaffected: compile WinProcHandling.cpp on its own
 *     without IS_TESTING and every internal helper remains static.
 *
 * BOUNDARY CHECKING (protection- and byte-modifying operations)
 * -------------------------------------------------------------
 * Every test that changes process state (page protection or memory bytes)
 * uses the BoundaryGuard helper. The guard snapshots the boundary window
 *     [modifiedOffset - modifiedSize, modifiedOffset + 2 * modifiedSize]
 * (page-aligned outward) BEFORE the modification: per-page state, protection
 * (including PAGE_GUARD / cache modifiers) and content bytes where the pages
 * are readable. Three-phase verification:
 *   Phase 2 (during the change): pages intersecting the modified scope hold
 *     the expected new protection/bytes; every other page inside the window
 *     is untouched.
 *   Phase 3 (after restoration): every page inside the window is again
 *     state-, protection- and byte-identical to the original snapshot.
 * Windows for byte-sized modifications use in-page offsets so the whole
 * formula window always lies inside memory the test itself allocated.
 *
 * Copyright (C) 2026  Aldrin John O. Manalansan  <aldrinjohnolaermanalansan@gmail.com>
 *
 * This Source Code is served under Open-Source AJOM License
 * You should have received a copy of License_OS-AJOM
 * along with this source code. If not, see:
 * <https://raw.githubusercontent.com/Aldrin-John-Olaer-Manalansan/AJOM_License/refs/heads/main/LICENSE_AJOM-OS>
 */

#include <catch2/catch_test_macros.hpp>

#ifndef IS_TESTING
#define IS_TESTING
#endif

// Unity include: compiles the library with IS_TESTING so TESTABLE_STATIC
// internals become reachable from the test cases below. See build recipe
// in the header comment. This replaces the previous header-only include.
#include "WinProcHandling.cpp"

#include <windows.h>
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <functional>
#include <limits>
#include <string>
#include <type_traits>

namespace {

constexpr const char* kTargetProcessName = "Battle_Realms_F.exe";

/** @brief Standard skip message for tests that require the live game target. */
const char* const kSkipMessage =
    "Battle_Realms_F.exe is not running; this remote integration test requires "
    "the live target process and was skipped instead of failing.";

/**
 * @struct ProcessFixture
 * @brief RAII owner of the handle opened for Battle_Realms_F.exe.
 */
struct ProcessFixture {
    /** Process identifier returned by FindProcessId. */
    DWORD pid{};
    /** Open handle used by remote Win32 operations. */
    HANDLE process{};

    ProcessFixture() {
        pid = WinProcHandling::FindProcessId(kTargetProcessName);
        if (pid != 0) {
            process = OpenProcess(
                PROCESS_QUERY_INFORMATION |
                PROCESS_VM_READ |
                PROCESS_VM_WRITE |
                PROCESS_VM_OPERATION,
                FALSE,
                pid);
        }
        if (!available()) {
            // Distinguish the two failure shapes for diagnostics.
            if (pid == 0) {
                WARN("ProcessFixture: " << kTargetProcessName << " was not found.");
            } else {
                WARN("ProcessFixture: OpenProcess(" << kTargetProcessName << ") failed; test will skip.");
            }
        }
    }

    ~ProcessFixture() {
        if (process)
            CloseHandle(process);
    }

    bool available() const {
        return pid != 0 && process != nullptr;
    }
};

/**
 * @struct RemoteAllocation
 * @brief RAII wrapper for temporary memory allocated inside the target process.
 */
struct RemoteAllocation {
    /** Target process handle. */
    HANDLE process{};
    /** Base address returned by VirtualAllocEx. */
    void* address{};
    /** Number of bytes allocated. */
    SIZE_T size{};

    RemoteAllocation(HANDLE processHandle, SIZE_T allocationSize, DWORD protection)
        : process(processHandle), size(allocationSize)
    {
        address = VirtualAllocEx(
            process, nullptr, size,
            MEM_RESERVE | MEM_COMMIT, protection);
    }

    ~RemoteAllocation() {
        if (address)
            VirtualFreeEx(process, address, 0, MEM_RELEASE);
    }

    explicit operator bool() const { return address != nullptr; }
};

/**
 * @struct LocalAllocation
 * @brief RAII wrapper for temporary local virtual memory.
 */
struct LocalAllocation {
    void* address{};
    SIZE_T size{};

    LocalAllocation(SIZE_T allocationSize, DWORD protection)
        : size(allocationSize)
    {
        address = VirtualAlloc(
            nullptr, size,
            MEM_RESERVE | MEM_COMMIT, protection);
    }

    ~LocalAllocation() {
        if (address)
            VirtualFree(address, 0, MEM_RELEASE);
    }

    explicit operator bool() const { return address != nullptr; }
};

/** @brief Reads the current protection value of a remote address. */
static DWORD QueryProtection(HANDLE process, const void* address) {
    MEMORY_BASIC_INFORMATION mbi{};
    REQUIRE(VirtualQueryEx(
        process, address, &mbi, sizeof(mbi)) == sizeof(mbi));
    return mbi.Protect;
}

/** @brief Reads the current protection value of a local address. */
static DWORD QueryProtectionLocal(const void* address) {
    MEMORY_BASIC_INFORMATION mbi{};
    REQUIRE(VirtualQuery(
        address, &mbi, sizeof(mbi)) == sizeof(mbi));
    return mbi.Protect;
}

/**
 * @brief Creates a deterministically invalid process handle.
 *
 * Opens a real handle to the current process and closes it, returning the
 * stale value. Unlike (HANDLE)-1 — which is the VALID current-process pseudo
 * handle — a closed handle value is genuinely invalid for the next API call;
 * no handle is opened in between, so the value cannot be recycled.
 */
static HANDLE MakeStaleProcessHandle() {
    HANDLE stale = OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId());
    REQUIRE(stale != nullptr);
    REQUIRE(CloseHandle(stale));
    return stale;
}

/**
 * @brief Verifies that the page following a test allocation is not committed.
 *
 * Kept for ad-hoc diagnostics; the boundary suites build their own
 * committed/uncommitted layouts instead of relying on ambient address-space
 * state, so no current test calls this helper.
 */
[[maybe_unused]] static bool RegionBeyondAllocationIsUncommitted(
    HANDLE process, const void* allocationBase, SIZE_T allocationSize)
{
    const auto nextAddress =
        static_cast<const std::uint8_t*>(allocationBase) + allocationSize;

    MEMORY_BASIC_INFORMATION mbi{};
    REQUIRE(VirtualQueryEx(
        process, nextAddress, &mbi, sizeof(mbi)) == sizeof(mbi));
    return mbi.State != MEM_COMMIT;
}

// ---------------------------------------------------------------------------
// TESTABLE_STATIC internal helpers, exposed through the unity include above.
// ---------------------------------------------------------------------------
using WinProcHandling::BaseProtection;
using WinProcHandling::IsReadableProtection;
using WinProcHandling::IsWritableProtection;
using WinProcHandling::IsExecutableProtection;
using WinProcHandling::WritableProtection;
using WinProcHandling::ReadableProtection;
using WinProcHandling::MakeRangeAccessible;
using WinProcHandling::RestoreLocal;
using WinProcHandling::RestoreRemote;
using WinProcHandling::MakeLocalWritable;
using WinProcHandling::MakeRemoteWritable;
using WinProcHandling::MakeLocalReadable;
using WinProcHandling::MakeRemoteReadable;
using WinProcHandling::IsValidProcessHandle;
using WinProcHandling::ConvertAnsiToWideName;
using WinProcHandling::PageProtectEntry;

/** @brief Runtime page size of the machine the suite runs on. */
std::uint32_t SystemPageSize() {
    static const std::uint32_t pageSize = [] {
        SYSTEM_INFO systemInfo{};
        GetSystemInfo(&systemInfo);
        return systemInfo.dwPageSize;
    }();
    return pageSize;
}

/**
 * @struct ReservedRange
 * @brief RAII owner of a reserved virtual-memory range that can be committed
 *        and decommitted in page-granular sub-ranges.
 *
 * Multi-region layouts (two committed sub-ranges with different protections,
 * committed pages separated by an uncommitted hole) are required to exercise
 * the region-walking logic of MakeRangeAccessible and the MakeLocal and
 * MakeRemote helper families are exercised against the real memory manager.
 */
struct ReservedRange {
    void* base{};
    SIZE_T size{};

    explicit ReservedRange(SIZE_T pageCount)
        : size(static_cast<SIZE_T>(pageCount) * SystemPageSize())
    {
        base = VirtualAlloc(nullptr, size, MEM_RESERVE, PAGE_NOACCESS);
    }

    ~ReservedRange() {
        if (base)
            VirtualFree(base, 0, MEM_RELEASE);
    }

    ReservedRange(const ReservedRange&) = delete;
    ReservedRange& operator=(const ReservedRange&) = delete;

    explicit operator bool() const { return base != nullptr; }

    /** @brief Address of the zero-based page inside the reserved range. */
    void* Page(size_t pageIndex) const {
        return static_cast<std::uint8_t*>(base) +
               static_cast<uintptr_t>(pageIndex) * SystemPageSize();
    }

    /** @brief Commits a page range with the requested protection. */
    bool CommitRange(size_t firstPage, SIZE_T pageCount, DWORD protection) const {
        return VirtualAlloc(
                   Page(firstPage),
                   pageCount * SystemPageSize(),
                   MEM_COMMIT,
                   protection) != nullptr;
    }

    /** @brief Decommits a page range, turning it back into reserved memory. */
    bool DecommitRange(size_t firstPage, SIZE_T pageCount) const {
        return VirtualFree(
                   Page(firstPage),
                   pageCount * SystemPageSize(),
                   MEM_DECOMMIT) != 0;
    }
};

/**
 * @struct BoundaryPageSnapshot
 * @brief One page's state inside a boundary window, captured at a point in time.
 */
struct BoundaryPageSnapshot {
    /** Page base address (always page-aligned). */
    uintptr_t base{};
    /** Recorded page size. */
    SIZE_T size{};
    /** MEMORY_BASIC_INFORMATION::State for the page. */
    DWORD state{};
    /** MEMORY_BASIC_INFORMATION::Protect, including PAGE_GUARD / cache modifiers. */
    DWORD protect{};
    /** Whether content bytes could be captured (committed, readable pages only). */
    bool contentCaptured{};
    /** Page contents when captured; empty otherwise. */
    std::vector<std::uint8_t> content;
};

/**
 * @struct BoundaryGuard
 * @brief Records and verifies the boundary window around a modification.
 *
 * The window spans [modifiedOffset - modifiedSize, modifiedOffset + 2 *
 * modifiedSize], page-aligned outward, and must lie inside memory the test
 * allocated. The guard snapshots every page of the window (state, protection
 * including modifier flags, and content bytes where the page is readable)
 * before the modification, then verifies:
 *
 *   - RequireScopeProtection: pages intersecting the modified scope carry the
 *     expected protection (a fixed value or a per-page callable mirroring the
 *     library's Writable/ReadableProtection mapping).
 *   - RequireWindowOutsideScopeUnchanged: pages outside the modified scope are
 *     state/protection/byte-identical.
 *   - RequireScopeBytesUnchanged: every captured page (scope included) still
 *     holds its original bytes; for protection-only operations.
 *   - RequireWindowBytesMatchImage: the captured window equals a caller-built
 *     expected byte image; for byte-modifying operations.
 *   - RequireWindowRestored: the entire window is state-, protection- and
 *     byte-identical to the original snapshot (restoration correctness).
 *
 * Pages that are not readable (PAGE_NOACCESS, PAGE_GUARD, reserved) are
 * tracked by state/protection only; their contents are never dereferenced,
 * which would either fault or clear a guard page.
 */
struct BoundaryGuard {
    /** Target process; nullptr means the current process. */
    HANDLE processHandle{};
    /** First page of the boundary window. */
    uintptr_t windowStart{};
    /** One past the last page of the boundary window. */
    uintptr_t windowEnd{};
    /** First modified byte. */
    uintptr_t scopeStart{};
    /** One past the last modified byte. */
    uintptr_t scopeEnd{};
    /** Pre-modification snapshot of every window page. */
    std::vector<BoundaryPageSnapshot> snapshot;

    /**
     * @brief Validates the layout, then snapshots the boundary window.
     *
     * @param targetProcess   Target process or nullptr for the current process.
     * @param allocationBase  Base of the memory the test allocated.
     * @param allocationSize  Size of that allocation.
     * @param modifiedAddress First byte the tested operation is expected to change.
     * @param modifiedSize    Number of bytes the tested operation is expected to change.
     */
    BoundaryGuard(HANDLE targetProcess,
                  const void* allocationBase,
                  SIZE_T allocationSize,
                  const void* modifiedAddress,
                  SIZE_T modifiedSize)
        : processHandle(targetProcess),
          scopeStart(reinterpret_cast<uintptr_t>(modifiedAddress)),
          scopeEnd(scopeStart + modifiedSize)
    {
        const uintptr_t pageSize = SystemPageSize();
        const uintptr_t allocationStart = reinterpret_cast<uintptr_t>(allocationBase);
        const uintptr_t allocationEnd = allocationStart + allocationSize;

        REQUIRE(modifiedSize > 0);
        REQUIRE(scopeStart >= modifiedSize); // the formula must not underflow

        // Documented boundary formula, page-aligned outward.
        const uintptr_t rawWindowStart = scopeStart - modifiedSize;
        const uintptr_t rawWindowEnd = scopeStart + 2 * modifiedSize;
        windowStart = rawWindowStart - (rawWindowStart % pageSize);
        windowEnd = rawWindowEnd + ((pageSize - (rawWindowEnd % pageSize)) % pageSize);

        INFO("Boundary window: 0x" << std::hex << windowStart
                                   << " .. 0x" << windowEnd
                                   << " (scope 0x" << scopeStart
                                   << " .. 0x" << scopeEnd << ")");
        REQUIRE(windowStart >= allocationStart);
        REQUIRE(windowEnd <= allocationEnd);

        Capture(snapshot);
    }

    /** @brief Snapshots the current state of every page inside the window. */
    void Capture(std::vector<BoundaryPageSnapshot>& out) const {
        out.clear();
        const uintptr_t pageSize = SystemPageSize();

        for (uintptr_t page = windowStart; page < windowEnd; page += pageSize) {
            MEMORY_BASIC_INFORMATION mbi{};
            SIZE_T queried = 0;
            if (processHandle)
                queried = VirtualQueryEx(
                    processHandle,
                    reinterpret_cast<LPCVOID>(page),
                    &mbi,
                    sizeof(mbi));
            else
                queried = VirtualQuery(
                    reinterpret_cast<LPCVOID>(page),
                    &mbi,
                    sizeof(mbi));
            REQUIRE(queried == sizeof(mbi));

            BoundaryPageSnapshot record;
            record.base = page;
            record.size = pageSize;
            record.state = mbi.State;
            record.protect = mbi.Protect;

            // x86/x64 hardware has no execute-only page bit: Windows may
            // DOCUMENT PAGE_EXECUTE as unreadable, but the CPU cannot enforce
            // that (reads succeed — the documented access violation is not
            // implementable in the page tables). Capture therefore tracks what
            // the process can ACTUALLY read; using the documented readability
            // class here would flip capture state when an operation transitions
            // e.g. PAGE_EXECUTE -> PAGE_EXECUTE_READWRITE and break the byte
            // comparisons. Guard pages stay excluded (reading one would
            // consume PAGE_GUARD), as do non-committed and PAGE_NOACCESS pages.
            const bool readable =
                mbi.State == MEM_COMMIT &&
                (mbi.Protect & PAGE_GUARD) == 0 &&
                BaseProtection(mbi.Protect) != PAGE_NOACCESS;

            if (readable) {
                record.content.assign(pageSize, 0);
                bool captured = false;
                if (processHandle) {
                    SIZE_T bytesRead = 0;
                    captured =
                        ReadProcessMemory(
                            processHandle,
                            reinterpret_cast<LPCVOID>(page),
                            record.content.data(),
                            pageSize,
                            &bytesRead) != 0 &&
                        bytesRead == pageSize;
                } else {
                    std::memcpy(
                        record.content.data(),
                        reinterpret_cast<const void*>(page),
                        pageSize);
                    captured = true;
                }
                // A readable page inside a controlled test window must be capturable.
                REQUIRE(captured);
                record.contentCaptured = true;
            }

            out.push_back(std::move(record));
        }
    }

    /** @brief True when the recorded page intersects the modified byte scope. */
    bool RecordIntersectsScope(const BoundaryPageSnapshot& record) const {
        return record.base < scopeEnd && (record.base + record.size) > scopeStart;
    }

    /**
     * @brief Phase 2: scope pages carry one fixed expected protection.
     *
     * Bare protection constants (e.g. `guard.RequireScopeProtection(PAGE_READWRITE)`)
     * intentionally resolve here. The Windows SDK defines those constants as int
     * macros, so this non-template overload must stay reachable for them; the
     * template overload below is constrained to invocables to guarantee that.
     */
    void RequireScopeProtection(DWORD expectedProtect) const {
        RequireScopeProtection(
            [expectedProtect](DWORD) { return expectedProtect; });
    }

    /**
     * @brief Phase 2: scope pages carry the protection a mapping function predicts.
     *
     * The callable receives the page's original snapshot protection so tests can
     * mirror WritableProtection/ReadableProtection for mixed-protection layouts
     * (e.g. passing the WritableProtection function itself).
     *
     * Constrained with is_invocable so only true callables match. Without the
     * constraint this forwarding-reference overload would hijack plain int
     * arguments on MSVC/MinGW (identity binding of an int prvalue beats the
     * int-to-DWORD conversion of the DWORD overload) and then fail to compile
     * by invoking a non-function. Verified against MinGW-w64 GCC; the same
     * resolution rules apply to MSVC.
     */
    template <typename ExpectedFn>
        requires std::is_invocable_v<ExpectedFn&, DWORD>
    void RequireScopeProtection(ExpectedFn&& expectedProtection) const {
        std::vector<BoundaryPageSnapshot> current;
        Capture(current);
        REQUIRE(current.size() == snapshot.size());

        for (size_t index = 0; index < snapshot.size(); ++index) {
            if (!RecordIntersectsScope(snapshot[index]))
                continue;
            INFO("Scope page at 0x" << std::hex << snapshot[index].base);
            REQUIRE(current[index].protect ==
                    expectedProtection(snapshot[index].protect));
        }
    }

    /**
     * @brief Phase 2: pages outside the modified scope are untouched.
     *
     * Comparison covers state, full protection value (guard/cache flags
     * included) and captured content bytes.
     */
    void RequireWindowOutsideScopeUnchanged() const {
        std::vector<BoundaryPageSnapshot> current;
        Capture(current);
        REQUIRE(current.size() == snapshot.size());

        for (size_t index = 0; index < snapshot.size(); ++index) {
            if (RecordIntersectsScope(snapshot[index]))
                continue;
            INFO("Outside-scope page at 0x" << std::hex << snapshot[index].base);
            REQUIRE(current[index].state == snapshot[index].state);
            REQUIRE(current[index].protect == snapshot[index].protect);
            REQUIRE(current[index].contentCaptured == snapshot[index].contentCaptured);
            if (snapshot[index].contentCaptured)
                REQUIRE(current[index].content == snapshot[index].content);
        }
    }

    /**
     * @brief Phase 2: every page readable at snapshot time still holds its
     *        original bytes; used for protection-only operations.
     */
    void RequireScopeBytesUnchanged() const {
        std::vector<BoundaryPageSnapshot> current;
        Capture(current);
        REQUIRE(current.size() == snapshot.size());

        for (size_t index = 0; index < snapshot.size(); ++index) {
            INFO("Window page at 0x" << std::hex << snapshot[index].base);
            if (snapshot[index].contentCaptured) {
                // Readable before the operation: not a single byte may change
                // and the page must not have lost readability either.
                REQUIRE(current[index].contentCaptured);
                REQUIRE(current[index].content == snapshot[index].content);
            } else if (current[index].contentCaptured) {
                // Unreadable before the operation (e.g. PAGE_NOACCESS scope
                // pages the operation itself upgraded) but readable now:
                // protection-only changes cannot alter bytes, and there is no
                // pre-change image to compare against. Skipped by design.
                INFO("Page became readable only through the operation; no "
                     "pre-change image exists to compare");
            }
            // Unreadable in both phases: nothing to compare.
        }
    }

    /** @brief Flattens the pre-modification snapshot into one window image. */
    std::vector<std::uint8_t> OriginalWindowImage() const {
        std::vector<std::uint8_t> image(windowEnd - windowStart, 0);
        for (const BoundaryPageSnapshot& record : snapshot) {
            if (!record.contentCaptured)
                continue;
            const size_t offset = static_cast<size_t>(record.base - windowStart);
            std::memcpy(image.data() + offset, record.content.data(), record.content.size());
        }
        return image;
    }

    /** @brief Original window image with the modified scope replaced by new data. */
    std::vector<std::uint8_t> ExpectedImageWithScopeReplaced(
        const void* newData, SIZE_T dataSize) const
    {
        REQUIRE(dataSize == scopeEnd - scopeStart);
        std::vector<std::uint8_t> image = OriginalWindowImage();
        std::memcpy(
            image.data() + (scopeStart - windowStart),
            newData,
            dataSize);
        return image;
    }

    /**
     * @brief Phase 2: the current window equals the expected byte image.
     *
     * Only pages whose bytes are captured at comparison time participate;
     * pages that were unreadable before and after are skipped symmetrically.
     */
    void RequireWindowBytesMatchImage(const std::vector<std::uint8_t>& expectedImage) const {
        REQUIRE(expectedImage.size() == windowEnd - windowStart);
        std::vector<BoundaryPageSnapshot> current;
        Capture(current);
        REQUIRE(current.size() == snapshot.size());

        for (size_t index = 0; index < snapshot.size(); ++index) {
            if (!current[index].contentCaptured)
                continue;
            const size_t offset = static_cast<size_t>(snapshot[index].base - windowStart);
            INFO("Byte image page at 0x" << std::hex << snapshot[index].base);
            REQUIRE(std::memcmp(
                        current[index].content.data(),
                        expectedImage.data() + offset,
                        current[index].content.size()) == 0);
        }
    }

    /**
     * @brief Phase 2: every page's state and protection equal the snapshot.
     *
     * Used after byte-modifying operations whose protection changes the
     * library has already rolled back internally; byte contents are verified
     * separately by RequireWindowBytesMatchImage.
     */
    void RequireWindowProtectionRestored() const {
        std::vector<BoundaryPageSnapshot> current;
        Capture(current);
        REQUIRE(current.size() == snapshot.size());

        for (size_t index = 0; index < snapshot.size(); ++index) {
            INFO("Protection-restored window page at 0x" << std::hex
                                                          << snapshot[index].base);
            REQUIRE(current[index].state == snapshot[index].state);
            REQUIRE(current[index].protect == snapshot[index].protect);
        }
    }

    /**
     * @brief Phase 3: the whole window is identical to the pre-modification
     *        snapshot (state, protection, and bytes where captured).
     */
    void RequireWindowRestored() const {
        std::vector<BoundaryPageSnapshot> current;
        Capture(current);
        REQUIRE(current.size() == snapshot.size());

        for (size_t index = 0; index < snapshot.size(); ++index) {
            INFO("Restored window page at 0x" << std::hex << snapshot[index].base);
            REQUIRE(current[index].base == snapshot[index].base);
            REQUIRE(current[index].size == snapshot[index].size);
            REQUIRE(current[index].state == snapshot[index].state);
            REQUIRE(current[index].protect == snapshot[index].protect);
            REQUIRE(current[index].contentCaptured == snapshot[index].contentCaptured);
            if (snapshot[index].contentCaptured)
                REQUIRE(current[index].content == snapshot[index].content);
        }
    }
};

// ---------------------------------------------------------------------------
// Deterministic fake memory manager for MakeRangeAccessible failure injection.
// ---------------------------------------------------------------------------
namespace mock {

/** @brief One fake virtual-memory region served by FakeQuery. */
struct Region {
    uintptr_t base{};
    SIZE_T size{};
    DWORD state{MEM_COMMIT};
    DWORD protect{PAGE_READWRITE};
    /** Misreporting knobs (0 = disabled): exercise the walker's defensive
     *  checks while the query call itself succeeds. */
    uintptr_t reportBaseOverride{};
    SIZE_T reportSizeOverride{};
    /** Reports RegionSize = 0 regardless of size. */
    bool reportZeroSize{};
};

/** @brief Fake VirtualQuery/VirtualQueryEx backed by a scripted region table. */
struct FakeQuery {
    std::vector<Region> regions;
    /** Log of successfully queried addresses, in call order. */
    std::vector<uintptr_t> queriedAddresses;
    /** 1-based call index that must fail; 0 = never fail. */
    size_t failAtCall{};
    size_t calls{};

    SIZE_T operator()(LPCVOID address, PMEMORY_BASIC_INFORMATION mbi, SIZE_T) {
        ++calls;
        if (failAtCall != 0 && calls == failAtCall)
            return 0;

        const uintptr_t requested = reinterpret_cast<uintptr_t>(address);
        queriedAddresses.push_back(requested);

        for (const Region& region : regions) {
            if (requested >= region.base && requested < region.base + region.size) {
                const uintptr_t reportedBase =
                    region.reportBaseOverride != 0 ? region.reportBaseOverride : region.base;
                const SIZE_T reportedSize =
                    region.reportZeroSize ? 0
                        : (region.reportSizeOverride != 0 ? region.reportSizeOverride
                                                          : region.size);
                mbi->BaseAddress = reinterpret_cast<PVOID>(reportedBase);
                mbi->AllocationBase = mbi->BaseAddress;
                mbi->RegionSize = reportedSize;
                mbi->AllocationProtect = region.protect;
                mbi->State = region.state;
                mbi->Protect = region.protect;
                mbi->Type = MEM_PRIVATE;
                return sizeof(MEMORY_BASIC_INFORMATION);
            }
        }
        return 0;
    }
};

/** @brief Fake VirtualProtect/VirtualProtectEx recording every call. */
struct FakeProtect {
    struct Call {
        LPVOID base{};
        SIZE_T size{};
        DWORD newProtect{};
        /** Value the fake wrote through the caller's out-parameter. */
        DWORD outOldProtect{};
    };

    std::vector<Call> calls;
    /** 1-based call index that must fail; 0 = never fail. */
    size_t failAtCall{};

    BOOL operator()(LPVOID base, SIZE_T size, DWORD newProtect, PDWORD previousProtect) {
        if (failAtCall != 0 && calls.size() + 1 == failAtCall)
            return FALSE;
        // Distinctive marker: entries must record the protection reported by
        // the protection-changing call, not the value seen during the query.
        *previousProtect = 0x5A5A5A5Au;
        calls.push_back({base, size, newProtect, 0x5A5A5A5Au});
        return TRUE;
    }
};

/** @brief Mapping function that always requests PAGE_NOACCESS. */
inline DWORD MockForceNoAccess(DWORD) { return PAGE_NOACCESS; }

/** @brief Mapping function that never requests a change. */
inline DWORD MockIdentityProtection(DWORD protection) { return protection; }

} // namespace mock

using mock::MockForceNoAccess;
using mock::MockIdentityProtection;

} // namespace

/** @test Verifies the behavior described by the Catch2 test name. */
TEST_CASE("FindProcessId locates the exact target executable", "[process]") {
    ProcessFixture process;
    if (!process.available())
        SKIP(kSkipMessage);

    const DWORD pid = WinProcHandling::FindProcessId(kTargetProcessName);
    REQUIRE(pid == process.pid);
}

/** @test Verifies the behavior described by the Catch2 test name. */
TEST_CASE("GetModuleBase returns the target executable module", "[module]") {
    ProcessFixture process;
    if (!process.available())
        SKIP(kSkipMessage);

    uintptr_t base = 0;
    const DWORD size = WinProcHandling::GetModuleBase(process.process, &base);

    REQUIRE(size != 0);
    REQUIRE(base != 0);

    MEMORY_BASIC_INFORMATION mbi{};
    REQUIRE(VirtualQueryEx(
        process.process,
        reinterpret_cast<LPCVOID>(base),
        &mbi,
        sizeof(mbi)) == sizeof(mbi));
    CHECK(mbi.State == MEM_COMMIT);
}

/** @test Verifies the behavior described by the Catch2 test name. */
TEST_CASE("GetModuleBase by PID returns the target executable", "[module]") {
    ProcessFixture process;
    if (!process.available())
        SKIP(kSkipMessage);

    uintptr_t base = 0;
    const DWORD size =
        WinProcHandling::GetModuleBase(process.pid, kTargetProcessName, &base);

    REQUIRE(size != 0);
    REQUIRE(base != 0);
}

/** @test Verifies that a remote read-only region can be patched and its original protection restored. */
TEST_CASE("Remote WriteMemory writes and restores protection", "[remote][write]") {
    ProcessFixture process;
    if (!process.available())
        SKIP(kSkipMessage);

    constexpr SIZE_T allocationSize = 2 * 4096;
    constexpr SIZE_T patchSize = 16;

    // Allocate as writable so the test can initialize the original bytes.
    RemoteAllocation memory(
        process.process,
        allocationSize,
        PAGE_READWRITE);

    REQUIRE(memory);

    // The modified scope sits one page in so the boundary window
    // [scope - patchSize, scope + 2*patchSize] stays inside the allocation.
    const auto scopeAddress =
        static_cast<std::uint8_t*>(memory.address) + 4096;

    const std::array<std::uint8_t, patchSize> original{};
    const std::array<std::uint8_t, patchSize> replacement{
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
        0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0xFF
    };

    // Seed the original bytes while the allocation is writable.
    REQUIRE(WriteProcessMemory(
        process.process,
        scopeAddress,
        original.data(),
        original.size(),
        nullptr));

    // Establish the protection that WriteMemory() must temporarily change.
    DWORD previousProtection = 0;

    REQUIRE(VirtualProtectEx(
        process.process,
        memory.address,
        allocationSize,
        PAGE_READONLY,
        &previousProtection));

    const DWORD before =
        QueryProtection(process.process, memory.address);

    CHECK((before & 0xFFu) == PAGE_READONLY);

    // Boundary snapshot of [scope - patchSize, scope + 2*patchSize].
    BoundaryGuard guard(
        process.process, memory.address, allocationSize,
        scopeAddress, patchSize);

    CHECK(WinProcHandling::WriteMemory(
        process.process,
        scopeAddress,
        replacement.data(),
        replacement.size(),
        WinProcHandling::e_VirtualProtectMode::SafelyChange,
        true)
        == WinProcHandling::e_WriteStatus::Success);

    // Phase 2: scope bytes replaced; out-of-scope window bytes and every
    // window protection value (library already rolled its changes back).
    guard.RequireWindowBytesMatchImage(
        guard.ExpectedImageWithScopeReplaced(replacement.data(), replacement.size()));
    guard.RequireWindowOutsideScopeUnchanged();
    guard.RequireWindowProtectionRestored();

    std::array<std::uint8_t, patchSize> observed{};

    REQUIRE(ReadProcessMemory(
        process.process,
        scopeAddress,
        observed.data(),
        observed.size(),
        nullptr));

    CHECK(observed == replacement);

    // WriteMemory() must restore the protection that existed before the write.
    CHECK((QueryProtection(process.process, memory.address) & 0xFFu) ==
          (before & 0xFFu));

    // Restore the original bytes before fixture teardown.
    REQUIRE(WinProcHandling::WriteMemory(
        process.process,
        scopeAddress,
        original.data(),
        original.size(),
        WinProcHandling::e_VirtualProtectMode::SafelyChange,
        true)
        == WinProcHandling::e_WriteStatus::Success);

    // Phase 3: the window is byte- and protection-identical to the snapshot.
    guard.RequireWindowRestored();

    std::array<std::uint8_t, patchSize> restoredBytes{};

    REQUIRE(ReadProcessMemory(
        process.process,
        scopeAddress,
        restoredBytes.data(),
        restoredBytes.size(),
        nullptr));

    CHECK(restoredBytes == original);
}

/** @test Verifies that multiple remote writes to different regions independently preserve their protections. */
TEST_CASE("Remote WriteMemory works repeatedly on different regions", "[remote][write]") {
    ProcessFixture process;
    if (!process.available())
        SKIP(kSkipMessage);

    constexpr SIZE_T pageSize = 4096;
    constexpr SIZE_T patchSize = 16;
    // In-page scope offset keeps [scope - patchSize, scope + 2*patchSize]
    // inside each one-page allocation.
    constexpr SIZE_T scopeOffset = 256;

    RemoteAllocation firstRegion(
        process.process,
        pageSize,
        PAGE_READWRITE);

    RemoteAllocation secondRegion(
        process.process,
        pageSize,
        PAGE_EXECUTE_READWRITE);

    REQUIRE(firstRegion);
    REQUIRE(secondRegion);

    const auto firstScope =
        static_cast<std::uint8_t*>(firstRegion.address) + scopeOffset;
    const auto secondScope =
        static_cast<std::uint8_t*>(secondRegion.address) + scopeOffset;

    const std::array<std::uint8_t, patchSize> original{
        0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C,
        0x0D, 0x0E, 0x0F, 0x10
    };

    const std::array<std::uint8_t, patchSize> firstReplacement{
        0x11, 0x12, 0x13, 0x14,
        0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C,
        0x1D, 0x1E, 0x1F, 0x20
    };

    const std::array<std::uint8_t, patchSize> secondReplacement{
        0x21, 0x22, 0x23, 0x24,
        0x25, 0x26, 0x27, 0x28,
        0x29, 0x2A, 0x2B, 0x2C,
        0x2D, 0x2E, 0x2F, 0x30
    };

    // Seed both allocations while they are writable.
    REQUIRE(WriteProcessMemory(
        process.process,
        firstScope,
        original.data(),
        original.size(),
        nullptr));

    REQUIRE(WriteProcessMemory(
        process.process,
        secondScope,
        original.data(),
        original.size(),
        nullptr));

    // Establish the protections that each WriteMemory() call must temporarily modify.
    DWORD ignoredPreviousProtection = 0;

    REQUIRE(VirtualProtectEx(
        process.process,
        firstRegion.address,
        pageSize,
        PAGE_READONLY,
        &ignoredPreviousProtection));

    REQUIRE(VirtualProtectEx(
        process.process,
        secondRegion.address,
        pageSize,
        PAGE_EXECUTE_READ,
        &ignoredPreviousProtection));

    const DWORD firstProtection =
        QueryProtection(process.process, firstRegion.address);

    const DWORD secondProtection =
        QueryProtection(process.process, secondRegion.address);

    CHECK((firstProtection & 0xFFu) == PAGE_READONLY);
    CHECK((secondProtection & 0xFFu) == PAGE_EXECUTE_READ);

    // Boundary snapshots of both modification scopes.
    BoundaryGuard firstGuard(
        process.process, firstRegion.address, pageSize, firstScope, patchSize);
    BoundaryGuard secondGuard(
        process.process, secondRegion.address, pageSize, secondScope, patchSize);

    // First write.
    REQUIRE(WinProcHandling::WriteMemory(
        process.process,
        firstScope,
        firstReplacement.data(),
        firstReplacement.size(),
        WinProcHandling::e_VirtualProtectMode::SafelyChange,
        true)
        == WinProcHandling::e_WriteStatus::Success);

    // Phase 2 on the first region: bytes replaced, boundaries intact.
    firstGuard.RequireWindowBytesMatchImage(
        firstGuard.ExpectedImageWithScopeReplaced(
            firstReplacement.data(), firstReplacement.size()));
    firstGuard.RequireWindowOutsideScopeUnchanged();
    firstGuard.RequireWindowProtectionRestored();

    // Verify first region and its protection immediately after the operation.
    std::array<std::uint8_t, patchSize> firstObserved{};

    REQUIRE(ReadProcessMemory(
        process.process,
        firstScope,
        firstObserved.data(),
        firstObserved.size(),
        nullptr));

    CHECK(firstObserved == firstReplacement);

    CHECK((QueryProtection(process.process, firstRegion.address) & 0xFFu) ==
          (firstProtection & 0xFFu));

    // Second write.
    REQUIRE(WinProcHandling::WriteMemory(
        process.process,
        secondScope,
        secondReplacement.data(),
        secondReplacement.size(),
        WinProcHandling::e_VirtualProtectMode::SafelyChange,
        true)
        == WinProcHandling::e_WriteStatus::Success);

    // Phase 2 on the second region, and the first region must be unaffected.
    secondGuard.RequireWindowBytesMatchImage(
        secondGuard.ExpectedImageWithScopeReplaced(
            secondReplacement.data(), secondReplacement.size()));
    secondGuard.RequireWindowOutsideScopeUnchanged();
    secondGuard.RequireWindowProtectionRestored();

    firstGuard.RequireWindowBytesMatchImage(
        firstGuard.ExpectedImageWithScopeReplaced(
            firstReplacement.data(), firstReplacement.size()));
    firstGuard.RequireWindowProtectionRestored();

    // Verify second region and its protection immediately after the operation.
    std::array<std::uint8_t, patchSize> secondObserved{};

    REQUIRE(ReadProcessMemory(
        process.process,
        secondScope,
        secondObserved.data(),
        secondObserved.size(),
        nullptr));

    CHECK(secondObserved == secondReplacement);

    CHECK((QueryProtection(process.process, secondRegion.address) & 0xFFu) ==
          (secondProtection & 0xFFu));

    // Repeat the operations in the opposite order.
    REQUIRE(WinProcHandling::WriteMemory(
        process.process,
        secondScope,
        original.data(),
        original.size(),
        WinProcHandling::e_VirtualProtectMode::SafelyChange,
        true)
        == WinProcHandling::e_WriteStatus::Success);

    REQUIRE(WinProcHandling::WriteMemory(
        process.process,
        firstScope,
        original.data(),
        original.size(),
        WinProcHandling::e_VirtualProtectMode::SafelyChange,
        true)
        == WinProcHandling::e_WriteStatus::Success);

    // Phase 3: both windows are byte- and protection-identical to their snapshots.
    firstGuard.RequireWindowRestored();
    secondGuard.RequireWindowRestored();

    // Verify both regions were restored to their original bytes.
    firstObserved.fill(0);

    REQUIRE(ReadProcessMemory(
        process.process,
        firstScope,
        firstObserved.data(),
        firstObserved.size(),
        nullptr));

    CHECK(firstObserved == original);

    secondObserved.fill(0);

    REQUIRE(ReadProcessMemory(
        process.process,
        secondScope,
        secondObserved.data(),
        secondObserved.size(),
        nullptr));

    CHECK(secondObserved == original);

    // Verify that both original protections were preserved.
    CHECK((QueryProtection(process.process, firstRegion.address) & 0xFFu) ==
          (firstProtection & 0xFFu));

    CHECK((QueryProtection(process.process, secondRegion.address) & 0xFFu) ==
          (secondProtection & 0xFFu));
}

/** @test Verifies remote FillWithNOPs writes exact NOP bytes and restores protection. */
TEST_CASE("Remote FillWithNOPs writes exact NOP bytes and restores protection", "[remote][nop]") {
    ProcessFixture process;
    if (!process.available())
        SKIP(kSkipMessage);

    RemoteAllocation memory(process.process, 4096, PAGE_EXECUTE_READ);
    REQUIRE(memory);

    constexpr SIZE_T count = 32;
    // In-page scope offset keeps [scope - count, scope + 2*count] inside the page.
    constexpr SIZE_T scopeOffset = 128;
    const auto scopeAddress =
        static_cast<std::uint8_t*>(memory.address) + scopeOffset;

    std::array<std::uint8_t, count> original{};
    std::array<std::uint8_t, count> nops{};
    nops.fill(0x90);
    std::array<std::uint8_t, count> observed{};

    // Seed the original bytes through the library (the page is execute/read-only).
    REQUIRE(WinProcHandling::WriteMemory(
        process.process, scopeAddress, original.data(), original.size(),
        WinProcHandling::e_VirtualProtectMode::SafelyChange, true)
        == WinProcHandling::e_WriteStatus::Success);

    const DWORD before = QueryProtection(process.process, memory.address);

    BoundaryGuard guard(
        process.process, memory.address, 4096, scopeAddress, count);

    CHECK(WinProcHandling::FillWithNOPs(
        process.process, scopeAddress, count,
        WinProcHandling::e_VirtualProtectMode::SafelyChange, true)
        == WinProcHandling::e_WriteStatus::Success);

    // Phase 2: scope filled with NOPs, window boundaries and protection intact.
    guard.RequireWindowBytesMatchImage(
        guard.ExpectedImageWithScopeReplaced(nops.data(), nops.size()));
    guard.RequireWindowOutsideScopeUnchanged();
    guard.RequireWindowProtectionRestored();

    REQUIRE(ReadProcessMemory(
        process.process, scopeAddress, observed.data(), observed.size(), nullptr));

    CHECK(std::all_of(observed.begin(), observed.end(),
                      [](std::uint8_t byteValue) { return byteValue == 0x90; }));
    CHECK(QueryProtection(process.process, memory.address) == before);

    // Restore the original bytes.
    REQUIRE(WinProcHandling::WriteMemory(
        process.process, scopeAddress, original.data(), original.size(),
        WinProcHandling::e_VirtualProtectMode::SafelyChange, true)
        == WinProcHandling::e_WriteStatus::Success);

    // Phase 3: full restoration of the boundary window.
    guard.RequireWindowRestored();
}


/** @test Verifies that ForceChange can modify a guarded page and restore PAGE_GUARD afterward. */
TEST_CASE("Remote ForceChange can patch a guarded committed page and restores PAGE_GUARD",
          "[remote][write][guard]")
{
    ProcessFixture process;
    if (!process.available())
        SKIP(kSkipMessage);

    constexpr SIZE_T pageSize = 4096;
    constexpr SIZE_T patchSize = 8;
    // In-page scope offset keeps [scope - patchSize, scope + 2*patchSize] inside the page.
    constexpr SIZE_T scopeOffset = 128;

    // Allocate as writable so the test can initialize the original bytes.
    RemoteAllocation memory(
        process.process,
        pageSize,
        PAGE_READWRITE);

    REQUIRE(memory);

    const auto scopeAddress =
        static_cast<std::uint8_t*>(memory.address) + scopeOffset;

    const std::array<std::uint8_t, patchSize> original{
        0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08
    };

    const std::array<std::uint8_t, patchSize> replacement{
        0x90, 0x90, 0x90, 0x90,
        0x90, 0x90, 0x90, 0x90
    };

    // Seed the original bytes while the page is writable.
    REQUIRE(WriteProcessMemory(
        process.process,
        scopeAddress,
        original.data(),
        original.size(),
        nullptr));

    // Establish PAGE_READONLY | PAGE_GUARD as the initial protection.
    DWORD previousProtection = 0;

    REQUIRE(VirtualProtectEx(
        process.process,
        memory.address,
        pageSize,
        PAGE_READONLY | PAGE_GUARD,
        &previousProtection));

    const DWORD guardedBefore =
        QueryProtection(process.process, memory.address);

    CHECK((guardedBefore & 0xFFu) == PAGE_READONLY);
    CHECK((guardedBefore & PAGE_GUARD) != 0);

    // Boundary snapshot. The whole window page is guarded, so the guard
    // tracks state/protection only and never dereferences the page.
    BoundaryGuard guard(
        process.process, memory.address, pageSize, scopeAddress, patchSize);

    // ForceChange is specifically expected to permit modification of a guarded page.
    CHECK(WinProcHandling::WriteMemory(
        process.process,
        scopeAddress,
        replacement.data(),
        replacement.size(),
        WinProcHandling::e_VirtualProtectMode::ForceChange,
        true)
        == WinProcHandling::e_WriteStatus::Success);

    // Phase 2: the library must have restored the complete original
    // protection, including PAGE_GUARD, across the whole boundary window.
    guard.RequireScopeProtection(guardedBefore);
    guard.RequireWindowProtectionRestored();

    // The library must have restored the complete original protection,
    // including PAGE_GUARD.
    const DWORD guardedAfter =
        QueryProtection(process.process, memory.address);

    CHECK(guardedAfter == guardedBefore);

    // PAGE_GUARD intentionally interferes with ordinary memory access.
    // Temporarily remove it so the test can inspect the bytes written by WriteMemory().
    DWORD protectionBeforeInspection = 0;

    REQUIRE(VirtualProtectEx(
        process.process,
        memory.address,
        pageSize,
        PAGE_READONLY,
        &protectionBeforeInspection));

    // Byte-level boundary check in the readable state: only the scope differs.
    BoundaryGuard readableGuard(
        process.process, memory.address, pageSize, scopeAddress, patchSize);
    readableGuard.RequireWindowBytesMatchImage(
        readableGuard.ExpectedImageWithScopeReplaced(replacement.data(), replacement.size()));

    std::array<std::uint8_t, patchSize> observed{};

    REQUIRE(ReadProcessMemory(
        process.process,
        scopeAddress,
        observed.data(),
        observed.size(),
        nullptr));

    CHECK(observed == replacement);

    // Restore the exact protection that existed after WriteMemory().
    DWORD ignoredPreviousProtection = 0;

    REQUIRE(VirtualProtectEx(
        process.process,
        memory.address,
        pageSize,
        guardedBefore,
        &ignoredPreviousProtection));

    CHECK(QueryProtection(process.process, memory.address) == guardedBefore);

    // Restore the original bytes. Remove PAGE_GUARD temporarily so the cleanup
    // operation can be performed without intentionally triggering the guard.
    REQUIRE(VirtualProtectEx(
        process.process,
        memory.address,
        pageSize,
        PAGE_READONLY,
        &ignoredPreviousProtection));

    REQUIRE(WinProcHandling::WriteMemory(
        process.process,
        scopeAddress,
        original.data(),
        original.size(),
        WinProcHandling::e_VirtualProtectMode::ForceChange,
        true)
        == WinProcHandling::e_WriteStatus::Success);

    // Restore the original guarded protection so the test leaves no modification.
    REQUIRE(VirtualProtectEx(
        process.process,
        memory.address,
        pageSize,
        PAGE_READONLY | PAGE_GUARD,
        &ignoredPreviousProtection));

    CHECK(QueryProtection(process.process, memory.address) ==
          (PAGE_READONLY | PAGE_GUARD));

    // Phase 3: the guarded window equals its pre-write snapshot again.
    guard.RequireWindowRestored();
}

/** @test Verifies that SafelyChange rejects a remote guarded page without removing PAGE_GUARD. */
TEST_CASE("SafelyChange rejects a guarded page without removing PAGE_GUARD",
          "[remote][safe][guard]") {
    ProcessFixture process;
    if (!process.available())
        SKIP(kSkipMessage);

    constexpr SIZE_T pageSize = 4096;
    constexpr SIZE_T patchSize = 4;
    constexpr SIZE_T scopeOffset = 128;

    RemoteAllocation memory(process.process, pageSize, PAGE_READWRITE);
    REQUIRE(memory);

    const auto scopeAddress =
        static_cast<std::uint8_t*>(memory.address) + scopeOffset;

    const std::array<std::uint8_t, patchSize> original{1,2,3,4};
    const std::array<std::uint8_t, patchSize> replacement{5,6,7,8};

    REQUIRE(WriteProcessMemory(
        process.process, scopeAddress, original.data(), original.size(), nullptr));

    DWORD previous = 0;
    REQUIRE(VirtualProtectEx(
        process.process, memory.address, pageSize,
        PAGE_READONLY | PAGE_GUARD, &previous));

    const DWORD before = QueryProtection(process.process, memory.address);

    BoundaryGuard guard(
        process.process, memory.address, pageSize, scopeAddress, patchSize);

    CHECK(WinProcHandling::WriteMemory(
        process.process, scopeAddress, replacement.data(), replacement.size(),
        WinProcHandling::e_VirtualProtectMode::SafelyChange, true)
        == WinProcHandling::e_WriteStatus::WriteMemoryFailed);

    // The rejected write must not have disturbed any page of the window.
    guard.RequireWindowRestored();
    CHECK(QueryProtection(process.process, memory.address) == before);
}

/** @test Verifies that a remote read of a PAGE_NOACCESS page flips, reads, and restores exactly. */
TEST_CASE("Remote ReadMemory reads exact bytes and restores protection", "[remote][read]") {
    ProcessFixture process;
    if (!process.available())
        SKIP(kSkipMessage);

    constexpr SIZE_T pageSize = 4096;
    constexpr SIZE_T readSize = 16;
    constexpr SIZE_T scopeOffset = 128;

    RemoteAllocation memory(process.process, pageSize, PAGE_NOACCESS);
    REQUIRE(memory);

    const auto scopeAddress =
        static_cast<std::uint8_t*>(memory.address) + scopeOffset;

    // Seed the page by temporarily making it writable.
    DWORD oldProtection = 0;
    REQUIRE(VirtualProtectEx(
        process.process, memory.address, pageSize, PAGE_READWRITE, &oldProtection));

    const std::array<std::uint8_t, readSize> expected{
        0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
        0x10,0x32,0x54,0x76,0x98,0xBA,0xDC,0xFE
    };

    REQUIRE(WriteProcessMemory(
        process.process, scopeAddress, expected.data(),
        expected.size(), nullptr));

    // Byte-level boundary snapshot while the page is still readable, so the
    // read operation can later be proven not to have disturbed any byte.
    BoundaryGuard readableGuard(
        process.process, memory.address, pageSize, scopeAddress, readSize);

    REQUIRE(VirtualProtectEx(
        process.process, memory.address, pageSize, PAGE_NOACCESS, &oldProtection));

    const DWORD before = QueryProtection(process.process, memory.address);

    // Protection-level boundary snapshot around the actual read operation.
    BoundaryGuard guard(
        process.process, memory.address, pageSize, scopeAddress, readSize);

    std::array<std::uint8_t, readSize> observed{};
    CHECK(WinProcHandling::ReadMemory(
        process.process, observed.data(), scopeAddress, observed.size(),
        WinProcHandling::e_VirtualProtectMode::SafelyChange));

    CHECK(observed == expected);

    // Phase 2/3: the read restored the NOACCESS state across the window.
    guard.RequireWindowRestored();
    CHECK(QueryProtection(process.process, memory.address) == before);

    // The bytes inside the window were not disturbed by the flip-and-read.
    REQUIRE(VirtualProtectEx(
        process.process, memory.address, pageSize, PAGE_READWRITE, &oldProtection));
    readableGuard.RequireWindowRestored();
    REQUIRE(VirtualProtectEx(
        process.process, memory.address, pageSize, PAGE_NOACCESS, &oldProtection));
}

/** @test Verifies that a failed remote read crossing into uncommitted memory still restores protection. */
TEST_CASE("Remote ReadMemory failure still restores protection", "[remote][read][regression]") {
    ProcessFixture process;
    if (!process.available())
        SKIP(kSkipMessage);

    constexpr SIZE_T pageSize = 4096;

    // Two committed pages; the second one is decommitted by the test itself so
    // the failing read deterministically crosses into uncommitted memory.
    RemoteAllocation memory(process.process, 2 * pageSize, PAGE_NOACCESS);
    REQUIRE(memory);

    DWORD oldProtection = 0;
    REQUIRE(VirtualProtectEx(
        process.process, memory.address, 2 * pageSize, PAGE_READWRITE, &oldProtection));

    std::array<std::uint8_t, 8> expected{1,2,3,4,5,6,7,8};
    REQUIRE(WriteProcessMemory(
        process.process, memory.address, expected.data(), expected.size(), nullptr));

    REQUIRE(VirtualProtectEx(
        process.process, memory.address, pageSize, PAGE_NOACCESS, &oldProtection));

    const auto uncommittedPage =
        static_cast<std::uint8_t*>(memory.address) + pageSize;
    REQUIRE(VirtualFreeEx(
        process.process, uncommittedPage, pageSize, MEM_DECOMMIT));

    // The read starts four bytes before the committed/uncommitted boundary and
    // crosses it. Its boundary window [scope - readSize, scope + 2*readSize]
    // page-aligns to exactly the two pages of the allocation.
    const auto badAddress =
        static_cast<const std::uint8_t*>(memory.address) + pageSize - 4;
    constexpr SIZE_T readSize = 16;

    BoundaryGuard guard(
        process.process, memory.address, 2 * pageSize, badAddress, readSize);

    std::array<std::uint8_t, readSize> output{};
    CHECK_FALSE(WinProcHandling::ReadMemory(
        process.process, output.data(), badAddress, output.size(),
        WinProcHandling::e_VirtualProtectMode::SafelyChange));

    // Phase 3: the failed read must not disturb committed or uncommitted pages.
    guard.RequireWindowRestored();
    CHECK(QueryProtection(process.process, memory.address) == PAGE_NOACCESS);
}

/** @test Verifies that a remote write crossing into uncommitted memory is rejected without touching the committed part. */
TEST_CASE("Remote write rejects a cross-region write rather than changing unrelated pages",
          "[remote][write][boundaries]") {
    ProcessFixture process;
    if (!process.available())
        SKIP(kSkipMessage);

    constexpr SIZE_T page = 4096;

    // Two committed pages; the second one is decommitted by the test itself so
    // the crossing write deterministically hits an uncommitted region.
    RemoteAllocation first(process.process, 2 * page, PAGE_READONLY);
    REQUIRE(first);

    const auto uncommittedPage =
        static_cast<std::uint8_t*>(first.address) + page;
    REQUIRE(VirtualFreeEx(
        process.process, uncommittedPage, page, MEM_DECOMMIT));

    const std::array<std::uint8_t, 8> bytes{1,2,3,4,5,6,7,8};
    const auto address =
        static_cast<std::uint8_t*>(first.address) + page - 4;

    BoundaryGuard guard(
        process.process, first.address, 2 * page, address, bytes.size());

    // The committed page ends at address+4; the requested write extends beyond it.
    CHECK(
        WinProcHandling::WriteMemory(
            process.process, address, bytes.data(), bytes.size(),
            WinProcHandling::e_VirtualProtectMode::SafelyChange, true)
        == WinProcHandling::e_WriteStatus::WriteMemoryFailed);

    // Phase 3: neither the committed page nor the reserved hole was disturbed.
    guard.RequireWindowRestored();
}

/** @test Verifies that DontChange writes bytes without altering protection. */
TEST_CASE("DontChange does not alter protection", "[remote][write][protection]") {
    ProcessFixture process;
    if (!process.available())
        SKIP(kSkipMessage);

    constexpr SIZE_T pageSize = 4096;
    constexpr SIZE_T patchSize = 4;
    constexpr SIZE_T scopeOffset = 128;

    RemoteAllocation memory(process.process, pageSize, PAGE_READWRITE);
    REQUIRE(memory);

    const auto scopeAddress =
        static_cast<std::uint8_t*>(memory.address) + scopeOffset;

    const std::array<std::uint8_t, patchSize> bytes{0xAA,0xBB,0xCC,0xDD};
    const DWORD before = QueryProtection(process.process, memory.address);

    BoundaryGuard guard(
        process.process, memory.address, pageSize, scopeAddress, patchSize);

    CHECK(WinProcHandling::WriteMemory(
        process.process, scopeAddress, bytes.data(), bytes.size(),
        WinProcHandling::e_VirtualProtectMode::DontChange, true)
        == WinProcHandling::e_WriteStatus::Success);

    // Phase 2: bytes replaced; not a single protection value in the window moved.
    guard.RequireWindowBytesMatchImage(
        guard.ExpectedImageWithScopeReplaced(bytes.data(), bytes.size()));
    guard.RequireWindowProtectionRestored();

    CHECK(QueryProtection(process.process, memory.address) == before);
}

/** @test Verifies the behavior described by the Catch2 test name. */
TEST_CASE("Invalid process handle is rejected", "[errors]") {
    const std::array<std::uint8_t, 4> fromBytes{1,2,3,4};
    std::array<std::uint8_t, 4> toBytes{4,5,6,7};

    CHECK(WinProcHandling::WriteMemory(nullptr, toBytes.data(), fromBytes.data(), fromBytes.size())
                == WinProcHandling::e_WriteStatus::WriteMemoryFailed);

    CHECK_FALSE(WinProcHandling::ReadMemory(nullptr, toBytes.data(), fromBytes.data(), fromBytes.size()));
}

/** @test Verifies the behavior described by the Catch2 test name. */
TEST_CASE("Zero-size operations are no-ops", "[edge]") {
    // Three-argument calls resolve to the local overloads (the remote
    // overloads require at least four arguments; SIZE_T has no default).
    CHECK(WinProcHandling::WriteMemory(
        nullptr, nullptr, 0) == WinProcHandling::e_WriteStatus::Success);

    CHECK(WinProcHandling::FillWithNOPs(
        nullptr, 0) == WinProcHandling::e_WriteStatus::Success);

    CHECK(WinProcHandling::ReadMemory(
        nullptr, nullptr, 0));
}

/** @test Pins the documented remote validation order: the handle is validated before zero-size short-circuiting. */
TEST_CASE("Remote zero-size operations still reject an invalid handle", "[remote][edge][errors]") {
    const std::array<std::uint8_t, 4> source{1,2,3,4};
    std::array<std::uint8_t, 4> output{};

    CHECK(WinProcHandling::WriteMemory(nullptr, output.data(), source.data(), 0)
          == WinProcHandling::e_WriteStatus::WriteMemoryFailed);

    CHECK(WinProcHandling::WriteMemory(nullptr, output.data(), source.data(), source.size())
          == WinProcHandling::e_WriteStatus::WriteMemoryFailed);

    CHECK_FALSE(WinProcHandling::ReadMemory(nullptr, output.data(), source.data(), 0));

    CHECK(WinProcHandling::FillWithNOPs(nullptr, output.data(), 0)
          == WinProcHandling::e_WriteStatus::WriteMemoryFailed);
}

/** @test Verifies remote zero-size requests succeed once a valid handle is supplied. */
TEST_CASE("Remote zero-size operations are no-ops with a valid handle", "[remote][edge]") {
    ProcessFixture process;
    if (!process.available())
        SKIP(kSkipMessage);

    RemoteAllocation memory(process.process, 4096, PAGE_READWRITE);
    REQUIRE(memory);

    const std::uint8_t sourceByte = 0x42;
    std::uint8_t outputByte = 0;

    CHECK(WinProcHandling::WriteMemory(
        process.process, memory.address, &sourceByte, 0,
        WinProcHandling::e_VirtualProtectMode::SafelyChange, true)
        == WinProcHandling::e_WriteStatus::Success);

    CHECK(WinProcHandling::FillWithNOPs(process.process, memory.address, 0)
          == WinProcHandling::e_WriteStatus::Success);

    CHECK(WinProcHandling::ReadMemory(
        process.process, &outputByte, memory.address, 0));
}

/** @test Verifies the behavior described by the Catch2 test name. */
TEST_CASE("ForEachScanProcess invokes callback with module-relative indices", "[scan]") {
    ProcessFixture process;
    if (!process.available())
        SKIP(kSkipMessage);

    uintptr_t base = 0;
    const DWORD size = WinProcHandling::GetModuleBase(process.process, &base);
    REQUIRE(size != 0);

    struct State {
        size_t count{};
        size_t firstIndex{std::numeric_limits<size_t>::max()};
        uint8_t firstByte{};
    } state;

    WinProcHandling::t_ProcessInfo info{};
    info.id = process.pid;
    info.handle = process.process;
    info.moduleBase = base;
    info.moduleSize = size;
    info.searchedOffsetFromBase = 0;
    info.searchSize = std::min<size_t>(size, 64 * 1024);

    WinProcHandling::ForEachScanProcess(
        &info,
        &state,
        [](void* callbackData, size_t byteIndex, uint8_t& byteValue) {
            auto& state = *static_cast<State*>(callbackData);
            if (state.count == 0) {
                state.firstIndex = byteIndex;
                state.firstByte = byteValue;
            }
            ++state.count;
            return state.count >= 64;
        });

    CHECK(state.count == 64);
    CHECK(state.firstIndex < info.searchSize);
    (void)state.firstByte;
}

/** @test Scans the test binary's own module through the pseudo-handle: bytes are delivered with correct module-relative indices. */
TEST_CASE("ForEachScanProcess scans the current process module range", "[scan][local]") {
    uintptr_t base = 0;
    const DWORD size = WinProcHandling::GetModuleBase(GetCurrentProcess(), &base);
    REQUIRE(size != 0);
    REQUIRE(base != 0);

    constexpr size_t scanRange = 4096;

    struct State {
        size_t count{};
        std::uint8_t firstByte{0};
        std::uint8_t secondByte{0};
    } state{};

    WinProcHandling::t_ProcessInfo info{};
    info.id = GetCurrentProcessId();
    info.handle = GetCurrentProcess();
    info.moduleBase = base;
    info.moduleSize = size;
    info.searchedOffsetFromBase = 0;
    info.searchSize = std::min<size_t>(size, scanRange);

    WinProcHandling::ForEachScanProcess(
        &info,
        &state,
        [](void* callbackData, size_t byteIndex, uint8_t& byteValue) {
            auto& state = *static_cast<State*>(callbackData);
            if (byteIndex == 0)
                state.firstByte = byteValue;
            if (byteIndex == 1)
                state.secondByte = byteValue;
            ++state.count;
            return false;
        });

    // The PE header region of a loaded image is committed and readable, so
    // every byte of the requested range must be delivered exactly once.
    CHECK(state.count == info.searchSize);

    // A loaded image begins with the DOS header magic "MZ" (0x5A4D).
    CHECK(state.firstByte == static_cast<std::uint8_t>(IMAGE_DOS_SIGNATURE & 0xFF));
    CHECK(state.secondByte == static_cast<std::uint8_t>(IMAGE_DOS_SIGNATURE >> 8));
}

/** @test Verifies that the scanner stops immediately when the callback returns true. */
TEST_CASE("ForEachScanProcess stops when the callback returns true", "[scan][local]") {
    uintptr_t base = 0;
    const DWORD size = WinProcHandling::GetModuleBase(GetCurrentProcess(), &base);
    REQUIRE(size != 0);

    struct State { size_t count{}; } state{};

    WinProcHandling::t_ProcessInfo info{};
    info.handle = GetCurrentProcess();
    info.moduleBase = base;
    info.moduleSize = size;
    info.searchedOffsetFromBase = 0;
    info.searchSize = std::min<size_t>(size, 64 * 1024);

    WinProcHandling::ForEachScanProcess(
        &info,
        &state,
        [](void* callbackData, size_t, uint8_t&) {
            auto& state = *static_cast<State*>(callbackData);
            ++state.count;
            return state.count >= 16;
        });

    CHECK(state.count == 16);
}

/** @test Verifies that invalid scanner inputs are rejected without invoking the callback. */
TEST_CASE("ForEachScanProcess rejects invalid inputs without invoking the callback",
          "[scan][errors]") {
    struct State { size_t count{}; } state{};

    auto countingCallback = [](void* callbackData, size_t, uint8_t&) {
        ++static_cast<State*>(callbackData)->count;
        return false;
    };

    WinProcHandling::ForEachScanProcess(nullptr, &state, countingCallback);
    CHECK(state.count == 0);

    WinProcHandling::t_ProcessInfo info{};

    WinProcHandling::ForEachScanProcess(&info, &state, countingCallback);
    CHECK(state.count == 0);

    info.handle = INVALID_HANDLE_VALUE;
    WinProcHandling::ForEachScanProcess(&info, &state, countingCallback);
    CHECK(state.count == 0);

    info.handle = GetCurrentProcess();
    WinProcHandling::ForEachScanProcess(&info, &state, nullptr);
    CHECK(state.count == 0);

    WinProcHandling::ForEachScanProcess(&info, &state, countingCallback);
    CHECK(state.count == 0); // moduleBase == 0 and moduleSize == 0 are rejected.

    info.moduleBase = 0x1000;
    WinProcHandling::ForEachScanProcess(&info, &state, countingCallback);
    CHECK(state.count == 0); // moduleSize == 0 is rejected.
}

/** @test Verifies FindProcessId's documented failure paths. */
TEST_CASE("FindProcessId returns zero for invalid or unknown names", "[process][errors]") {
    CHECK(WinProcHandling::FindProcessId(nullptr) == 0);
    CHECK(WinProcHandling::FindProcessId("") == 0);
    CHECK(WinProcHandling::FindProcessId("no_such_process_ajom_selftest.exe") == 0);
}

/** @test Verifies GetModuleBase's documented failure paths (no live target required). */
TEST_CASE("GetModuleBase rejects invalid inputs", "[module][errors]") {
    uintptr_t base = 0xAAAA;

    CHECK(WinProcHandling::GetModuleBase(nullptr, &base) == 0);
    // NOTE: (HANDLE)-1 is the current-process pseudo handle and is therefore a
    // VALID input (covered by the pseudo-handle agreement test); there is no
    // other documented invalid sentinel for process handles to reject here.

    CHECK(WinProcHandling::GetModuleBase(0, "kernel32.dll", &base) == 0);
    CHECK(WinProcHandling::GetModuleBase(GetCurrentProcessId(), nullptr, &base) == 0);
    CHECK(WinProcHandling::GetModuleBase(GetCurrentProcessId(), "", &base) == 0);
    CHECK(WinProcHandling::GetModuleBase(
        GetCurrentProcessId(), "no_such_module_ajom_selftest.dll", &base) == 0);

    CHECK(base == 0xAAAA); // outBase stays untouched on failure.
}

/** @test Verifies that the pseudo-handle and a fully privileged real self handle agree. */
TEST_CASE("GetModuleBase agrees between the pseudo-handle and a real self handle",
          "[module][local]") {
    uintptr_t pseudoBase = 0;
    const DWORD pseudoSize = WinProcHandling::GetModuleBase(GetCurrentProcess(), &pseudoBase);
    REQUIRE(pseudoSize != 0);
    REQUIRE(pseudoBase != 0);

    HANDLE self = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE,
        GetCurrentProcessId());
    REQUIRE(self != nullptr);

    uintptr_t realBase = 0;
    const DWORD realSize = WinProcHandling::GetModuleBase(self, &realBase);
    CloseHandle(self);

    REQUIRE(realSize != 0);
    CHECK(realBase == pseudoBase);
    CHECK(realSize == pseudoSize);
}

/** @test Verifies that ForceChange can patch a local guarded page and restores PAGE_GUARD. */
TEST_CASE("Local ForceChange can patch a guarded committed page and restores PAGE_GUARD",
          "[local][write][guard]") {
    constexpr SIZE_T pageSize = 4096;
    constexpr SIZE_T patchSize = 8;
    // In-page scope offset keeps [scope - patchSize, scope + 2*patchSize] inside the page.
    constexpr SIZE_T scopeOffset = 128;

    LocalAllocation memory(pageSize, PAGE_READWRITE);
    REQUIRE(memory);

    const auto scopeAddress =
        static_cast<std::uint8_t*>(memory.address) + scopeOffset;

    const std::array<std::uint8_t, patchSize> original{
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
    };
    const std::array<std::uint8_t, patchSize> replacement{
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90
    };

    // Seed the original bytes while the page is writable.
    std::memcpy(scopeAddress, original.data(), original.size());

    DWORD previousProtection = 0;
    REQUIRE(VirtualProtect(
        memory.address, pageSize, PAGE_READONLY | PAGE_GUARD, &previousProtection));

    const DWORD guardedBefore = QueryProtectionLocal(memory.address);
    CHECK((guardedBefore & 0xFFu) == PAGE_READONLY);
    CHECK((guardedBefore & PAGE_GUARD) != 0);

    // Boundary snapshot; the guarded page is tracked by protection only.
    BoundaryGuard guard(
        nullptr, memory.address, pageSize, scopeAddress, patchSize);

    // Regression test for the local ForceChange guard-page defect: the local
    // overloads must honor ForceChange exactly like the remote ones.
    CHECK(WinProcHandling::WriteMemory(
        scopeAddress, replacement.data(), replacement.size(),
        WinProcHandling::e_VirtualProtectMode::ForceChange, true)
        == WinProcHandling::e_WriteStatus::Success);

    // Phase 2: the whole window is back to the guarded pre-write state.
    guard.RequireScopeProtection(guardedBefore);
    guard.RequireWindowProtectionRestored();
    CHECK(QueryProtectionLocal(memory.address) == guardedBefore);

    // Lift the guard temporarily so the bytes can be inspected.
    DWORD ignoredPreviousProtection = 0;
    REQUIRE(VirtualProtect(memory.address, pageSize, PAGE_READONLY, &ignoredPreviousProtection));

    // Byte-level boundary check in the readable state: only the scope differs.
    BoundaryGuard readableGuard(
        nullptr, memory.address, pageSize, scopeAddress, patchSize);
    readableGuard.RequireWindowBytesMatchImage(
        readableGuard.ExpectedImageWithScopeReplaced(replacement.data(), replacement.size()));

    std::array<std::uint8_t, patchSize> observed{};
    std::memcpy(observed.data(), scopeAddress, observed.size());
    CHECK(observed == replacement);

    // Re-establish the guarded state the test found (and leaves) behind.
    REQUIRE(VirtualProtect(memory.address, pageSize, guardedBefore, &ignoredPreviousProtection));
    CHECK(QueryProtectionLocal(memory.address) == guardedBefore);

    // Phase 3: the guarded window equals its pre-write snapshot.
    guard.RequireWindowRestored();
}

/** @test Verifies that local SafelyChange still rejects guarded pages without touching PAGE_GUARD. */
TEST_CASE("Local SafelyChange rejects a guarded page without removing PAGE_GUARD",
          "[local][safe][guard]") {
    constexpr SIZE_T pageSize = 4096;
    constexpr SIZE_T patchSize = 4;
    constexpr SIZE_T scopeOffset = 128;

    LocalAllocation memory(pageSize, PAGE_READWRITE);
    REQUIRE(memory);

    const auto scopeAddress =
        static_cast<std::uint8_t*>(memory.address) + scopeOffset;

    const std::array<std::uint8_t, patchSize> replacement{5,6,7,8};

    DWORD previousProtection = 0;
    REQUIRE(VirtualProtect(
        memory.address, pageSize, PAGE_READONLY | PAGE_GUARD, &previousProtection));

    const DWORD guardedBefore = QueryProtectionLocal(memory.address);

    BoundaryGuard guard(
        nullptr, memory.address, pageSize, scopeAddress, patchSize);

    CHECK(WinProcHandling::WriteMemory(
        scopeAddress, replacement.data(), replacement.size(),
        WinProcHandling::e_VirtualProtectMode::SafelyChange, true)
        == WinProcHandling::e_WriteStatus::WriteMemoryFailed);

    // The rejected write must not have disturbed any page of the window.
    guard.RequireWindowRestored();
    CHECK(QueryProtectionLocal(memory.address) == guardedBefore);
}

/** @test Verifies that local ForceChange can read a guarded page and restores PAGE_GUARD. */
TEST_CASE("Local ReadMemory ForceChange reads a guarded page and restores PAGE_GUARD",
          "[local][read][guard]") {
    constexpr SIZE_T pageSize = 4096;
    constexpr SIZE_T readSize = 16;
    constexpr SIZE_T scopeOffset = 128;

    LocalAllocation memory(pageSize, PAGE_READWRITE);
    REQUIRE(memory);

    const auto scopeAddress =
        static_cast<std::uint8_t*>(memory.address) + scopeOffset;

    const std::array<std::uint8_t, readSize> expected{
        0x10,0x32,0x54,0x76,0x98,0xBA,0xDC,0xFE,
        0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF
    };
    std::memcpy(scopeAddress, expected.data(), expected.size());

    DWORD previousProtection = 0;
    REQUIRE(VirtualProtect(
        memory.address, pageSize, PAGE_READONLY | PAGE_GUARD, &previousProtection));

    const DWORD guardedBefore = QueryProtectionLocal(memory.address);

    BoundaryGuard guard(
        nullptr, memory.address, pageSize, scopeAddress, readSize);

    std::array<std::uint8_t, readSize> observed{};
    CHECK(WinProcHandling::ReadMemory(
        observed.data(), scopeAddress, observed.size(),
        WinProcHandling::e_VirtualProtectMode::ForceChange));

    CHECK(observed == expected);

    // Phase 3: the guarded page (and the whole window) is back to its snapshot.
    guard.RequireWindowRestored();
    CHECK(QueryProtectionLocal(memory.address) == guardedBefore);
}

/** @test Verifies the local read flip path: a PAGE_NOACCESS page is read via a temporary, restored protection flip. */
TEST_CASE("Local ReadMemory temporarily makes a PAGE_NOACCESS page readable and restores it",
          "[local][read][protection]") {
    constexpr SIZE_T pageSize = 4096;
    constexpr SIZE_T readSize = 16;
    constexpr SIZE_T scopeOffset = 128;

    LocalAllocation memory(pageSize, PAGE_NOACCESS);
    REQUIRE(memory);

    const auto scopeAddress =
        static_cast<std::uint8_t*>(memory.address) + scopeOffset;

    // Seed the page while it is writable, then lock it down again.
    DWORD oldProtection = 0;
    REQUIRE(VirtualProtect(memory.address, pageSize, PAGE_READWRITE, &oldProtection));

    const std::array<std::uint8_t, readSize> expected{
        0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
        0x10,0x32,0x54,0x76,0x98,0xBA,0xDC,0xFE
    };
    std::memcpy(scopeAddress, expected.data(), expected.size());

    // Byte-level boundary snapshot in the readable state.
    BoundaryGuard readableGuard(
        nullptr, memory.address, pageSize, scopeAddress, readSize);

    REQUIRE(VirtualProtect(memory.address, pageSize, PAGE_NOACCESS, &oldProtection));

    const DWORD before = QueryProtectionLocal(memory.address);
    CHECK((before & 0xFFu) == PAGE_NOACCESS);

    // Protection-level boundary snapshot around the actual read operation.
    BoundaryGuard guard(
        nullptr, memory.address, pageSize, scopeAddress, readSize);

    std::array<std::uint8_t, readSize> observed{};
    CHECK(WinProcHandling::ReadMemory(
        observed.data(), scopeAddress, observed.size(),
        WinProcHandling::e_VirtualProtectMode::SafelyChange));

    CHECK(observed == expected);

    // The read restored the NOACCESS state across the whole window.
    guard.RequireWindowRestored();
    CHECK(QueryProtectionLocal(memory.address) == before);

    // The flip-and-read did not disturb any byte inside the window.
    REQUIRE(VirtualProtect(memory.address, pageSize, PAGE_READWRITE, &oldProtection));
    readableGuard.RequireWindowRestored();
    REQUIRE(VirtualProtect(memory.address, pageSize, PAGE_NOACCESS, &oldProtection));
}

/** @test Verifies that a local read crossing into uncommitted memory fails without crashing and restores everything. */
TEST_CASE("Local ReadMemory fails on uncommitted memory without crashing",
          "[local][read][boundaries]") {
    constexpr SIZE_T pageSize = 4096;

    // Two committed pages; the second one is decommitted by the test itself so
    // the failing read deterministically crosses into uncommitted memory.
    LocalAllocation memory(2 * pageSize, PAGE_READWRITE);
    REQUIRE(memory);

    const auto uncommittedPage =
        static_cast<std::uint8_t*>(memory.address) + pageSize;
    REQUIRE(VirtualFree(uncommittedPage, pageSize, MEM_DECOMMIT));

    // The read starts four bytes before the committed/uncommitted boundary and
    // crosses it. Its boundary window page-aligns to exactly the two pages.
    const auto badAddress =
        static_cast<const std::uint8_t*>(memory.address) + pageSize - 4;
    constexpr SIZE_T readSize = 16;

    BoundaryGuard guard(
        nullptr, memory.address, 2 * pageSize, badAddress, readSize);

    std::array<std::uint8_t, readSize> output{};
    CHECK_FALSE(WinProcHandling::ReadMemory(
        output.data(), badAddress, output.size(),
        WinProcHandling::e_VirtualProtectMode::SafelyChange));

    // Phase 3: committed and uncommitted pages are both untouched.
    guard.RequireWindowRestored();
}

/** @test Verifies local FillWithNOPs writes exact 0x90 bytes into writable memory. */
TEST_CASE("Local FillWithNOPs writes exact NOP bytes", "[local][nop]") {
    constexpr SIZE_T pageSize = 4096;
    constexpr SIZE_T count = 32;
    // In-page scope offset keeps [scope - count, scope + 2*count] inside the page.
    constexpr SIZE_T scopeOffset = 128;

    LocalAllocation memory(pageSize, PAGE_READWRITE);
    REQUIRE(memory);

    const auto scopeAddress =
        static_cast<std::uint8_t*>(memory.address) + scopeOffset;

    std::array<std::uint8_t, count> original{};
    original.fill(0x11);
    std::array<std::uint8_t, count> nops{};
    nops.fill(0x90);
    std::memcpy(scopeAddress, original.data(), original.size());

    BoundaryGuard guard(
        nullptr, memory.address, pageSize, scopeAddress, count);

    CHECK(WinProcHandling::FillWithNOPs(scopeAddress, count)
          == WinProcHandling::e_WriteStatus::Success);

    // Phase 2: scope NOP-filled, window and protection untouched.
    guard.RequireWindowBytesMatchImage(
        guard.ExpectedImageWithScopeReplaced(nops.data(), nops.size()));
    guard.RequireWindowOutsideScopeUnchanged();
    guard.RequireWindowProtectionRestored();

    std::array<std::uint8_t, count> observed{};
    std::memcpy(observed.data(), scopeAddress, observed.size());
    CHECK(std::all_of(observed.begin(), observed.end(),
                      [](std::uint8_t byteValue) { return byteValue == 0x90; }));

    // Restore the original bytes and prove full restoration.
    std::memcpy(scopeAddress, original.data(), original.size());
    guard.RequireWindowRestored();
}

/** @test Verifies that local WriteMemory flushes executable code and restores protection. */
TEST_CASE("Local WriteMemory flushes executable code and restores protection",
          "[local][cache]") {
    constexpr SIZE_T page = 4096;
    constexpr SIZE_T scopeOffset = 128;
    LocalAllocation code(page, PAGE_READWRITE);
    REQUIRE(code);

#if defined(_M_X64) || defined(__x86_64__)
    // mov eax, 1; ret
    const std::array<std::uint8_t, 6> code1{0xB8,0x01,0x00,0x00,0x00,0xC3};
    // mov eax, 2; ret
    const std::array<std::uint8_t, 6> code2{0xB8,0x02,0x00,0x00,0x00,0xC3};

    const auto entry =
        static_cast<std::uint8_t*>(code.address) + scopeOffset;

    BoundaryGuard guard(
        nullptr, code.address, page, entry, code1.size());

    REQUIRE(WinProcHandling::WriteMemory(
        entry, code1.data(), code1.size(),
        WinProcHandling::e_VirtualProtectMode::SafelyChange, true)
        == WinProcHandling::e_WriteStatus::Success);

    // Phase 2: code bytes replaced, window intact.
    guard.RequireWindowBytesMatchImage(
        guard.ExpectedImageWithScopeReplaced(code1.data(), code1.size()));
    guard.RequireWindowOutsideScopeUnchanged();
    guard.RequireWindowProtectionRestored();

    DWORD oldProtect = 0;
    REQUIRE(VirtualProtect(code.address, page, PAGE_EXECUTE_READ, &oldProtect));

    auto fn = reinterpret_cast<int(*)()>(entry);
    CHECK(fn() == 1);

    // Boundary snapshot in the executable/readable state.
    BoundaryGuard executableGuard(
        nullptr, code.address, page, entry, code2.size());

    // Change back through the library; the library must flush the instruction cache.
    REQUIRE(WinProcHandling::WriteMemory(
        entry, code2.data(), code2.size(),
        WinProcHandling::e_VirtualProtectMode::SafelyChange, true)
        == WinProcHandling::e_WriteStatus::Success);

    executableGuard.RequireWindowBytesMatchImage(
        executableGuard.ExpectedImageWithScopeReplaced(code2.data(), code2.size()));
    executableGuard.RequireWindowProtectionRestored();

    CHECK(fn() == 2);
#else
    SKIP("Executable-code test is implemented for x64 builds.");
#endif
}

// ===========================================================================
// TESTABLE_STATIC pure helpers: protection classification and mapping
// (no process state is modified; every documented input class is covered)
// ===========================================================================

/** @test BaseProtection strips every documented modifier and keeps base bits. */
TEST_CASE("BaseProtection isolates the base protection bits", "[internal][pure]") {
    struct Value {
        const char* name;
        DWORD protect;
        DWORD expected;
    };

    const Value values[] = {
        {"PAGE_NOACCESS", PAGE_NOACCESS, PAGE_NOACCESS},
        {"PAGE_READONLY", PAGE_READONLY, PAGE_READONLY},
        {"PAGE_READWRITE", PAGE_READWRITE, PAGE_READWRITE},
        {"PAGE_WRITECOPY", PAGE_WRITECOPY, PAGE_WRITECOPY},
        {"PAGE_EXECUTE", PAGE_EXECUTE, PAGE_EXECUTE},
        {"PAGE_EXECUTE_READ", PAGE_EXECUTE_READ, PAGE_EXECUTE_READ},
        {"PAGE_EXECUTE_READWRITE", PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_READWRITE},
        {"PAGE_EXECUTE_WRITECOPY", PAGE_EXECUTE_WRITECOPY, PAGE_EXECUTE_WRITECOPY},
        {"zero (invalid protection)", 0u, 0u},
        {"all base bits", 0xFFu, 0xFFu},
        {"PAGE_GUARD modifier", PAGE_READWRITE | PAGE_GUARD, PAGE_READWRITE},
        {"PAGE_NOCACHE modifier", PAGE_READONLY | PAGE_NOCACHE, PAGE_READONLY},
        {"PAGE_WRITECOMBINE modifier", PAGE_READONLY | PAGE_WRITECOMBINE, PAGE_READONLY},
        {"PAGE_TARGETS_INVALID flag", PAGE_EXECUTE | PAGE_TARGETS_INVALID, PAGE_EXECUTE},
        {"all modifiers together",
         PAGE_EXECUTE_READWRITE | PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE |
             PAGE_TARGETS_INVALID,
         PAGE_EXECUTE_READWRITE},
        {"every bit set", 0xFFFFFFFFu, 0xFFu},
    };

    for (const Value& value : values) {
        INFO(value.name);
        CHECK(BaseProtection(value.protect) == value.expected);
    }
}

/** @test IsReadableProtection accepts exactly the documented readable bases, ignoring modifiers. */
TEST_CASE("IsReadableProtection classifies readable base protections", "[internal][pure]") {
    const DWORD readableProtections[] = {
        PAGE_READONLY,
        PAGE_READWRITE,
        PAGE_WRITECOPY,
        PAGE_EXECUTE_READ,
        PAGE_EXECUTE_READWRITE,
        PAGE_EXECUTE_WRITECOPY,
    };

    for (const DWORD protect : readableProtections) {
        INFO("base 0x" << std::hex << protect);
        CHECK(IsReadableProtection(protect));
        CHECK(IsReadableProtection(protect | PAGE_GUARD));
        CHECK(IsReadableProtection(protect | PAGE_NOCACHE));
        CHECK(IsReadableProtection(protect | PAGE_WRITECOMBINE | PAGE_GUARD));
    }

    const DWORD unreadableProtections[] = {
        PAGE_NOACCESS,
        PAGE_EXECUTE,
        0u,
    };

    for (const DWORD protect : unreadableProtections) {
        INFO("base 0x" << std::hex << protect);
        CHECK_FALSE(IsReadableProtection(protect));
        CHECK_FALSE(IsReadableProtection(protect | PAGE_GUARD));
        CHECK_FALSE(IsReadableProtection(protect | PAGE_NOCACHE | PAGE_WRITECOMBINE));
    }
}

/** @test IsWritableProtection accepts exactly the documented writable bases, ignoring modifiers. */
TEST_CASE("IsWritableProtection classifies writable base protections", "[internal][pure]") {
    const DWORD writableProtections[] = {
        PAGE_READWRITE,
        PAGE_WRITECOPY,
        PAGE_EXECUTE_READWRITE,
        PAGE_EXECUTE_WRITECOPY,
    };

    for (const DWORD protect : writableProtections) {
        INFO("base 0x" << std::hex << protect);
        CHECK(IsWritableProtection(protect));
        CHECK(IsWritableProtection(protect | PAGE_GUARD));
        CHECK(IsWritableProtection(protect | PAGE_NOCACHE | PAGE_WRITECOMBINE));
    }

    const DWORD unwritableProtections[] = {
        PAGE_NOACCESS,
        PAGE_READONLY,
        PAGE_EXECUTE,
        PAGE_EXECUTE_READ,
        0u,
    };

    for (const DWORD protect : unwritableProtections) {
        INFO("base 0x" << std::hex << protect);
        CHECK_FALSE(IsWritableProtection(protect));
        CHECK_FALSE(IsWritableProtection(protect | PAGE_GUARD));
    }
}

/** @test IsExecutableProtection accepts exactly the documented executable bases, ignoring modifiers. */
TEST_CASE("IsExecutableProtection classifies executable base protections", "[internal][pure]") {
    const DWORD executableProtections[] = {
        PAGE_EXECUTE,
        PAGE_EXECUTE_READ,
        PAGE_EXECUTE_READWRITE,
        PAGE_EXECUTE_WRITECOPY,
    };

    for (const DWORD protect : executableProtections) {
        INFO("base 0x" << std::hex << protect);
        CHECK(IsExecutableProtection(protect));
        CHECK(IsExecutableProtection(protect | PAGE_GUARD));
        CHECK(IsExecutableProtection(protect | PAGE_NOCACHE | PAGE_WRITECOMBINE));
    }

    const DWORD nonExecutableProtections[] = {
        PAGE_NOACCESS,
        PAGE_READONLY,
        PAGE_READWRITE,
        PAGE_WRITECOPY,
        0u,
    };

    for (const DWORD protect : nonExecutableProtections) {
        INFO("base 0x" << std::hex << protect);
        CHECK_FALSE(IsExecutableProtection(protect));
        CHECK_FALSE(IsExecutableProtection(protect | PAGE_GUARD));
    }
}

/** @test WritableProtection maps every base protection and preserves only cache modifiers. */
TEST_CASE("WritableProtection maps every base protection to its writable equivalent",
          "[internal][pure]") {
    struct Mapping {
        const char* name;
        DWORD input;
        DWORD expected;
    };

    const Mapping mappings[] = {
        {"PAGE_NOACCESS", PAGE_NOACCESS, PAGE_READWRITE},
        {"PAGE_READONLY", PAGE_READONLY, PAGE_READWRITE},
        {"PAGE_READWRITE", PAGE_READWRITE, PAGE_READWRITE},
        {"PAGE_WRITECOPY", PAGE_WRITECOPY, PAGE_READWRITE},
        {"PAGE_EXECUTE", PAGE_EXECUTE, PAGE_EXECUTE_READWRITE},
        {"PAGE_EXECUTE_READ", PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE},
        {"PAGE_EXECUTE_READWRITE", PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_READWRITE},
        {"PAGE_EXECUTE_WRITECOPY", PAGE_EXECUTE_WRITECOPY, PAGE_EXECUTE_READWRITE},
        {"guard modifier stripped", PAGE_READONLY | PAGE_GUARD, PAGE_READWRITE},
        {"PAGE_NOCACHE preserved", PAGE_READONLY | PAGE_NOCACHE, PAGE_READWRITE | PAGE_NOCACHE},
        {"PAGE_WRITECOMBINE preserved",
         PAGE_READONLY | PAGE_WRITECOMBINE,
         PAGE_READWRITE | PAGE_WRITECOMBINE},
        {"both cache modifiers preserved",
         PAGE_READONLY | PAGE_NOCACHE | PAGE_WRITECOMBINE,
         PAGE_READWRITE | PAGE_NOCACHE | PAGE_WRITECOMBINE},
        {"guard stripped while cache kept",
         PAGE_EXECUTE_READ | PAGE_GUARD | PAGE_NOCACHE,
         PAGE_EXECUTE_READWRITE | PAGE_NOCACHE},
        {"PAGE_TARGETS_INVALID stripped",
         PAGE_EXECUTE | PAGE_TARGETS_INVALID,
         PAGE_EXECUTE_READWRITE},
    };

    for (const Mapping& mapping : mappings) {
        INFO(mapping.name);
        CHECK(WritableProtection(mapping.input) == mapping.expected);
    }
}

/** @test ReadableProtection maps every base protection and preserves only cache modifiers. */
TEST_CASE("ReadableProtection maps every base protection to its readable equivalent",
          "[internal][pure]") {
    struct Mapping {
        const char* name;
        DWORD input;
        DWORD expected;
    };

    const Mapping mappings[] = {
        {"PAGE_NOACCESS", PAGE_NOACCESS, PAGE_READONLY},
        {"PAGE_READONLY", PAGE_READONLY, PAGE_READONLY},
        {"PAGE_READWRITE", PAGE_READWRITE, PAGE_READONLY},
        {"PAGE_WRITECOPY", PAGE_WRITECOPY, PAGE_READONLY},
        {"PAGE_EXECUTE", PAGE_EXECUTE, PAGE_EXECUTE_READ},
        {"PAGE_EXECUTE_READ", PAGE_EXECUTE_READ, PAGE_EXECUTE_READ},
        {"PAGE_EXECUTE_READWRITE", PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_READ},
        {"PAGE_EXECUTE_WRITECOPY", PAGE_EXECUTE_WRITECOPY, PAGE_EXECUTE_READ},
        {"guard modifier stripped", PAGE_READWRITE | PAGE_GUARD, PAGE_READONLY},
        {"PAGE_NOCACHE preserved", PAGE_EXECUTE | PAGE_NOCACHE, PAGE_EXECUTE_READ | PAGE_NOCACHE},
        {"PAGE_WRITECOMBINE preserved",
         PAGE_EXECUTE | PAGE_WRITECOMBINE,
         PAGE_EXECUTE_READ | PAGE_WRITECOMBINE},
        {"guard stripped while cache kept",
         PAGE_READWRITE | PAGE_GUARD | PAGE_WRITECOMBINE,
         PAGE_READONLY | PAGE_WRITECOMBINE},
    };

    for (const Mapping& mapping : mappings) {
        INFO(mapping.name);
        CHECK(ReadableProtection(mapping.input) == mapping.expected);
    }
}

/** @test Mapping outputs always satisfy their own classification, and execute intent survives. */
TEST_CASE("Writable/ReadableProtection outputs satisfy their own classification",
          "[internal][pure]") {
    const DWORD baseProtections[] = {
        PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
        PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
    };
    const DWORD modifiers[] = {
        0u, PAGE_GUARD, PAGE_NOCACHE, PAGE_WRITECOMBINE, PAGE_GUARD | PAGE_NOCACHE,
    };

    for (const DWORD base : baseProtections) {
        for (const DWORD modifier : modifiers) {
            const DWORD input = base | modifier;
            INFO("input 0x" << std::hex << input);

            const DWORD writable = WritableProtection(input);
            const DWORD readable = ReadableProtection(input);

            CHECK(IsWritableProtection(writable));
            CHECK(IsReadableProtection(writable));
            CHECK(IsReadableProtection(readable));
            CHECK_FALSE(IsWritableProtection(readable));

            // Both mappings must preserve (or add) execute intent.
            CHECK(IsExecutableProtection(writable) == IsExecutableProtection(input));
            CHECK(IsExecutableProtection(readable) == IsExecutableProtection(input));
        }
    }
}

/** @test IsValidProcessHandle follows Win32 pseudo-handle rules. */
TEST_CASE("IsValidProcessHandle follows Win32 pseudo-handle rules",
          "[internal][handle]") {
    CHECK_FALSE(IsValidProcessHandle(nullptr));

    // (HANDLE)-1 is numerically INVALID_HANDLE_VALUE, yet for process handles
    // it is the documented current-process pseudo handle returned by
    // GetCurrentProcess(); Win32 process APIs resolve it to the current
    // process. The two values cannot be distinguished, and must not be.
    CHECK(IsValidProcessHandle(GetCurrentProcess()));
    CHECK(IsValidProcessHandle(INVALID_HANDLE_VALUE));

    // Any other non-null value is syntactically valid: this is a cheap
    // pre-check, not a liveness probe. The value is never used for calls.
    CHECK(IsValidProcessHandle(reinterpret_cast<HANDLE>(static_cast<uintptr_t>(0x1234))));

    HANDLE self = OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId());
    REQUIRE(self != nullptr);
    CHECK(IsValidProcessHandle(self));
    CloseHandle(self);
}

/** @test ConvertAnsiToWideName converts ASCII names and rejects invalid inputs. */
TEST_CASE("ConvertAnsiToWideName converts ASCII names and rejects invalid inputs",
          "[internal][string]") {
    std::wstring out;

    SECTION("null pointer fails and clears the output") {
        out = L"stale";
        CHECK_FALSE(ConvertAnsiToWideName(nullptr, out));
        CHECK(out.empty());
    }

    SECTION("empty string fails and clears the output") {
        out = L"stale";
        CHECK_FALSE(ConvertAnsiToWideName("", out));
        CHECK(out.empty());
    }

    SECTION("pointer to a lone terminator is an empty name") {
        out = L"stale";
        CHECK_FALSE(ConvertAnsiToWideName("\0", out));
        CHECK(out.empty());
    }

    SECTION("single character") {
        REQUIRE(ConvertAnsiToWideName("x", out));
        CHECK(out == L"x");
    }

    SECTION("ASCII executable names convert exactly") {
        REQUIRE(ConvertAnsiToWideName("Battle_Realms_F.exe", out));
        CHECK(out == L"Battle_Realms_F.exe");

        REQUIRE(ConvertAnsiToWideName("a.b-c_d 09", out));
        CHECK(out == L"a.b-c_d 09");
    }

    SECTION("long ASCII name") {
        const std::string longName(4096, 'k');
        REQUIRE(ConvertAnsiToWideName(longName.c_str(), out));
        REQUIRE(out.size() == longName.size());
        CHECK(out.front() == L'k');
        CHECK(out.back() == L'k');
    }

    SECTION("successive calls do not leak state between conversions") {
        REQUIRE(ConvertAnsiToWideName("first.exe", out));
        REQUIRE(ConvertAnsiToWideName("second.exe", out));
        CHECK(out == L"second.exe");

        CHECK_FALSE(ConvertAnsiToWideName("", out));
        CHECK(out.empty());
    }

    SECTION("non-ASCII text converts when the system code page can represent it") {
        // ConvertAnsiToWideName assumes the ambient system ANSI code page
        // (CP_ACP), which differs per machine. Probe characters drawn from the
        // common Windows code page families and take the first one this code
        // page can encode AND decode unchanged, so the section exercises real
        // non-ASCII conversion on virtually every locale instead of asserting
        // a single Latin-1 guess. The skip below remains a last resort for
        // degenerate configurations only.
        constexpr wchar_t probes[] = {
            L'\x00E9', // e-acute       - Latin-1 family (1252 & friends)
            L'\x00FC', // u-umlaut      - Latin-1 family
            L'\x03B1', // alpha         - Greek (1253, KS X 1001, Big5)
            L'\x0410', // Cyrillic A    - Cyrillic (1251)
            L'\x05D0', // alef          - Hebrew (1255)
            L'\x0627', // alef          - Arabic (1256)
            L'\x4E2D', // CJK ideograph - Simplified/Traditional (936/950)
            L'\x3042', // hiragana A    - Shift-JIS (932, KS X 1001)
        };

        // Best-fit mappings (e.g. e-acute -> 'e') preserve LENGTH while
        // changing content, so each probe must be decoded and compared as
        // characters; a size-only check would accept lossy round trips.
        wchar_t selected = L'\0';
        for (const wchar_t probe : probes) {
            const int encodedSize = WideCharToMultiByte(
                CP_ACP, 0, &probe, 1, nullptr, 0, nullptr, nullptr);
            if (encodedSize <= 0)
                continue;

            std::string encoded(static_cast<size_t>(encodedSize), '\0');
            if (WideCharToMultiByte(
                    CP_ACP, 0, &probe, 1,
                    encoded.data(), encodedSize, nullptr, nullptr) != encodedSize)
                continue;

            const int decodedSize = MultiByteToWideChar(
                CP_ACP, 0, encoded.data(), encodedSize, nullptr, 0);
            if (decodedSize != 1)
                continue;

            wchar_t decoded = L'\0';
            if (MultiByteToWideChar(
                    CP_ACP, 0, encoded.data(), encodedSize, &decoded, 1) != 1)
                continue;
            if (decoded == probe) {
                selected = probe;
                break;
            }
        }

        if (selected == L'\0')
            SKIP("System code page round-trips none of the probe characters; "
                 "nothing locale-independent left to verify.");

        std::wstring wideName = L"Battle";
        wideName += selected;
        wideName += L".exe";

        const int ansiSize = WideCharToMultiByte(
            CP_ACP, 0, wideName.c_str(), -1, nullptr, 0, nullptr, nullptr);
        REQUIRE(ansiSize > 1);

        std::string ansiName(static_cast<size_t>(ansiSize), '\0');
        REQUIRE(WideCharToMultiByte(
            CP_ACP, 0, wideName.c_str(), -1,
            ansiName.data(), ansiSize, nullptr, nullptr) == ansiSize);

        REQUIRE(ConvertAnsiToWideName(ansiName.c_str(), out));
        CHECK(out == wideName);
    }
}

// ===========================================================================
// TESTABLE_STATIC MakeRangeAccessible — deterministic fake-callable matrix
//
// The templated walker takes injectable query/protect callables, so every
// failure path (query failure, protect failure, defensive misreports) can be
// reached deterministically. Real-API behavior is covered separately below.
// ===========================================================================

/** @test Zero-size requests succeed without calling the query or protect callables. */
TEST_CASE("MakeRangeAccessible: zero-size requests are no-ops", "[internal][mock]") {
    mock::FakeQuery query;
    mock::FakeProtect protect;
    std::vector<PageProtectEntry> entries;

    CHECK(MakeRangeAccessible(
        nullptr, 0, entries, query, protect, WritableProtection, true));
    CHECK(MakeRangeAccessible(
        reinterpret_cast<LPVOID>(0x10000), 0, entries, query, protect,
        WritableProtection, false));

    CHECK(entries.empty());
    CHECK(query.calls == 0);
    CHECK(query.queriedAddresses.empty());
    CHECK(protect.calls.empty());
}

/** @test A null address with a non-zero size fails before any query. */
TEST_CASE("MakeRangeAccessible: null address with non-zero size fails", "[internal][mock]") {
    mock::FakeQuery query;
    mock::FakeProtect protect;
    std::vector<PageProtectEntry> entries;

    CHECK_FALSE(MakeRangeAccessible(
        nullptr, 4096, entries, query, protect, WritableProtection, true));

    CHECK(entries.empty());
    CHECK(query.calls == 0);
    CHECK(protect.calls.empty());
}

/** @test A range whose end would overflow the address space fails before any query. */
TEST_CASE("MakeRangeAccessible: overflowing range fails before querying", "[internal][mock]") {
    mock::FakeQuery query;
    mock::FakeProtect protect;
    std::vector<PageProtectEntry> entries;

    const auto address = reinterpret_cast<LPVOID>(
        std::numeric_limits<uintptr_t>::max() - 10);

    CHECK_FALSE(MakeRangeAccessible(
        address, 100, entries, query, protect, WritableProtection, true));

    CHECK(entries.empty());
    CHECK(query.calls == 0);
    CHECK(protect.calls.empty());
}

/** @test A single homogeneous region is changed once and recorded exactly. */
TEST_CASE("MakeRangeAccessible: changes one region and records the entry", "[internal][mock]") {
    mock::FakeQuery query;
    query.regions = {{0x10000, 0x10000, MEM_COMMIT, PAGE_READONLY}};

    mock::FakeProtect protect;
    std::vector<PageProtectEntry> entries;

    CHECK(MakeRangeAccessible(
        reinterpret_cast<LPVOID>(0x10000), 0x8000, entries, query, protect,
        WritableProtection, true));

    REQUIRE(protect.calls.size() == 1);
    CHECK(protect.calls[0].base == reinterpret_cast<LPVOID>(0x10000));
    CHECK(protect.calls[0].size == 0x8000);
    CHECK(protect.calls[0].newProtect == PAGE_READWRITE);
    CHECK(protect.calls[0].outOldProtect == 0x5A5A5A5Au);

    REQUIRE(entries.size() == 1);
    CHECK(entries[0].base == reinterpret_cast<LPVOID>(0x10000));
    CHECK(entries[0].size == 0x8000);
    // The entry must record the protection reported by the protect call's
    // out-parameter (0x5A5A5A5A marker), not any value seen while querying.
    CHECK(entries[0].oldProtect == 0x5A5A5A5Au);

    // The walker queried exactly the range start; the region covered the rest.
    REQUIRE(query.queriedAddresses.size() == 1);
    CHECK(query.queriedAddresses[0] == 0x10000);
}

/** @test The patch is clamped to the requested range inside a larger region. */
TEST_CASE("MakeRangeAccessible: clamps the patch to the requested range", "[internal][mock]") {
    mock::FakeQuery query;
    query.regions = {{0x10000, 0x40000, MEM_COMMIT, PAGE_READONLY}};

    mock::FakeProtect protect;
    std::vector<PageProtectEntry> entries;

    CHECK(MakeRangeAccessible(
        reinterpret_cast<LPVOID>(0x20000), 0x10000, entries, query, protect,
        WritableProtection, true));

    REQUIRE(protect.calls.size() == 1);
    CHECK(protect.calls[0].base == reinterpret_cast<LPVOID>(0x20000));
    CHECK(protect.calls[0].size == 0x10000);

    REQUIRE(entries.size() == 1);
    CHECK(entries[0].base == reinterpret_cast<LPVOID>(0x20000));
    CHECK(entries[0].size == 0x10000);
}

/** @test Contiguous regions produce one clamped entry each, in walk order. */
TEST_CASE("MakeRangeAccessible: walks contiguous regions with one entry each",
          "[internal][mock]") {
    mock::FakeQuery query;
    query.regions = {
        {0x10000, 0x8000, MEM_COMMIT, PAGE_READONLY},
        {0x18000, 0x8000, MEM_COMMIT, PAGE_EXECUTE_READ},
    };

    mock::FakeProtect protect;
    std::vector<PageProtectEntry> entries;

    CHECK(MakeRangeAccessible(
        reinterpret_cast<LPVOID>(0x10000), 0x10000, entries, query, protect,
        WritableProtection, true));

    REQUIRE(protect.calls.size() == 2);
    CHECK(protect.calls[0].base == reinterpret_cast<LPVOID>(0x10000));
    CHECK(protect.calls[0].size == 0x8000);
    CHECK(protect.calls[0].newProtect == PAGE_READWRITE);
    CHECK(protect.calls[1].base == reinterpret_cast<LPVOID>(0x18000));
    CHECK(protect.calls[1].size == 0x8000);
    CHECK(protect.calls[1].newProtect == PAGE_EXECUTE_READWRITE);

    REQUIRE(entries.size() == 2);
    CHECK(entries[0].base == reinterpret_cast<LPVOID>(0x10000));
    CHECK(entries[0].size == 0x8000);
    CHECK(entries[1].base == reinterpret_cast<LPVOID>(0x18000));
    CHECK(entries[1].size == 0x8000);

    REQUIRE(query.queriedAddresses.size() == 2);
    CHECK(query.queriedAddresses[0] == 0x10000);
    CHECK(query.queriedAddresses[1] == 0x18000);
}

/** @test A region larger than the requested range is not touched beyond the range. */
TEST_CASE("MakeRangeAccessible: region extending beyond the range is clamped",
          "[internal][mock]") {
    mock::FakeQuery query;
    query.regions = {{0x10000, 0x40000, MEM_COMMIT, PAGE_READONLY}};

    mock::FakeProtect protect;
    std::vector<PageProtectEntry> entries;

    CHECK(MakeRangeAccessible(
        reinterpret_cast<LPVOID>(0x18000), 0x8000, entries, query, protect,
        WritableProtection, true));

    REQUIRE(protect.calls.size() == 1);
    CHECK(protect.calls[0].base == reinterpret_cast<LPVOID>(0x18000));
    CHECK(protect.calls[0].size == 0x8000);

    // One query: the walker jumps to the region end, past the range end.
    REQUIRE(query.queriedAddresses.size() == 1);
    CHECK(query.queriedAddresses[0] == 0x18000);
}

/** @test An identity mapping requests no change and records nothing. */
TEST_CASE("MakeRangeAccessible: identity mapping performs no protect calls",
          "[internal][mock]") {
    mock::FakeQuery query;
    query.regions = {{0x10000, 0x8000, MEM_COMMIT, PAGE_READWRITE}};

    mock::FakeProtect protect;
    std::vector<PageProtectEntry> entries;

    CHECK(MakeRangeAccessible(
        reinterpret_cast<LPVOID>(0x10000), 0x8000, entries, query, protect,
        MockIdentityProtection, true));

    CHECK(protect.calls.empty());
    CHECK(entries.empty());
    CHECK(query.queriedAddresses.size() == 1);
}

/** @test The injected mapping function decides the requested protection. */
TEST_CASE("MakeRangeAccessible: honors the injected mapping function", "[internal][mock]") {
    mock::FakeQuery query;
    query.regions = {{0x10000, 0x8000, MEM_COMMIT, PAGE_READONLY}};

    mock::FakeProtect protect;
    std::vector<PageProtectEntry> entries;

    SECTION("custom mapping") {
        CHECK(MakeRangeAccessible(
            reinterpret_cast<LPVOID>(0x10000), 0x8000, entries, query, protect,
            MockForceNoAccess, true));

        REQUIRE(protect.calls.size() == 1);
        CHECK(protect.calls[0].newProtect == PAGE_NOACCESS);
    }

    SECTION("library WritableProtection mapping") {
        CHECK(MakeRangeAccessible(
            reinterpret_cast<LPVOID>(0x10000), 0x8000, entries, query, protect,
            WritableProtection, true));

        REQUIRE(protect.calls.size() == 1);
        CHECK(protect.calls[0].newProtect == PAGE_READWRITE);
    }

    SECTION("library ReadableProtection mapping") {
        // PAGE_READONLY is already its own readable equivalent, so for that
        // input ReadableProtection is an identity mapping and the walker must
        // issue NO protect call — the contract pinned by the identity-mapping
        // test above (this section previously contradicted it by seeding a
        // readable region yet expecting a call). Seed a writable region so
        // the mapper has a real downgrade to perform.
        query.regions = {{0x10000, 0x8000, MEM_COMMIT, PAGE_READWRITE}};

        CHECK(MakeRangeAccessible(
            reinterpret_cast<LPVOID>(0x10000), 0x8000, entries, query, protect,
            ReadableProtection, true));

        REQUIRE(protect.calls.size() == 1);
        CHECK(protect.calls[0].newProtect == PAGE_READONLY);
    }
}

/** @test A query failure on the first region fails without calling protect. */
TEST_CASE("MakeRangeAccessible: query failure on the first region fails cleanly",
          "[internal][mock]") {
    mock::FakeQuery query;
    query.failAtCall = 1;
    query.regions = {{0x10000, 0x8000, MEM_COMMIT, PAGE_READONLY}};

    mock::FakeProtect protect;
    std::vector<PageProtectEntry> entries;

    CHECK_FALSE(MakeRangeAccessible(
        reinterpret_cast<LPVOID>(0x10000), 0x8000, entries, query, protect,
        WritableProtection, true));

    CHECK(entries.empty());
    CHECK(protect.calls.empty());
}

/** @test A query failure on a later region keeps the entries recorded so far. */
TEST_CASE("MakeRangeAccessible: query failure on a later region keeps earlier entries",
          "[internal][mock]") {
    mock::FakeQuery query;
    query.failAtCall = 2;
    query.regions = {
        {0x10000, 0x8000, MEM_COMMIT, PAGE_READONLY},
        {0x18000, 0x8000, MEM_COMMIT, PAGE_READONLY},
    };

    mock::FakeProtect protect;
    std::vector<PageProtectEntry> entries;

    CHECK_FALSE(MakeRangeAccessible(
        reinterpret_cast<LPVOID>(0x10000), 0x10000, entries, query, protect,
        WritableProtection, true));

    REQUIRE(entries.size() == 1);
    CHECK(entries[0].base == reinterpret_cast<LPVOID>(0x10000));
    CHECK(entries[0].size == 0x8000);
    CHECK(protect.calls.size() == 1);
}

/** @test A protect failure on the first region fails without recording entries. */
TEST_CASE("MakeRangeAccessible: protect failure on the first region fails cleanly",
          "[internal][mock]") {
    mock::FakeQuery query;
    query.regions = {{0x10000, 0x8000, MEM_COMMIT, PAGE_READONLY}};

    mock::FakeProtect protect;
    protect.failAtCall = 1;
    std::vector<PageProtectEntry> entries;

    CHECK_FALSE(MakeRangeAccessible(
        reinterpret_cast<LPVOID>(0x10000), 0x8000, entries, query, protect,
        WritableProtection, true));

    CHECK(entries.empty());
    CHECK(protect.calls.empty());
}

/** @test A protect failure on a later region keeps the entries recorded so far. */
TEST_CASE("MakeRangeAccessible: protect failure on a later region keeps earlier entries",
          "[internal][mock]") {
    mock::FakeQuery query;
    query.regions = {
        {0x10000, 0x8000, MEM_COMMIT, PAGE_READONLY},
        {0x18000, 0x8000, MEM_COMMIT, PAGE_EXECUTE_READ},
    };

    mock::FakeProtect protect;
    protect.failAtCall = 2;
    std::vector<PageProtectEntry> entries;

    CHECK_FALSE(MakeRangeAccessible(
        reinterpret_cast<LPVOID>(0x10000), 0x10000, entries, query, protect,
        WritableProtection, true));

    REQUIRE(entries.size() == 1);
    CHECK(entries[0].base == reinterpret_cast<LPVOID>(0x10000));
    CHECK(protect.calls.size() == 1);
}

/** @test A successful query reporting a zero RegionSize fails defensively. */
TEST_CASE("MakeRangeAccessible: zero RegionSize fails defensively", "[internal][mock]") {
    mock::FakeQuery query;
    mock::Region region;
    region.base = 0x10000;
    region.size = 0x8000;
    region.protect = PAGE_READONLY;
    region.reportZeroSize = true;
    query.regions = {region};

    mock::FakeProtect protect;
    std::vector<PageProtectEntry> entries;

    CHECK_FALSE(MakeRangeAccessible(
        reinterpret_cast<LPVOID>(0x10000), 0x8000, entries, query, protect,
        WritableProtection, true));

    CHECK(entries.empty());
    CHECK(protect.calls.empty());
}

/** @test A region not containing the queried address fails defensively (no forward progress). */
TEST_CASE("MakeRangeAccessible: non-containing region fails defensively", "[internal][mock]") {
    mock::FakeQuery query;
    mock::Region region;
    region.base = 0x10000;
    region.size = 0x1000;
    region.protect = PAGE_READONLY;
    // The query succeeds but reports a region base past the requested range.
    region.reportBaseOverride = 0x90000;
    query.regions = {region};

    mock::FakeProtect protect;
    std::vector<PageProtectEntry> entries;

    CHECK_FALSE(MakeRangeAccessible(
        reinterpret_cast<LPVOID>(0x10000), 0x2000, entries, query, protect,
        WritableProtection, true));

    CHECK(entries.empty());
    CHECK(protect.calls.empty());
}

/** @test A RegionSize that would overflow the address space fails defensively. */
TEST_CASE("MakeRangeAccessible: RegionSize overflow fails defensively", "[internal][mock]") {
    mock::FakeQuery query;
    mock::Region region;
    region.base = std::numeric_limits<uintptr_t>::max() - 0x1000;
    region.size = 0x1000;
    region.protect = PAGE_READONLY;
    region.reportSizeOverride = 0x2000; // base + size overflows uintptr_t
    query.regions = {region};

    mock::FakeProtect protect;
    std::vector<PageProtectEntry> entries;

    CHECK_FALSE(MakeRangeAccessible(
        reinterpret_cast<LPVOID>(std::numeric_limits<uintptr_t>::max() - 0x1000),
        0x1000, entries, query, protect, WritableProtection, true));

    CHECK(entries.empty());
    CHECK(protect.calls.empty());
}

/** @test Uncommitted states are rejected before any protection change. */
TEST_CASE("MakeRangeAccessible: uncommitted regions are rejected", "[internal][mock]") {
    mock::FakeProtect protect;
    std::vector<PageProtectEntry> entries;

    SECTION("MEM_RESERVE") {
        mock::FakeQuery query;
        query.regions = {{0x10000, 0x8000, MEM_RESERVE, 0}};
        CHECK_FALSE(MakeRangeAccessible(
            reinterpret_cast<LPVOID>(0x10000), 0x8000, entries, query, protect,
            WritableProtection, true));
    }

    SECTION("MEM_FREE") {
        mock::FakeQuery query;
        query.regions = {{0x10000, 0x8000, MEM_FREE, 0}};
        CHECK_FALSE(MakeRangeAccessible(
            reinterpret_cast<LPVOID>(0x10000), 0x8000, entries, query, protect,
            WritableProtection, true));
    }

    CHECK(entries.empty());
    CHECK(protect.calls.empty());
}

/** @test Guard pages are rejected exactly when rejectGuardPages is set. */
TEST_CASE("MakeRangeAccessible: guard pages follow rejectGuardPages", "[internal][mock]") {
    mock::FakeQuery query;
    query.regions = {{0x10000, 0x8000, MEM_COMMIT, PAGE_READONLY | PAGE_GUARD}};

    mock::FakeProtect protect;
    std::vector<PageProtectEntry> entries;

    SECTION("rejectGuardPages = true") {
        CHECK_FALSE(MakeRangeAccessible(
            reinterpret_cast<LPVOID>(0x10000), 0x8000, entries, query, protect,
            WritableProtection, true));

        CHECK(entries.empty());
        CHECK(protect.calls.empty());
    }

    SECTION("rejectGuardPages = false") {
        CHECK(MakeRangeAccessible(
            reinterpret_cast<LPVOID>(0x10000), 0x8000, entries, query, protect,
            WritableProtection, false));

        REQUIRE(protect.calls.size() == 1);
        // WritableProtection strips the guard modifier from the request.
        CHECK(protect.calls[0].newProtect == PAGE_READWRITE);

        REQUIRE(entries.size() == 1);
        CHECK(entries[0].oldProtect == 0x5A5A5A5Au);
    }
}

// ===========================================================================
// TESTABLE_STATIC RestoreLocal / RestoreRemote
//
// Restoration boundary checks use the end-to-end convention: the guard is
// constructed BEFORE the test's own setup changes, so after Restore* the
// window must equal the true original state.
// ===========================================================================

/** @test RestoreLocal restores a single recorded entry across the whole boundary window. */
TEST_CASE("RestoreLocal restores a single recorded entry", "[internal][local][protection]") {
    constexpr SIZE_T pageSize = 4096;
    // Three pages; the scope is the middle page so the boundary window
    // [scope - pageSize, scope + 2*pageSize] covers all three pages.
    LocalAllocation memory(3 * pageSize, PAGE_READWRITE);
    REQUIRE(memory);

    const auto scope = static_cast<std::uint8_t*>(memory.address) + pageSize;

    // End-to-end boundary snapshot while everything is still READWRITE.
    BoundaryGuard guard(nullptr, memory.address, 3 * pageSize, scope, pageSize);

    // Setup: scope becomes READONLY; the entry records the original READWRITE.
    DWORD previous = 0;
    REQUIRE(VirtualProtect(scope, pageSize, PAGE_READONLY, &previous));
    REQUIRE(previous == PAGE_READWRITE);
    guard.RequireWindowOutsideScopeUnchanged(); // setup only touched the scope

    std::vector<PageProtectEntry> entries;
    entries.push_back({scope, pageSize, PAGE_READWRITE});

    CHECK(RestoreLocal(entries, 0));
    CHECK(entries.empty());

    // Phase 3: the entire window is byte- and protection-identical again.
    guard.RequireWindowRestored();
    CHECK(QueryProtectionLocal(scope) == PAGE_READWRITE);
}

/** @test RestoreLocal honors startIndex by leaving lower-indexed entries unrestored. */
TEST_CASE("RestoreLocal startIndex leaves lower entries untouched",
          "[internal][local][protection]") {
    constexpr SIZE_T pageSize = 4096;
    // Six pages: entries live on pages 1, 2 and 3; each page's boundary window
    // [scope - pageSize, scope + 2*pageSize] fits inside the allocation.
    LocalAllocation memory(6 * pageSize, PAGE_READWRITE);
    REQUIRE(memory);

    const auto page1 = static_cast<std::uint8_t*>(memory.address) + 1 * pageSize;
    const auto page2 = static_cast<std::uint8_t*>(memory.address) + 2 * pageSize;
    const auto page3 = static_cast<std::uint8_t*>(memory.address) + 3 * pageSize;

    BoundaryGuard guard1(nullptr, memory.address, 6 * pageSize, page1, pageSize);
    BoundaryGuard guard2(nullptr, memory.address, 6 * pageSize, page2, pageSize);
    BoundaryGuard guard3(nullptr, memory.address, 6 * pageSize, page3, pageSize);

    // Setup: all three pages become NOACCESS; entries record the original RW.
    DWORD previous = 0;
    REQUIRE(VirtualProtect(page1, pageSize, PAGE_NOACCESS, &previous));
    REQUIRE(VirtualProtect(page2, pageSize, PAGE_NOACCESS, &previous));
    REQUIRE(VirtualProtect(page3, pageSize, PAGE_NOACCESS, &previous));

    std::vector<PageProtectEntry> entries;
    entries.push_back({page1, pageSize, PAGE_READWRITE});
    entries.push_back({page2, pageSize, PAGE_READWRITE});
    entries.push_back({page3, pageSize, PAGE_READWRITE});

    // startIndex = 1: e2 and e1 are restored in reverse order; e0 is left alone.
    CHECK(RestoreLocal(entries, 1));
    REQUIRE(entries.size() == 1);
    CHECK(entries[0].base == page1);

    CHECK(QueryProtectionLocal(page1) == PAGE_NOACCESS); // deliberately untouched
    CHECK(QueryProtectionLocal(page2) == PAGE_READWRITE);
    CHECK(QueryProtectionLocal(page3) == PAGE_READWRITE);

    // Cleanup first: guard1/guard2 windows overlap page1, so the full-window
    // boundary checks below need page1 back at its snapshot protection before
    // they can hold (its deliberate NOACCESS state was already verified above).
    REQUIRE(VirtualProtect(page1, pageSize, PAGE_READWRITE, &previous));

    // Boundary: pages 2 and 3 (and their windows) are fully restored.
    guard2.RequireWindowRestored();
    guard3.RequireWindowRestored();
    guard1.RequireWindowRestored();
}

/** @test RestoreLocal restores in reverse order, proven through overlapping entries. */
TEST_CASE("RestoreLocal restores entries in reverse order",
          "[internal][local][protection]") {
    constexpr SIZE_T pageSize = 4096;
    // Six pages; the scope spans pages 2-3 so its boundary window fits.
    LocalAllocation memory(6 * pageSize, PAGE_READWRITE);
    REQUIRE(memory);

    const auto scope = static_cast<std::uint8_t*>(memory.address) + 2 * pageSize;

    BoundaryGuard guard(nullptr, memory.address, 6 * pageSize, scope, 2 * pageSize);

    // Setup with two overlapping changes:
    //   A = {scope, 2p, RW}      recorded when pages 2-3 become EXECUTE_READ
    //   B = {scope, 1p, ER}      recorded when page 2 becomes NOACCESS
    // Reverse-order restoration applies B first, then A; a forward-order
    // implementation would leave page 2 at EXECUTE_READ instead of READWRITE.
    DWORD previous = 0;
    REQUIRE(VirtualProtect(scope, 2 * pageSize, PAGE_EXECUTE_READ, &previous));
    REQUIRE(previous == PAGE_READWRITE);
    const PageProtectEntry entryA{scope, 2 * pageSize, PAGE_READWRITE};

    REQUIRE(VirtualProtect(scope, pageSize, PAGE_NOACCESS, &previous));
    REQUIRE(previous == PAGE_EXECUTE_READ);
    const PageProtectEntry entryB{scope, pageSize, PAGE_EXECUTE_READ};

    std::vector<PageProtectEntry> entries{entryA, entryB};

    CHECK(RestoreLocal(entries, 0));
    CHECK(entries.empty());

    // Final state is only reachable through reverse-order restoration.
    CHECK(QueryProtectionLocal(scope) == PAGE_READWRITE);
    CHECK(QueryProtectionLocal(
              static_cast<std::uint8_t*>(scope) + pageSize) == PAGE_READWRITE);

    guard.RequireWindowRestored();
}

/** @test RestoreLocal continues best-effort and reports failure when one entry cannot be restored. */
TEST_CASE("RestoreLocal continues best-effort after a failed restore",
          "[internal][local][protection]") {
    constexpr SIZE_T pageSize = 4096;
    // Three pages; page 1 is decommitted so restoring it fails deterministically.
    LocalAllocation memory(3 * pageSize, PAGE_READWRITE);
    REQUIRE(memory);

    const auto deadPage = static_cast<std::uint8_t*>(memory.address) + 1 * pageSize;
    const auto livePage = static_cast<std::uint8_t*>(memory.address) + 2 * pageSize;

    // Setup: live page becomes READONLY (entry records RW); dead page is decommitted.
    DWORD previous = 0;
    REQUIRE(VirtualProtect(livePage, pageSize, PAGE_READONLY, &previous));
    REQUIRE(VirtualFree(deadPage, pageSize, MEM_DECOMMIT));

    SECTION("failure recorded first is applied first and skipped") {
        std::vector<PageProtectEntry> entries;
        entries.push_back({deadPage, pageSize, PAGE_READWRITE});
        entries.push_back({livePage, pageSize, PAGE_READWRITE});

        // Reverse order: the live entry is restored before the dead one fails.
        CHECK_FALSE(RestoreLocal(entries, 0));
        CHECK(entries.empty());
        CHECK(QueryProtectionLocal(livePage) == PAGE_READWRITE);
    }

    SECTION("failure applied last does not prevent earlier work") {
        std::vector<PageProtectEntry> entries;
        entries.push_back({livePage, pageSize, PAGE_READWRITE});
        entries.push_back({deadPage, pageSize, PAGE_READWRITE});

        // Reverse order: the dead entry fails first; the loop must continue.
        CHECK_FALSE(RestoreLocal(entries, 0));
        CHECK(entries.empty());
        CHECK(QueryProtectionLocal(livePage) == PAGE_READWRITE);
    }
}

/** @test RestoreLocal treats an empty range and startIndex == size as no-ops. */
TEST_CASE("RestoreLocal no-op cases", "[internal][local][protection]") {
    constexpr SIZE_T pageSize = 4096;
    LocalAllocation memory(3 * pageSize, PAGE_READWRITE);
    REQUIRE(memory);

    const auto scope = static_cast<std::uint8_t*>(memory.address) + pageSize;

    std::vector<PageProtectEntry> entries;

    CHECK(RestoreLocal(entries, 0));
    CHECK(entries.empty());

    DWORD previous = 0;
    REQUIRE(VirtualProtect(scope, pageSize, PAGE_NOACCESS, &previous));
    entries.push_back({scope, pageSize, PAGE_NOACCESS});

    // startIndex == size: nothing is restored, the vector is unchanged.
    CHECK(RestoreLocal(entries, 1));
    REQUIRE(entries.size() == 1);
    CHECK(QueryProtectionLocal(scope) == PAGE_NOACCESS);
}

/** @test RestoreRemote restores a single entry through the pseudo-handle. */
TEST_CASE("RestoreRemote restores a single entry via the pseudo-handle",
          "[internal][local][remote][protection]") {
    constexpr SIZE_T pageSize = 4096;
    LocalAllocation memory(3 * pageSize, PAGE_READWRITE);
    REQUIRE(memory);

    const auto scope = static_cast<std::uint8_t*>(memory.address) + pageSize;

    BoundaryGuard guard(GetCurrentProcess(), memory.address, 3 * pageSize, scope, pageSize);

    DWORD previous = 0;
    REQUIRE(VirtualProtect(scope, pageSize, PAGE_READONLY, &previous));

    std::vector<PageProtectEntry> entries;
    entries.push_back({scope, pageSize, PAGE_READWRITE});

    CHECK(RestoreRemote(GetCurrentProcess(), entries, 0));
    CHECK(entries.empty());
    guard.RequireWindowRestored();
    CHECK(QueryProtectionLocal(scope) == PAGE_READWRITE);
}

/** @test RestoreRemote restores a single entry through a real, fully privileged self handle. */
TEST_CASE("RestoreRemote restores a single entry via a real self handle",
          "[internal][local][remote][protection]") {
    HANDLE self = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
            PROCESS_VM_OPERATION,
        FALSE,
        GetCurrentProcessId());
    REQUIRE(self != nullptr);

    constexpr SIZE_T pageSize = 4096;
    LocalAllocation memory(3 * pageSize, PAGE_READWRITE);
    REQUIRE(memory);

    const auto scope = static_cast<std::uint8_t*>(memory.address) + pageSize;

    BoundaryGuard guard(self, memory.address, 3 * pageSize, scope, pageSize);

    DWORD previous = 0;
    REQUIRE(VirtualProtect(scope, pageSize, PAGE_READONLY, &previous));

    std::vector<PageProtectEntry> entries;
    entries.push_back({scope, pageSize, PAGE_READWRITE});

    CHECK(RestoreRemote(self, entries, 0));
    CHECK(entries.empty());
    guard.RequireWindowRestored();
    CHECK(QueryProtectionLocal(scope) == PAGE_READWRITE);

    CloseHandle(self);
}

/** @test RestoreRemote honors startIndex exactly like the local variant. */
TEST_CASE("RestoreRemote startIndex leaves lower entries untouched",
          "[internal][local][remote][protection]") {
    constexpr SIZE_T pageSize = 4096;
    LocalAllocation memory(6 * pageSize, PAGE_READWRITE);
    REQUIRE(memory);

    const auto page1 = static_cast<std::uint8_t*>(memory.address) + 1 * pageSize;
    const auto page2 = static_cast<std::uint8_t*>(memory.address) + 2 * pageSize;
    const auto page3 = static_cast<std::uint8_t*>(memory.address) + 3 * pageSize;

    DWORD previous = 0;
    REQUIRE(VirtualProtect(page1, pageSize, PAGE_NOACCESS, &previous));
    REQUIRE(VirtualProtect(page2, pageSize, PAGE_NOACCESS, &previous));
    REQUIRE(VirtualProtect(page3, pageSize, PAGE_NOACCESS, &previous));

    std::vector<PageProtectEntry> entries;
    entries.push_back({page1, pageSize, PAGE_READWRITE});
    entries.push_back({page2, pageSize, PAGE_READWRITE});
    entries.push_back({page3, pageSize, PAGE_READWRITE});

    CHECK(RestoreRemote(GetCurrentProcess(), entries, 1));
    REQUIRE(entries.size() == 1);
    CHECK(entries[0].base == page1);

    CHECK(QueryProtectionLocal(page1) == PAGE_NOACCESS);
    CHECK(QueryProtectionLocal(page2) == PAGE_READWRITE);
    CHECK(QueryProtectionLocal(page3) == PAGE_READWRITE);

    // Cleanup.
    REQUIRE(VirtualProtect(page1, pageSize, PAGE_READWRITE, &previous));
}

/** @test RestoreRemote fails for invalid handles yet still clears the entries. */
TEST_CASE("RestoreRemote invalid handles fail but clear the entries",
          "[internal][remote][errors]") {
    constexpr SIZE_T pageSize = 4096;
    LocalAllocation memory(3 * pageSize, PAGE_READWRITE);
    REQUIRE(memory);

    const auto scope = static_cast<std::uint8_t*>(memory.address) + pageSize;

    DWORD previous = 0;
    REQUIRE(VirtualProtect(scope, pageSize, PAGE_READONLY, &previous));

    std::vector<PageProtectEntry> entries;
    entries.push_back({scope, pageSize, PAGE_READWRITE});

    SECTION("null handle") {
        CHECK_FALSE(RestoreRemote(nullptr, entries, 0));
    }

    SECTION("stale closed handle") {
        // (HANDLE)-1 is the valid current-process pseudo handle, so a real
        // invalid handle is required: a handle to this process that has been
        // closed again.
        CHECK_FALSE(RestoreRemote(MakeStaleProcessHandle(), entries, 0));
    }

    // The entries are consumed even when every restore call fails; the page
    // itself keeps the protection the failed call could not change.
    CHECK(entries.empty());
    CHECK(QueryProtectionLocal(scope) == PAGE_READONLY);

    // Cleanup through a working handle.
    std::vector<PageProtectEntry> cleanup;
    cleanup.push_back({scope, pageSize, PAGE_READWRITE});
    CHECK(RestoreRemote(GetCurrentProcess(), cleanup, 0));
}

/** @test RestoreRemote reports failure when the handle lacks VM_OPERATION access. */
TEST_CASE("RestoreRemote without VM_OPERATION fails and leaves protection unchanged",
          "[internal][remote][errors]") {
    // Query-only handle: VirtualProtectEx requires PROCESS_VM_OPERATION.
    HANDLE restricted = OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId());
    REQUIRE(restricted != nullptr);

    constexpr SIZE_T pageSize = 4096;
    LocalAllocation memory(3 * pageSize, PAGE_READWRITE);
    REQUIRE(memory);

    const auto scope = static_cast<std::uint8_t*>(memory.address) + pageSize;

    DWORD previous = 0;
    REQUIRE(VirtualProtect(scope, pageSize, PAGE_READONLY, &previous));

    std::vector<PageProtectEntry> entries;
    entries.push_back({scope, pageSize, PAGE_READWRITE});

    CHECK_FALSE(RestoreRemote(restricted, entries, 0));
    CHECK(entries.empty());
    CHECK(QueryProtectionLocal(scope) == PAGE_READONLY);

    CloseHandle(restricted);

    // Cleanup through a working handle.
    std::vector<PageProtectEntry> cleanup;
    cleanup.push_back({scope, pageSize, PAGE_READWRITE});
    CHECK(RestoreRemote(GetCurrentProcess(), cleanup, 0));
}

/** @test RestoreRemote restores protections inside the live game target. */
TEST_CASE("RestoreRemote restores protections in the live game",
          "[remote][internal][protection]") {
    ProcessFixture process;
    if (!process.available())
        SKIP(kSkipMessage);

    constexpr SIZE_T pageSize = 4096;
    // Three pages so the middle-page scope has a full boundary window.
    RemoteAllocation memory(process.process, 3 * pageSize, PAGE_READWRITE);
    REQUIRE(memory);

    const auto scope = static_cast<std::uint8_t*>(memory.address) + pageSize;

    // End-to-end boundary snapshot while everything is still READWRITE.
    BoundaryGuard guard(process.process, memory.address, 3 * pageSize, scope, pageSize);

    DWORD previous = 0;
    REQUIRE(VirtualProtectEx(
        process.process, scope, pageSize, PAGE_READONLY, &previous));
    guard.RequireWindowOutsideScopeUnchanged(); // setup only touched the scope

    std::vector<PageProtectEntry> entries;
    entries.push_back({scope, pageSize, PAGE_READWRITE});

    CHECK(RestoreRemote(process.process, entries, 0));
    CHECK(entries.empty());

    // Phase 3: the whole window inside the game process is restored.
    guard.RequireWindowRestored();
    CHECK(QueryProtection(process.process, scope) == PAGE_READWRITE);
}

// ===========================================================================
// TESTABLE_STATIC MakeLocalWritable / MakeLocalReadable — real memory manager
//
// Every scenario records the three-phase boundary check around a page-aligned
// scope; layouts give the window [scope - size, scope + 2*size] room inside
// memory the test allocated. Multi-region and hole layouts exercise the
// region-walking contract against the real VirtualQuery/VirtualProtect.
// ===========================================================================

/** @test MakeLocalWritable on an already writable page performs no changes. */
TEST_CASE("MakeLocalWritable on writable memory is a no-op", "[internal][local][protection]") {
    constexpr SIZE_T pageSize = 4096;
    LocalAllocation memory(3 * pageSize, PAGE_READWRITE);
    REQUIRE(memory);

    const auto scope = static_cast<std::uint8_t*>(memory.address) + pageSize;

    BoundaryGuard guard(nullptr, memory.address, 3 * pageSize, scope, pageSize);

    std::vector<PageProtectEntry> entries;

    SECTION("rejectGuardPages = true") {
        CHECK(MakeLocalWritable(scope, pageSize, entries, true));
    }

    SECTION("rejectGuardPages = false") {
        CHECK(MakeLocalWritable(scope, pageSize, entries, false));
    }

    CHECK(entries.empty());
    guard.RequireWindowRestored();
}

/** @test MakeLocalWritable maps every constructible initial protection to its writable equivalent. */
TEST_CASE("MakeLocalWritable changes each initial protection exactly", 
          "[internal][local][protection][boundary]") {
    const struct Scenario {
        const char* name;
        DWORD initialProtection;
        bool seedBytes;
    } scenarios[] = {
        {"PAGE_READONLY", PAGE_READONLY, true},
        {"PAGE_EXECUTE_READ", PAGE_EXECUTE_READ, true},
        {"PAGE_EXECUTE", PAGE_EXECUTE, true},
        {"PAGE_NOACCESS", PAGE_NOACCESS, false},
    };

    for (const Scenario& scenario : scenarios) {
        CAPTURE(scenario.name);

        constexpr SIZE_T pageSize = 4096;
        // Seed while writable, then lock the allocation down to the scenario's
        // initial protection (VirtualAlloc cannot create every protection and
        // memcpy cannot write through read-only/execute-only pages).
        LocalAllocation memory(3 * pageSize, PAGE_READWRITE);
        REQUIRE(memory);

        const auto scope = static_cast<std::uint8_t*>(memory.address) + pageSize;

        if (scenario.seedBytes) {
            const std::array<std::uint8_t, 8> payload{1, 2, 3, 4, 5, 6, 7, 8};
            std::memcpy(scope, payload.data(), payload.size());
        }

        DWORD previous = 0;
        REQUIRE(VirtualProtect(
            memory.address, 3 * pageSize, scenario.initialProtection, &previous));

        // Boundary snapshot of the pristine scenario state.
        BoundaryGuard guard(nullptr, memory.address, 3 * pageSize, scope, pageSize);

        std::vector<PageProtectEntry> entries;
        CHECK(MakeLocalWritable(scope, pageSize, entries, true));

        REQUIRE(entries.size() == 1);
        CHECK(entries[0].base == scope);
        CHECK(entries[0].size == pageSize);
        CHECK(entries[0].oldProtect == scenario.initialProtection);

        // Phase 2: scope holds the predicted writable protection; the rest of
        // the window (protection and bytes) is untouched; no byte changed.
        guard.RequireScopeProtection(WritableProtection);
        guard.RequireWindowOutsideScopeUnchanged();
        guard.RequireScopeBytesUnchanged();

        CHECK(QueryProtectionLocal(scope) == WritableProtection(scenario.initialProtection));

        // The caller (WriteMemory) restores through the recorded entries.
        CHECK(RestoreLocal(entries, 0));

        // Phase 3: the window is identical to the pristine snapshot.
        guard.RequireWindowRestored();
    }
}

/** @test MakeLocalWritable honors rejectGuardPages against a real guard page. */
TEST_CASE("MakeLocalWritable guard-page handling", "[internal][local][protection][guard]") {
    constexpr SIZE_T pageSize = 4096;
    LocalAllocation memory(3 * pageSize, PAGE_READWRITE);
    REQUIRE(memory);

    const auto scope = static_cast<std::uint8_t*>(memory.address) + pageSize;

    DWORD previous = 0;
    REQUIRE(VirtualProtect(scope, pageSize, PAGE_READONLY | PAGE_GUARD, &previous));

    // Snapshot while the scope is guarded (tracked by protection only).
    BoundaryGuard guard(nullptr, memory.address, 3 * pageSize, scope, pageSize);

    std::vector<PageProtectEntry> entries;

    SECTION("rejectGuardPages = true rejects") {
        CHECK_FALSE(MakeLocalWritable(scope, pageSize, entries, true));
        CHECK(entries.empty());
        guard.RequireWindowRestored(); // guard flag and everything else intact
    }

    SECTION("rejectGuardPages = false changes and can restore") {
        CHECK(MakeLocalWritable(scope, pageSize, entries, false));

        REQUIRE(entries.size() == 1);
        CHECK(entries[0].oldProtect == (PAGE_READONLY | PAGE_GUARD));
        CHECK(QueryProtectionLocal(scope) == PAGE_READWRITE); // guard removed

        guard.RequireScopeProtection(PAGE_READWRITE);
        guard.RequireWindowOutsideScopeUnchanged();

        CHECK(RestoreLocal(entries, 0));

        // Restoring PAGE_READONLY | PAGE_GUARD re-arms the guard page.
        CHECK(QueryProtectionLocal(scope) == (PAGE_READONLY | PAGE_GUARD));
        guard.RequireWindowRestored();
    }
}

/** @test MakeLocalWritable walks two differently protected regions with one entry each. */
TEST_CASE("MakeLocalWritable spans two regions with clamped entries",
          "[internal][local][protection][boundary]") {
    constexpr SIZE_T pageSize = 4096;
    ReservedRange memory(8);
    REQUIRE(memory);

    REQUIRE(memory.CommitRange(0, 4, PAGE_READONLY));
    REQUIRE(memory.CommitRange(4, 4, PAGE_EXECUTE_READ));

    // Scope = pages 3-4, crossing the region boundary between page 3 and 4.
    // Window [scope - 2p, scope + 4p) = [page1, page7) fits in the 8 pages.
    const auto scope = memory.Page(3);

    BoundaryGuard guard(nullptr, memory.base, 8 * pageSize, scope, 2 * pageSize);

    std::vector<PageProtectEntry> entries;
    CHECK(MakeLocalWritable(scope, 2 * pageSize, entries, true));

    REQUIRE(entries.size() == 2);
    CHECK(entries[0].base == scope);
    CHECK(entries[0].size == pageSize);
    CHECK(entries[0].oldProtect == PAGE_READONLY);
    CHECK(entries[1].base == memory.Page(4));
    CHECK(entries[1].size == pageSize);
    CHECK(entries[1].oldProtect == PAGE_EXECUTE_READ);

    // Phase 2: each region holds the protection WritableProtection predicts.
    guard.RequireScopeProtection(WritableProtection);
    guard.RequireWindowOutsideScopeUnchanged();
    guard.RequireScopeBytesUnchanged();

    CHECK(QueryProtectionLocal(memory.Page(3)) == PAGE_READWRITE);
    CHECK(QueryProtectionLocal(memory.Page(4)) == PAGE_EXECUTE_READWRITE);

    CHECK(RestoreLocal(entries, 0));

    // Phase 3: both regions and the whole window are restored.
    guard.RequireWindowRestored();
    CHECK(QueryProtectionLocal(memory.Page(3)) == PAGE_READONLY);
    CHECK(QueryProtectionLocal(memory.Page(4)) == PAGE_EXECUTE_READ);
}

/** @test MakeLocalWritable fails on an uncommitted hole while keeping the partial changes restorable. */
TEST_CASE("MakeLocalWritable fails on an uncommitted hole", 
          "[internal][local][protection][boundary]") {
    constexpr SIZE_T pageSize = 4096;
    ReservedRange memory(12);
    REQUIRE(memory);

    REQUIRE(memory.CommitRange(1, 1, PAGE_READONLY));   // padding inside the window
    REQUIRE(memory.CommitRange(4, 2, PAGE_READONLY));   // first part of the scope
    // Pages 2-3 and 6-11 stay reserved: pages 6-7 form the in-scope hole.

    // Scope = pages 4-7 (4 pages). Window [0, 12p) covers the whole reservation.
    const auto scope = memory.Page(4);

    BoundaryGuard guard(nullptr, memory.base, 12 * pageSize, scope, 4 * pageSize);

    std::vector<PageProtectEntry> entries;
    CHECK_FALSE(MakeLocalWritable(scope, 4 * pageSize, entries, true));

    // The committed prefix (pages 4-5) was changed and recorded.
    REQUIRE(entries.size() == 1);
    CHECK(entries[0].base == scope);
    CHECK(entries[0].size == 2 * pageSize);
    CHECK(entries[0].oldProtect == PAGE_READONLY);

    CHECK(QueryProtectionLocal(scope) == PAGE_READWRITE);
    // Reserved (never committed) pages carry no meaningful protection value:
    // current Windows reports Protect = 0 for them (older documentation
    // suggested PAGE_NOACCESS). The invariant that matters is that the hole
    // was NOT committed and therefore was not touched by the operation.
    {
        MEMORY_BASIC_INFORMATION hole{};
        REQUIRE(VirtualQuery(memory.Page(6), &hole, sizeof(hole)) == sizeof(hole));
        CHECK(hole.State != MEM_COMMIT);
    }

    // The caller rolls the partial change back.
    CHECK(RestoreLocal(entries, 0));

    // Phase 3: committed pages, reserved hole and padding are all as before.
    guard.RequireWindowRestored();
}

/** @test MakeLocalWritable handles unaligned scopes with page-granular clamping. */
TEST_CASE("MakeLocalWritable unaligned scopes", "[internal][local][protection][boundary]") {
    constexpr SIZE_T pageSize = 4096;

    SECTION("single-page unaligned scope") {
        // Seven pages; scope = base + 2p + 256, size 512.
        // Window [2p - 256, 2p + 1280) page-aligns to pages 1-2.
        LocalAllocation memory(7 * pageSize, PAGE_READONLY);
        REQUIRE(memory);

        const auto scope =
            static_cast<std::uint8_t*>(memory.address) + 2 * pageSize + 256;

        BoundaryGuard guard(nullptr, memory.address, 7 * pageSize, scope, 512);

        std::vector<PageProtectEntry> entries;
        CHECK(MakeLocalWritable(scope, 512, entries, true));

        // The whole intersecting page was the actual change unit.
        REQUIRE(entries.size() == 1);
        CHECK(entries[0].base == scope);
        CHECK(entries[0].size == 512);
        CHECK(entries[0].oldProtect == PAGE_READONLY);

        CHECK(QueryProtectionLocal(scope) == PAGE_READWRITE);
        CHECK(QueryProtectionLocal(memory.address) == PAGE_READONLY); // page 0 untouched
        CHECK(QueryProtectionLocal(
                  static_cast<std::uint8_t*>(memory.address) + 3 * pageSize) == PAGE_READONLY);

        guard.RequireScopeProtection(WritableProtection);
        guard.RequireWindowOutsideScopeUnchanged();

        CHECK(RestoreLocal(entries, 0));
        guard.RequireWindowRestored();
    }

    SECTION("two-page unaligned scope") {
        // Seven pages; scope = base + 2p + 256, size = 1p + 512.
        // Window [2p + 256 - 1p - 512, 2p + 256 + 2p + 1024) page-aligns
        // to pages 0-4; pages 5-6 stay outside the window.
        LocalAllocation memory(7 * pageSize, PAGE_READONLY);
        REQUIRE(memory);

        const auto scope =
            static_cast<std::uint8_t*>(memory.address) + 2 * pageSize + 256;
        const SIZE_T scopeSize = pageSize + 512;

        BoundaryGuard guard(nullptr, memory.address, 7 * pageSize, scope, scopeSize);

        std::vector<PageProtectEntry> entries;
        CHECK(MakeLocalWritable(scope, scopeSize, entries, true));

        // One region, one protect call with the requested (unaligned) bounds.
        REQUIRE(entries.size() == 1);
        CHECK(entries[0].base == scope);
        CHECK(entries[0].size == scopeSize);
        CHECK(entries[0].oldProtect == PAGE_READONLY);

        CHECK(QueryProtectionLocal(scope) == PAGE_READWRITE);
        CHECK(QueryProtectionLocal(
                  static_cast<std::uint8_t*>(scope) + scopeSize - 1) == PAGE_READWRITE);
        CHECK(QueryProtectionLocal(memory.address) == PAGE_READONLY);
        CHECK(QueryProtectionLocal(
                  static_cast<std::uint8_t*>(memory.address) + 6 * pageSize) == PAGE_READONLY);

        guard.RequireScopeProtection(WritableProtection);
        guard.RequireWindowOutsideScopeUnchanged();

        CHECK(RestoreLocal(entries, 0));
        guard.RequireWindowRestored();
    }
}

/** @test MakeLocalWritable edge cases for zero-size and null addresses. */
TEST_CASE("MakeLocalWritable edge cases", "[internal][local][errors]") {
    std::vector<PageProtectEntry> entries;

    // Zero size succeeds regardless of the address, without touching entries.
    CHECK(MakeLocalWritable(nullptr, 0, entries, true));
    CHECK(entries.empty());

    CHECK(MakeLocalWritable(reinterpret_cast<LPVOID>(0x10000), 0, entries, false));
    CHECK(entries.empty());

    // A null address with a non-zero size fails without recording anything.
    CHECK_FALSE(MakeLocalWritable(nullptr, 4096, entries, true));
    CHECK(entries.empty());
}

/** @test MakeLocalReadable on an already readable page performs no changes. */
TEST_CASE("MakeLocalReadable on readable memory is a no-op", "[internal][local][protection]") {
    constexpr SIZE_T pageSize = 4096;

    SECTION("PAGE_READONLY page") {
        LocalAllocation memory(3 * pageSize, PAGE_READONLY);
        REQUIRE(memory);
        const auto scope = static_cast<std::uint8_t*>(memory.address) + pageSize;

        BoundaryGuard guard(nullptr, memory.address, 3 * pageSize, scope, pageSize);

        std::vector<PageProtectEntry> entries;
        CHECK(MakeLocalReadable(scope, pageSize, entries, true));
        CHECK(entries.empty());
        guard.RequireWindowRestored();
    }

    SECTION("PAGE_EXECUTE_READ page") {
        LocalAllocation memory(3 * pageSize, PAGE_EXECUTE_READ);
        REQUIRE(memory);
        const auto scope = static_cast<std::uint8_t*>(memory.address) + pageSize;

        BoundaryGuard guard(nullptr, memory.address, 3 * pageSize, scope, pageSize);

        std::vector<PageProtectEntry> entries;
        CHECK(MakeLocalReadable(scope, pageSize, entries, true));
        CHECK(entries.empty());
        guard.RequireWindowRestored();
    }
}

/** @test MakeLocalReadable maps each initial protection to its readable equivalent. */
TEST_CASE("MakeLocalReadable changes each initial protection exactly",
          "[internal][local][protection][boundary]") {
    const struct Scenario {
        const char* name;
        DWORD initialProtection;
    } scenarios[] = {
        {"PAGE_READWRITE", PAGE_READWRITE},
        {"PAGE_EXECUTE", PAGE_EXECUTE},
        {"PAGE_NOACCESS", PAGE_NOACCESS},
    };

    for (const Scenario& scenario : scenarios) {
        CAPTURE(scenario.name);

        constexpr SIZE_T pageSize = 4096;
        LocalAllocation memory(3 * pageSize, scenario.initialProtection);
        REQUIRE(memory);

        const auto scope = static_cast<std::uint8_t*>(memory.address) + pageSize;

        BoundaryGuard guard(nullptr, memory.address, 3 * pageSize, scope, pageSize);

        std::vector<PageProtectEntry> entries;
        CHECK(MakeLocalReadable(scope, pageSize, entries, true));

        REQUIRE(entries.size() == 1);
        CHECK(entries[0].base == scope);
        CHECK(entries[0].size == pageSize);
        CHECK(entries[0].oldProtect == scenario.initialProtection);

        guard.RequireScopeProtection(ReadableProtection);
        guard.RequireWindowOutsideScopeUnchanged();

        CHECK(QueryProtectionLocal(scope) == ReadableProtection(scenario.initialProtection));

        // The page is now readable: the purpose of the helper can be exercised.
        if (scenario.initialProtection == PAGE_NOACCESS) {
            std::array<std::uint8_t, 8> observed{};
            std::memcpy(observed.data(), scope, observed.size()); // must not fault
        }

        CHECK(RestoreLocal(entries, 0));
        guard.RequireWindowRestored();
    }
}

/** @test MakeLocalReadable honors rejectGuardPages against a real guard page. */
TEST_CASE("MakeLocalReadable guard-page handling", "[internal][local][protection][guard]") {
    constexpr SIZE_T pageSize = 4096;
    LocalAllocation memory(3 * pageSize, PAGE_READWRITE);
    REQUIRE(memory);

    const auto scope = static_cast<std::uint8_t*>(memory.address) + pageSize;

    DWORD previous = 0;
    REQUIRE(VirtualProtect(scope, pageSize, PAGE_READWRITE | PAGE_GUARD, &previous));

    BoundaryGuard guard(nullptr, memory.address, 3 * pageSize, scope, pageSize);

    std::vector<PageProtectEntry> entries;

    SECTION("rejectGuardPages = true rejects") {
        CHECK_FALSE(MakeLocalReadable(scope, pageSize, entries, true));
        CHECK(entries.empty());
        guard.RequireWindowRestored();
    }

    SECTION("rejectGuardPages = false changes and can restore") {
        CHECK(MakeLocalReadable(scope, pageSize, entries, false));

        REQUIRE(entries.size() == 1);
        CHECK(entries[0].oldProtect == (PAGE_READWRITE | PAGE_GUARD));
        CHECK(QueryProtectionLocal(scope) == PAGE_READONLY); // guard removed

        CHECK(RestoreLocal(entries, 0));
        CHECK(QueryProtectionLocal(scope) == (PAGE_READWRITE | PAGE_GUARD));
        guard.RequireWindowRestored();
    }
}

/** @test MakeLocalReadable walks two differently protected regions with one entry each. */
TEST_CASE("MakeLocalReadable spans two regions with clamped entries",
          "[internal][local][protection][boundary]") {
    constexpr SIZE_T pageSize = 4096;
    ReservedRange memory(8);
    REQUIRE(memory);

    REQUIRE(memory.CommitRange(0, 4, PAGE_READWRITE));
    REQUIRE(memory.CommitRange(4, 4, PAGE_EXECUTE));

    const auto scope = memory.Page(3); // pages 3-4 cross the region boundary

    BoundaryGuard guard(nullptr, memory.base, 8 * pageSize, scope, 2 * pageSize);

    std::vector<PageProtectEntry> entries;
    CHECK(MakeLocalReadable(scope, 2 * pageSize, entries, true));

    REQUIRE(entries.size() == 2);
    CHECK(entries[0].base == scope);
    CHECK(entries[0].size == pageSize);
    CHECK(entries[0].oldProtect == PAGE_READWRITE);
    CHECK(entries[1].base == memory.Page(4));
    CHECK(entries[1].size == pageSize);
    CHECK(entries[1].oldProtect == PAGE_EXECUTE);

    guard.RequireScopeProtection(ReadableProtection);
    guard.RequireWindowOutsideScopeUnchanged();

    CHECK(QueryProtectionLocal(memory.Page(3)) == PAGE_READONLY);
    CHECK(QueryProtectionLocal(memory.Page(4)) == PAGE_EXECUTE_READ);

    CHECK(RestoreLocal(entries, 0));

    guard.RequireWindowRestored();
    CHECK(QueryProtectionLocal(memory.Page(3)) == PAGE_READWRITE);
    CHECK(QueryProtectionLocal(memory.Page(4)) == PAGE_EXECUTE);
}

/** @test MakeLocalReadable fails on an uncommitted hole while staying restorable. */
TEST_CASE("MakeLocalReadable fails on an uncommitted hole",
          "[internal][local][protection][boundary]") {
    constexpr SIZE_T pageSize = 4096;
    ReservedRange memory(12);
    REQUIRE(memory);

    REQUIRE(memory.CommitRange(1, 1, PAGE_READWRITE));  // padding inside the window
    REQUIRE(memory.CommitRange(4, 2, PAGE_READWRITE));  // committed prefix of the scope

    const auto scope = memory.Page(4);

    BoundaryGuard guard(nullptr, memory.base, 12 * pageSize, scope, 4 * pageSize);

    std::vector<PageProtectEntry> entries;
    CHECK_FALSE(MakeLocalReadable(scope, 4 * pageSize, entries, true));

    REQUIRE(entries.size() == 1);
    CHECK(entries[0].base == scope);
    CHECK(entries[0].size == 2 * pageSize);
    CHECK(entries[0].oldProtect == PAGE_READWRITE);

    CHECK(QueryProtectionLocal(scope) == PAGE_READONLY);

    CHECK(RestoreLocal(entries, 0));
    guard.RequireWindowRestored();
}

/** @test MakeLocalReadable edge cases for zero-size and null addresses. */
TEST_CASE("MakeLocalReadable edge cases", "[internal][local][errors]") {
    std::vector<PageProtectEntry> entries;

    CHECK(MakeLocalReadable(nullptr, 0, entries, true));
    CHECK(entries.empty());

    CHECK(MakeLocalReadable(reinterpret_cast<LPVOID>(0x10000), 0, entries, false));
    CHECK(entries.empty());

    CHECK_FALSE(MakeLocalReadable(nullptr, 4096, entries, true));
    CHECK(entries.empty());
}

// ===========================================================================
// TESTABLE_STATIC MakeRemoteWritable / MakeRemoteReadable
//
// The remote helpers are exercised against the current process through the
// pseudo-handle and through a real, fully privileged self handle. Restriction-
// handle scenarios reproduce real API failure paths deterministically; key
// scenarios are additionally repeated against the live game when present.
// ===========================================================================

/** @test MakeRemoteWritable changes a page through the pseudo-handle with a full boundary check. */
TEST_CASE("MakeRemoteWritable via the pseudo-handle",
          "[internal][remote][protection][boundary]") {
    constexpr SIZE_T pageSize = 4096;
    LocalAllocation memory(3 * pageSize, PAGE_READONLY);
    REQUIRE(memory);

    const auto scope = static_cast<std::uint8_t*>(memory.address) + pageSize;
    HANDLE self = GetCurrentProcess();

    BoundaryGuard guard(self, memory.address, 3 * pageSize, scope, pageSize);

    std::vector<PageProtectEntry> entries;
    CHECK(MakeRemoteWritable(self, scope, pageSize, entries, true));

    REQUIRE(entries.size() == 1);
    CHECK(entries[0].base == scope);
    CHECK(entries[0].size == pageSize);
    CHECK(entries[0].oldProtect == PAGE_READONLY);

    guard.RequireScopeProtection(WritableProtection);
    guard.RequireWindowOutsideScopeUnchanged();
    guard.RequireScopeBytesUnchanged();

    CHECK(QueryProtectionLocal(scope) == PAGE_READWRITE);

    CHECK(RestoreRemote(self, entries, 0));
    guard.RequireWindowRestored();
    CHECK(QueryProtectionLocal(scope) == PAGE_READONLY);
}

/** @test MakeRemoteWritable through a real self handle behaves identically. */
TEST_CASE("MakeRemoteWritable via a real self handle",
          "[internal][remote][protection][boundary]") {
    HANDLE self = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
            PROCESS_VM_OPERATION,
        FALSE,
        GetCurrentProcessId());
    REQUIRE(self != nullptr);

    constexpr SIZE_T pageSize = 4096;
    LocalAllocation memory(3 * pageSize, PAGE_EXECUTE_READ);
    REQUIRE(memory);

    const auto scope = static_cast<std::uint8_t*>(memory.address) + pageSize;

    BoundaryGuard guard(self, memory.address, 3 * pageSize, scope, pageSize);

    std::vector<PageProtectEntry> entries;
    CHECK(MakeRemoteWritable(self, scope, pageSize, entries, true));

    REQUIRE(entries.size() == 1);
    CHECK(entries[0].oldProtect == PAGE_EXECUTE_READ);

    guard.RequireScopeProtection(WritableProtection);
    guard.RequireWindowOutsideScopeUnchanged();

    CHECK(QueryProtectionLocal(scope) == PAGE_EXECUTE_READWRITE);

    CHECK(RestoreRemote(self, entries, 0));
    guard.RequireWindowRestored();
    CHECK(QueryProtectionLocal(scope) == PAGE_EXECUTE_READ);

    CloseHandle(self);
}

/** @test MakeRemoteWritable rejects invalid handles without touching the entries. */
TEST_CASE("MakeRemoteWritable rejects invalid handles", "[internal][remote][errors]") {
    std::vector<PageProtectEntry> entries;
    entries.push_back({nullptr, 0, 0}); // sentinel that must survive untouched

    SECTION("null handle") {
        CHECK_FALSE(MakeRemoteWritable(
            nullptr, reinterpret_cast<LPVOID>(0x10000), 4096, entries, true));
    }

    SECTION("stale closed handle") {
        // (HANDLE)-1 is the valid current-process pseudo handle, so a real
        // invalid handle is required: a handle to this process that has been
        // closed again.
        CHECK_FALSE(MakeRemoteWritable(
            MakeStaleProcessHandle(), reinterpret_cast<LPVOID>(0x10000), 4096,
            entries, true));
    }

    REQUIRE(entries.size() == 1);
    CHECK(entries[0].base == nullptr);
}

/** @test MakeRemoteWritable fails cleanly when the handle cannot change protection. */
TEST_CASE("MakeRemoteWritable fails when the handle cannot change protection",
          "[internal][remote][errors]") {
    // Query-only handle: VirtualQueryEx succeeds, VirtualProtectEx fails.
    HANDLE restricted = OpenProcess(
        PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId());
    REQUIRE(restricted != nullptr);

    constexpr SIZE_T pageSize = 4096;
    LocalAllocation memory(3 * pageSize, PAGE_READONLY);
    REQUIRE(memory);

    const auto scope = static_cast<std::uint8_t*>(memory.address) + pageSize;

    std::vector<PageProtectEntry> entries;
    CHECK_FALSE(MakeRemoteWritable(restricted, scope, pageSize, entries, true));

    // The protect call failed before recording anything.
    CHECK(entries.empty());
    CHECK(QueryProtectionLocal(scope) == PAGE_READONLY);

    CloseHandle(restricted);
}

/** @test MakeRemoteWritable fails cleanly when the handle cannot even query. */
TEST_CASE("MakeRemoteWritable fails when the handle cannot query",
          "[internal][remote][errors]") {
    // VM_OPERATION-only handle: VirtualQueryEx lacks PROCESS_QUERY_* rights.
    HANDLE restricted = OpenProcess(PROCESS_VM_OPERATION, FALSE, GetCurrentProcessId());
    if (!restricted)
        SKIP("Could not open a PROCESS_VM_OPERATION-only self handle.");

    constexpr SIZE_T pageSize = 4096;
    LocalAllocation memory(3 * pageSize, PAGE_READONLY);
    REQUIRE(memory);

    const auto scope = static_cast<std::uint8_t*>(memory.address) + pageSize;

    std::vector<PageProtectEntry> entries;
    CHECK_FALSE(MakeRemoteWritable(restricted, scope, pageSize, entries, true));

    CHECK(entries.empty());
    CHECK(QueryProtectionLocal(scope) == PAGE_READONLY);

    CloseHandle(restricted);
}

/** @test MakeRemoteReadable changes a page through the pseudo-handle with a full boundary check. */
TEST_CASE("MakeRemoteReadable via the pseudo-handle",
          "[internal][remote][protection][boundary]") {
    constexpr SIZE_T pageSize = 4096;
    LocalAllocation memory(3 * pageSize, PAGE_READWRITE);
    REQUIRE(memory);

    const auto scope = static_cast<std::uint8_t*>(memory.address) + pageSize;
    HANDLE self = GetCurrentProcess();

    BoundaryGuard guard(self, memory.address, 3 * pageSize, scope, pageSize);

    std::vector<PageProtectEntry> entries;
    CHECK(MakeRemoteReadable(self, scope, pageSize, entries, true));

    REQUIRE(entries.size() == 1);
    CHECK(entries[0].base == scope);
    CHECK(entries[0].size == pageSize);
    CHECK(entries[0].oldProtect == PAGE_READWRITE);

    guard.RequireScopeProtection(ReadableProtection);
    guard.RequireWindowOutsideScopeUnchanged();
    guard.RequireScopeBytesUnchanged();

    CHECK(QueryProtectionLocal(scope) == PAGE_READONLY);

    CHECK(RestoreRemote(self, entries, 0));
    guard.RequireWindowRestored();
    CHECK(QueryProtectionLocal(scope) == PAGE_READWRITE);
}

/** @test MakeRemoteReadable works on a NOACCESS page through a real self handle. */
TEST_CASE("MakeRemoteReadable via a real self handle",
          "[internal][remote][protection][boundary]") {
    HANDLE self = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
            PROCESS_VM_OPERATION,
        FALSE,
        GetCurrentProcessId());
    REQUIRE(self != nullptr);

    constexpr SIZE_T pageSize = 4096;
    LocalAllocation memory(3 * pageSize, PAGE_NOACCESS);
    REQUIRE(memory);

    const auto scope = static_cast<std::uint8_t*>(memory.address) + pageSize;

    BoundaryGuard guard(self, memory.address, 3 * pageSize, scope, pageSize);

    std::vector<PageProtectEntry> entries;
    CHECK(MakeRemoteReadable(self, scope, pageSize, entries, true));

    REQUIRE(entries.size() == 1);
    CHECK(entries[0].oldProtect == PAGE_NOACCESS);

    guard.RequireScopeProtection(ReadableProtection);
    guard.RequireWindowOutsideScopeUnchanged();

    CHECK(QueryProtectionLocal(scope) == PAGE_READONLY);

    CHECK(RestoreRemote(self, entries, 0));
    guard.RequireWindowRestored();
    CHECK(QueryProtectionLocal(scope) == PAGE_NOACCESS);

    CloseHandle(self);
}

/** @test MakeRemoteReadable rejects invalid handles without touching the entries. */
TEST_CASE("MakeRemoteReadable rejects invalid handles", "[internal][remote][errors]") {
    std::vector<PageProtectEntry> entries;
    entries.push_back({nullptr, 0, 0}); // sentinel that must survive untouched

    SECTION("null handle") {
        CHECK_FALSE(MakeRemoteReadable(
            nullptr, reinterpret_cast<LPVOID>(0x10000), 4096, entries, true));
    }

    SECTION("stale closed handle") {
        // (HANDLE)-1 is the valid current-process pseudo handle, so a real
        // invalid handle is required: a handle to this process that has been
        // closed again.
        CHECK_FALSE(MakeRemoteReadable(
            MakeStaleProcessHandle(), reinterpret_cast<LPVOID>(0x10000), 4096,
            entries, true));
    }

    REQUIRE(entries.size() == 1);
    CHECK(entries[0].base == nullptr);
}

/** @test MakeRemoteReadable fails cleanly when the handle cannot change protection. */
TEST_CASE("MakeRemoteReadable fails when the handle cannot change protection",
          "[internal][remote][errors]") {
    // Query-only handle: VirtualQueryEx succeeds, VirtualProtectEx fails.
    HANDLE restricted = OpenProcess(
        PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId());
    REQUIRE(restricted != nullptr);

    constexpr SIZE_T pageSize = 4096;
    LocalAllocation memory(3 * pageSize, PAGE_READWRITE);
    REQUIRE(memory);

    const auto scope = static_cast<std::uint8_t*>(memory.address) + pageSize;

    std::vector<PageProtectEntry> entries;
    CHECK_FALSE(MakeRemoteReadable(restricted, scope, pageSize, entries, true));

    CHECK(entries.empty());
    CHECK(QueryProtectionLocal(scope) == PAGE_READWRITE);

    CloseHandle(restricted);
}

/** @test MakeRemoteWritable and RestoreRemote round-trip inside the live game. */
TEST_CASE("MakeRemoteWritable round-trips in the live game",
          "[remote][internal][protection][boundary]") {
    ProcessFixture process;
    if (!process.available())
        SKIP(kSkipMessage);

    constexpr SIZE_T pageSize = 4096;
    RemoteAllocation memory(process.process, 3 * pageSize, PAGE_READONLY);
    REQUIRE(memory);

    const auto scope = static_cast<std::uint8_t*>(memory.address) + pageSize;

    BoundaryGuard guard(process.process, memory.address, 3 * pageSize, scope, pageSize);

    std::vector<PageProtectEntry> entries;
    CHECK(MakeRemoteWritable(process.process, scope, pageSize, entries, true));

    REQUIRE(entries.size() == 1);
    CHECK(entries[0].base == scope);
    CHECK(entries[0].size == pageSize);
    CHECK(entries[0].oldProtect == PAGE_READONLY);

    guard.RequireScopeProtection(WritableProtection);
    guard.RequireWindowOutsideScopeUnchanged();

    CHECK(QueryProtection(process.process, scope) == PAGE_READWRITE);

    CHECK(RestoreRemote(process.process, entries, 0));

    guard.RequireWindowRestored();
    CHECK(QueryProtection(process.process, scope) == PAGE_READONLY);
}

/** @test MakeRemoteReadable and RestoreRemote round-trip inside the live game. */
TEST_CASE("MakeRemoteReadable round-trips in the live game",
          "[remote][internal][protection][boundary]") {
    ProcessFixture process;
    if (!process.available())
        SKIP(kSkipMessage);

    constexpr SIZE_T pageSize = 4096;
    RemoteAllocation memory(process.process, 3 * pageSize, PAGE_READWRITE);
    REQUIRE(memory);

    const auto scope = static_cast<std::uint8_t*>(memory.address) + pageSize;

    BoundaryGuard guard(process.process, memory.address, 3 * pageSize, scope, pageSize);

    std::vector<PageProtectEntry> entries;
    CHECK(MakeRemoteReadable(process.process, scope, pageSize, entries, true));

    REQUIRE(entries.size() == 1);
    CHECK(entries[0].oldProtect == PAGE_READWRITE);

    guard.RequireScopeProtection(ReadableProtection);
    guard.RequireWindowOutsideScopeUnchanged();

    CHECK(QueryProtection(process.process, scope) == PAGE_READONLY);

    CHECK(RestoreRemote(process.process, entries, 0));

    guard.RequireWindowRestored();
    CHECK(QueryProtection(process.process, scope) == PAGE_READWRITE);
}
