/*
 * @File: UnitTests.cpp
 * @Author: Aldrin John O. Manalansan (ajom)
 * @Email: aldrinjohnolaermanalansan@gmail.com
 * @LastUpdate: August 29, 2026
 * @Brief: Catch2 v3 live integration tests for WinProcHandling.
 *
 * Battle_Realms_F.exe must already be running. Remote tests allocate temporary
 * memory inside that process rather than modifying arbitrary game instructions.
 * Every test restores bytes/protections it changes before returning.
 *
 * Copyright (C) 2026  Aldrin John O. Manalansan  <aldrinjohnolaermanalansan@gmail.com>
 * 
 * This Source Code is served under Open-Source AJOM License
 * You should have received a copy of License_OS-AJOM
 * along with this source code. If not, see:
 * <https://raw.githubusercontent.com/Aldrin-John-Olaer-Manalansan/AJOM_License/refs/heads/main/LICENSE_AJOM-OS>
 */

#include <catch2/catch_test_macros.hpp>

#include "WinProcHandling.hpp"

#include <windows.h>
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

namespace {

constexpr const char* kTargetProcessName = "Battle_Realms_F.exe";

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

/** @brief Classifies the base protection modes accepted as readable by the tests. */
static bool IsReadable(DWORD protection) {
    switch (protection & 0xFFu) {
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

} // namespace

/** @test Verifies the behavior described by the Catch2 test name. */
TEST_CASE("FindProcessId locates the exact target executable", "[process]") {
    const DWORD pid = WinProcHandling::FindProcessId(kTargetProcessName);
    REQUIRE(pid != 0);
}

/** @test Verifies the behavior described by the Catch2 test name. */
TEST_CASE("GetModuleBase returns the target executable module", "[module]") {
    ProcessFixture process;
    REQUIRE(process.available());

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
    REQUIRE(process.available());

    uintptr_t base = 0;
    const DWORD size =
        WinProcHandling::GetModuleBase(process.pid, kTargetProcessName, &base);

    REQUIRE(size != 0);
    REQUIRE(base != 0);
}

/** @test Verifies that a remote read-only region can be patched and its original protection restored. */
TEST_CASE("Remote WriteMemory writes and restores protection", "[remote][write]") {
    ProcessFixture process;
    REQUIRE(process.available());

    constexpr SIZE_T allocationSize = 2 * 4096;

    // Allocate as writable so the test can initialize the original bytes.
    RemoteAllocation memory(
        process.process,
        allocationSize,
        PAGE_READWRITE);

    REQUIRE(memory);

    const std::array<std::uint8_t, 16> original{};
    const std::array<std::uint8_t, 16> replacement{
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
        0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0xFF
    };

    // Seed the original bytes while the allocation is writable.
    REQUIRE(WriteProcessMemory(
        process.process,
        memory.address,
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

    CHECK(WinProcHandling::WriteMemory(
        process.process,
        memory.address,
        replacement.data(),
        replacement.size(),
        WinProcHandling::e_VirtualProtectMode::SafelyChange,
        true)
        == WinProcHandling::e_WriteStatus::Success);

    std::array<std::uint8_t, 16> observed{};

    REQUIRE(ReadProcessMemory(
        process.process,
        memory.address,
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
        memory.address,
        original.data(),
        original.size(),
        WinProcHandling::e_VirtualProtectMode::SafelyChange,
        true)
        == WinProcHandling::e_WriteStatus::Success);

    std::array<std::uint8_t, 16> restoredBytes{};

    REQUIRE(ReadProcessMemory(
        process.process,
        memory.address,
        restoredBytes.data(),
        restoredBytes.size(),
        nullptr));

    CHECK(restoredBytes == original);
}

/** @test Verifies that multiple remote writes to different regions independently preserve their protections. */
TEST_CASE("Remote WriteMemory works repeatedly on different regions", "[remote][write]") {
    ProcessFixture process;
    REQUIRE(process.available());

    constexpr SIZE_T pageSize = 4096;

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

    const std::array<std::uint8_t, 16> original{
        0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C,
        0x0D, 0x0E, 0x0F, 0x10
    };

    const std::array<std::uint8_t, 16> firstReplacement{
        0x11, 0x12, 0x13, 0x14,
        0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C,
        0x1D, 0x1E, 0x1F, 0x20
    };

    const std::array<std::uint8_t, 16> secondReplacement{
        0x21, 0x22, 0x23, 0x24,
        0x25, 0x26, 0x27, 0x28,
        0x29, 0x2A, 0x2B, 0x2C,
        0x2D, 0x2E, 0x2F, 0x30
    };

    // Seed both allocations while they are writable.
    REQUIRE(WriteProcessMemory(
        process.process,
        firstRegion.address,
        original.data(),
        original.size(),
        nullptr));

    REQUIRE(WriteProcessMemory(
        process.process,
        secondRegion.address,
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

    // First write.
    REQUIRE(WinProcHandling::WriteMemory(
        process.process,
        firstRegion.address,
        firstReplacement.data(),
        firstReplacement.size(),
        WinProcHandling::e_VirtualProtectMode::SafelyChange,
        true)
        == WinProcHandling::e_WriteStatus::Success);

    // Verify first region and its protection immediately after the operation.
    std::array<std::uint8_t, 16> firstObserved{};

    REQUIRE(ReadProcessMemory(
        process.process,
        firstRegion.address,
        firstObserved.data(),
        firstObserved.size(),
        nullptr));

    CHECK(firstObserved == firstReplacement);

    CHECK((QueryProtection(process.process, firstRegion.address) & 0xFFu) ==
          (firstProtection & 0xFFu));

    // Second write.
    REQUIRE(WinProcHandling::WriteMemory(
        process.process,
        secondRegion.address,
        secondReplacement.data(),
        secondReplacement.size(),
        WinProcHandling::e_VirtualProtectMode::SafelyChange,
        true)
        == WinProcHandling::e_WriteStatus::Success);

    // Verify second region and its protection immediately after the operation.
    std::array<std::uint8_t, 16> secondObserved{};

    REQUIRE(ReadProcessMemory(
        process.process,
        secondRegion.address,
        secondObserved.data(),
        secondObserved.size(),
        nullptr));

    CHECK(secondObserved == secondReplacement);

    CHECK((QueryProtection(process.process, secondRegion.address) & 0xFFu) ==
          (secondProtection & 0xFFu));

    // Repeat the operations in the opposite order.
    REQUIRE(WinProcHandling::WriteMemory(
        process.process,
        secondRegion.address,
        original.data(),
        original.size(),
        WinProcHandling::e_VirtualProtectMode::SafelyChange,
        true)
        == WinProcHandling::e_WriteStatus::Success);

    REQUIRE(WinProcHandling::WriteMemory(
        process.process,
        firstRegion.address,
        original.data(),
        original.size(),
        WinProcHandling::e_VirtualProtectMode::SafelyChange,
        true)
        == WinProcHandling::e_WriteStatus::Success);

    // Verify both regions were restored to their original bytes.
    firstObserved.fill(0);

    REQUIRE(ReadProcessMemory(
        process.process,
        firstRegion.address,
        firstObserved.data(),
        firstObserved.size(),
        nullptr));

    CHECK(firstObserved == original);

    secondObserved.fill(0);

    REQUIRE(ReadProcessMemory(
        process.process,
        secondRegion.address,
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

/** @test Verifies the behavior described by the Catch2 test name. */
TEST_CASE("Remote FillWithNOPs writes exact NOP bytes and restores protection", "[remote][nop]") {
    ProcessFixture process;
    REQUIRE(process.available());

    RemoteAllocation memory(process.process, 4096, PAGE_EXECUTE_READ);
    REQUIRE(memory);

    constexpr SIZE_T count = 32;
    std::array<std::uint8_t, count> original{};
    std::array<std::uint8_t, count> observed{};

    const DWORD before = QueryProtection(process.process, memory.address);

    REQUIRE(WinProcHandling::WriteMemory(
        process.process, memory.address, original.data(), original.size(),
        WinProcHandling::e_VirtualProtectMode::SafelyChange, true)
        == WinProcHandling::e_WriteStatus::Success);

    CHECK(WinProcHandling::FillWithNOPs(
        process.process, memory.address, count,
        WinProcHandling::e_VirtualProtectMode::SafelyChange, true)
        == WinProcHandling::e_WriteStatus::Success);

    REQUIRE(ReadProcessMemory(
        process.process, memory.address, observed.data(), observed.size(), nullptr));

    CHECK(std::all_of(observed.begin(), observed.end(),
                      [](std::uint8_t byteValue) { return byteValue == 0x90; }));
    CHECK(QueryProtection(process.process, memory.address) == before);

    REQUIRE(WinProcHandling::WriteMemory(
        process.process, memory.address, original.data(), original.size(),
        WinProcHandling::e_VirtualProtectMode::SafelyChange, true)
        == WinProcHandling::e_WriteStatus::Success);
}


/** @test Verifies that ForceChange can modify a guarded page and restore PAGE_GUARD afterward. */
TEST_CASE("Remote ForceChange can patch a guarded committed page and restores PAGE_GUARD",
          "[remote][write][guard]")
{
    ProcessFixture process;
    REQUIRE(process.available());

    constexpr SIZE_T pageSize = 4096;

    // Allocate as writable so the test can initialize the original bytes.
    RemoteAllocation memory(
        process.process,
        pageSize,
        PAGE_READWRITE);

    REQUIRE(memory);

    const std::array<std::uint8_t, 8> original{
        0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08
    };

    const std::array<std::uint8_t, 8> replacement{
        0x90, 0x90, 0x90, 0x90,
        0x90, 0x90, 0x90, 0x90
    };

    // Seed the original bytes while the page is writable.
    REQUIRE(WriteProcessMemory(
        process.process,
        memory.address,
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

    // ForceChange is specifically expected to permit modification of a guarded page.
    CHECK(WinProcHandling::WriteMemory(
        process.process,
        memory.address,
        replacement.data(),
        replacement.size(),
        WinProcHandling::e_VirtualProtectMode::ForceChange,
        true)
        == WinProcHandling::e_WriteStatus::Success);

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

    std::array<std::uint8_t, 8> observed{};

    REQUIRE(ReadProcessMemory(
        process.process,
        memory.address,
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
        memory.address,
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
}

/** @test Verifies the behavior described by the Catch2 test name. */
TEST_CASE("SafelyChange rejects a guarded page without removing PAGE_GUARD",
          "[remote][safe][guard]") {
    ProcessFixture process;
    REQUIRE(process.available());

    RemoteAllocation memory(process.process, 4096, PAGE_READWRITE);
    REQUIRE(memory);

    const std::array<std::uint8_t, 4> original{1,2,3,4};
    const std::array<std::uint8_t, 4> replacement{5,6,7,8};

    REQUIRE(WriteProcessMemory(
        process.process, memory.address, original.data(), original.size(), nullptr));

    DWORD previous = 0;
    REQUIRE(VirtualProtectEx(
        process.process, memory.address, 4096,
        PAGE_READONLY | PAGE_GUARD, &previous));

    const DWORD before = QueryProtection(process.process, memory.address);

    CHECK(WinProcHandling::WriteMemory(
        process.process, memory.address, replacement.data(), replacement.size(),
        WinProcHandling::e_VirtualProtectMode::SafelyChange, true)
        == WinProcHandling::e_WriteStatus::WriteMemoryFailed);

    CHECK(QueryProtection(process.process, memory.address) == before);
}

/** @test Verifies the behavior described by the Catch2 test name. */
TEST_CASE("Remote ReadMemory reads exact bytes and restores protection", "[remote][read]") {
    ProcessFixture process;
    REQUIRE(process.available());

    RemoteAllocation memory(process.process, 4096, PAGE_NOACCESS);
    REQUIRE(memory);

    // Seed the page by temporarily making it writable.
    DWORD oldProtection = 0;
    REQUIRE(VirtualProtectEx(
        process.process, memory.address, 4096, PAGE_READWRITE, &oldProtection));

    const std::array<std::uint8_t, 16> expected{
        0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
        0x10,0x32,0x54,0x76,0x98,0xBA,0xDC,0xFE
    };

    REQUIRE(WriteProcessMemory(
        process.process, memory.address, expected.data(),
        expected.size(), nullptr));

    REQUIRE(VirtualProtectEx(
        process.process, memory.address, 4096, PAGE_NOACCESS, &oldProtection));

    const DWORD before = QueryProtection(process.process, memory.address);

    std::array<std::uint8_t, 16> observed{};
    CHECK(WinProcHandling::ReadMemory(
        process.process, observed.data(), memory.address, observed.size(),
        WinProcHandling::e_VirtualProtectMode::SafelyChange));

    CHECK(observed == expected);
    CHECK(QueryProtection(process.process, memory.address) == before);
}

/** @test Verifies the behavior described by the Catch2 test name. */
TEST_CASE("Remote ReadMemory failure still restores protection", "[remote][read][regression]") {
    ProcessFixture process;
    REQUIRE(process.available());

    RemoteAllocation memory(process.process, 4096, PAGE_NOACCESS);
    REQUIRE(memory);

    DWORD oldProtection = 0;
    REQUIRE(VirtualProtectEx(
        process.process, memory.address, 4096, PAGE_READWRITE, &oldProtection));

    std::array<std::uint8_t, 8> expected{1,2,3,4,5,6,7,8};
    REQUIRE(WriteProcessMemory(
        process.process, memory.address, expected.data(), expected.size(), nullptr));

    REQUIRE(VirtualProtectEx(
        process.process, memory.address, 4096, PAGE_NOACCESS, &oldProtection));

    // Cross into an uncommitted address by reading beyond the allocation.
    std::array<std::uint8_t, 16> output{};
    const auto badAddress =
        reinterpret_cast<const std::uint8_t*>(memory.address) + 4096 - 4;

    CHECK_FALSE(WinProcHandling::ReadMemory(
        process.process, output.data(), badAddress, output.size(),
        WinProcHandling::e_VirtualProtectMode::SafelyChange));

    CHECK(QueryProtection(process.process, memory.address) == PAGE_NOACCESS);
}

/** @test Verifies the behavior described by the Catch2 test name. */
TEST_CASE("Remote write rejects a cross-region write rather than changing unrelated pages",
          "[remote][write][boundaries]") {
    ProcessFixture process;
    REQUIRE(process.available());

    constexpr SIZE_T page = 4096;

    // Two separate allocations make the second page a different reservation.
    RemoteAllocation first(process.process, page, PAGE_READONLY);
    REQUIRE(first);

    const std::array<std::uint8_t, 8> bytes{1,2,3,4,5,6,7,8};
    const auto address =
        reinterpret_cast<std::uint8_t*>(first.address) + page - 4;

    // The allocation ends at address+4; the requested write extends beyond it.
    CHECK(
        WinProcHandling::WriteMemory(
            process.process, address, bytes.data(), bytes.size(),
            WinProcHandling::e_VirtualProtectMode::SafelyChange, true)
        == WinProcHandling::e_WriteStatus::WriteMemoryFailed);
}

/** @test Verifies the behavior described by the Catch2 test name. */
TEST_CASE("DontChange does not alter protection", "[remote][write][protection]") {
    ProcessFixture process;
    REQUIRE(process.available());

    RemoteAllocation memory(process.process, 4096, PAGE_READWRITE);
    REQUIRE(memory);

    const std::array<std::uint8_t, 4> bytes{0xAA,0xBB,0xCC,0xDD};
    const DWORD before = QueryProtection(process.process, memory.address);

    CHECK(WinProcHandling::WriteMemory(
        process.process, memory.address, bytes.data(), bytes.size(),
        WinProcHandling::e_VirtualProtectMode::DontChange, true)
        == WinProcHandling::e_WriteStatus::Success);

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
    CHECK(WinProcHandling::WriteMemory(
        nullptr, nullptr, 0) == WinProcHandling::e_WriteStatus::Success);

    CHECK(WinProcHandling::FillWithNOPs(
        nullptr, 0) == WinProcHandling::e_WriteStatus::Success);

    CHECK(WinProcHandling::ReadMemory(
        nullptr, nullptr, 0));
}

/** @test Verifies the behavior described by the Catch2 test name. */
TEST_CASE("ForEachScanProcess invokes callback with module-relative indices", "[scan]") {
    ProcessFixture process;
    REQUIRE(process.available());

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

/** @test Verifies the behavior described by the Catch2 test name. */
TEST_CASE("Local WriteMemory flushes executable code and restores protection",
          "[local][cache]") {
    constexpr SIZE_T page = 4096;
    LocalAllocation code(page, PAGE_READWRITE);
    REQUIRE(code);

#if defined(_M_X64) || defined(__x86_64__)
    // mov eax, 1; ret
    const std::array<std::uint8_t, 6> code1{0xB8,0x01,0x00,0x00,0x00,0xC3};
    // mov eax, 2; ret
    const std::array<std::uint8_t, 6> code2{0xB8,0x02,0x00,0x00,0x00,0xC3};

    REQUIRE(WinProcHandling::WriteMemory(
        code.address, code1.data(), code1.size(),
        WinProcHandling::e_VirtualProtectMode::SafelyChange, true)
        == WinProcHandling::e_WriteStatus::Success);

    DWORD oldProtect = 0;
    REQUIRE(VirtualProtect(code.address, page, PAGE_EXECUTE_READ, &oldProtect));

    auto fn = reinterpret_cast<int(*)()>(code.address);
    CHECK(fn() == 1);

    // Change back through the library; the library must flush the instruction cache.
    REQUIRE(WinProcHandling::WriteMemory(
        code.address, code2.data(), code2.size(),
        WinProcHandling::e_VirtualProtectMode::SafelyChange, true)
        == WinProcHandling::e_WriteStatus::Success);

    CHECK(fn() == 2);
#else
    SKIP("Executable-code test is implemented for x64 builds.");
#endif
}
