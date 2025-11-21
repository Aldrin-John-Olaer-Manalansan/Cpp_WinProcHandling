/*
 * @File: WinProcHandling.hpp
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

#pragma once

#ifndef NOMINMAX
    #define NOMINMAX 1
#endif

#include <windows.h>
#include <cstdint>

namespace WinProcHandling {
    struct t_ProcessInfo {
        size_t searchedOffsetFromBase;
        size_t searchSize;
        DWORD id;
        HANDLE handle;
        uintptr_t moduleBase;
        size_t moduleSize;
    };

    enum class e_WriteStatus : int8_t {
        FlushInstructionCacheFailed = -1,
        WriteMemoryFailed,
        Success
    };
    
    enum class e_VirtualProtectMode : uint8_t {
        DontChange,
        SafelyChange,
        ForceChange
    };

    DWORD FindProcessId(const char* processName);

    DWORD GetModuleBase(HANDLE processHandle, uintptr_t *const outBase);
    DWORD GetModuleBase(DWORD pid, const char* moduleName, uintptr_t *const outBase);

    void ForEachScanProcess(
        t_ProcessInfo* const processInfo,
        void* const callbackData, bool(*callback)(void* callbackData, size_t byteIndex, uint8_t& byte)
    );

    e_WriteStatus FillWithNOPs(
        LPVOID target, 
        const SIZE_T patchSize, 
        const e_VirtualProtectMode virtualProtectMode = e_VirtualProtectMode::DontChange,
        const bool flushInstructionCache = true);
    e_WriteStatus FillWithNOPs(
        HANDLE processHandle, 
        LPVOID target, 
        const SIZE_T patchSize, 
        const e_VirtualProtectMode virtualProtectMode = e_VirtualProtectMode::SafelyChange,
        const bool flushInstructionCache = true);

    e_WriteStatus WriteMemory(
        LPVOID destination, 
        LPCVOID source, 
        const SIZE_T size, 
        const e_VirtualProtectMode virtualProtectMode = e_VirtualProtectMode::DontChange,
        const bool flushInstructionCache = true);
    e_WriteStatus WriteMemory(
        HANDLE processHandle, 
        LPVOID remoteDestination, 
        LPCVOID localSource, 
        const SIZE_T size, 
        const e_VirtualProtectMode virtualProtectMode = e_VirtualProtectMode::SafelyChange,
        const bool flushInstructionCache = true);

    bool ReadMemory(
        LPVOID destination, 
        LPCVOID source, 
        const SIZE_T size, 
        const e_VirtualProtectMode virtualProtectMode = e_VirtualProtectMode::DontChange);
    bool ReadMemory(
        HANDLE processHandle, 
        LPVOID localDestination, 
        LPCVOID remoteSource, 
        const SIZE_T size, 
        const e_VirtualProtectMode virtualProtectMode = e_VirtualProtectMode::SafelyChange);
}