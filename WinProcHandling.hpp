/*
 * @File: WinProcHandling.hpp
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

#pragma once

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

    DWORD FindProcessId(const char* processName);
    // uintptr_t GetModuleBase(DWORD pid, const char* moduleName);
    DWORD GetModuleBase(HANDLE hProcess, uintptr_t *const outBase);
    DWORD GetModuleBase(DWORD pid, const char* moduleName, uintptr_t *const outBase);
    void ForEachScanProcess(
        t_ProcessInfo* const processInfo,
        void* const callbackData, bool(*callback)(void* callbackData, size_t byteIndex, uint8_t& byte)
    );
    bool PatchMemory(HANDLE ph, LPVOID target, LPCVOID patchBytes, const SIZE_T patchSize);
    bool FillWithNOPs(HANDLE ph, LPVOID target, const SIZE_T patchSize);
    bool ReadMemory(HANDLE ph, LPVOID destination, LPCVOID target, const SIZE_T size);
}