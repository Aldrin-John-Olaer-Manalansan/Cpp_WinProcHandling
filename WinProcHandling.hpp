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

    DWORD GetModuleBase(HANDLE processHandle, uintptr_t *const outBase);
    DWORD GetModuleBase(DWORD pid, const char* moduleName, uintptr_t *const outBase);

    void ForEachScanProcess(
        t_ProcessInfo* const processInfo,
        void* const callbackData, bool(*callback)(void* callbackData, size_t byteIndex, uint8_t& byte)
    );

    int8_t FillWithNOPs(LPVOID target, const SIZE_T patchSize, const bool virtualProtect = false);
    int8_t FillWithNOPs(HANDLE processHandle, LPVOID target, const SIZE_T patchSize);

    int8_t WriteMemory(LPVOID destination, LPCVOID source, const SIZE_T size, const bool virtualProtect = false);
    int8_t WriteMemory(HANDLE processHandle, LPVOID remoteDestination, LPCVOID localSource, const SIZE_T size);

    bool ReadMemory(LPVOID destination, LPCVOID source, const SIZE_T size, const bool virtualProtect = false);
    bool ReadMemory(HANDLE processHandle, LPVOID localDestination, LPCVOID remoteSource, const SIZE_T size);
}