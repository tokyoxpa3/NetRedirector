# -*- coding: utf-8 -*-
"""Windows 單一實例控制 (named mutex + 既有視窗帶到前景)。

用命名 mutex 判斷是否已有程式執行個體在跑：第二次啟動時不開新視窗，
而是把已開啟的視窗還原/帶到前景後立即結束。

mutex handle 需在整個程式生命週期持有，否則 Windows 會在最後一個 handle
關閉時自動釋放 mutex，造成單一實例保護失效。
"""

import ctypes
from ctypes import wintypes

_MUTEX_NAME = "Local\\NetRedirector.SingleInstance"
_ERROR_ALREADY_EXISTS = 183
_SW_RESTORE = 9

_kernel32 = ctypes.windll.kernel32
_user32 = ctypes.windll.user32

_kernel32.CreateMutexW.restype = wintypes.HANDLE
_kernel32.CreateMutexW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR]
_kernel32.CloseHandle.argtypes = [wintypes.HANDLE]


def acquire_mutex():
    """建立命名 mutex。

    回傳 (handle, already_running)：
    - handle: 成功建立時為有效 handle，需於程式結束時 release_mutex()。
    - already_running: True 表示已有其他執行個體持有該 mutex。
    """
    handle = _kernel32.CreateMutexW(None, False, _MUTEX_NAME)
    if not handle:
        return None, False
    if _kernel32.GetLastError() == _ERROR_ALREADY_EXISTS:
        _kernel32.CloseHandle(handle)
        return None, True
    return handle, False


def release_mutex(handle):
    """釋放 mutex handle。"""
    if handle:
        _kernel32.CloseHandle(handle)


def bring_existing_to_front(title_substr="NetRedirector"):
    """列舉所有可見視窗，把標題含 title_substr 的視窗還原並帶到前景。"""
    matches = []

    WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

    def _cb(hwnd, _lparam):
        if not _user32.IsWindowVisible(hwnd):
            return True
        length = _user32.GetWindowTextLengthW(hwnd)
        if length <= 0:
            return True
        buf = ctypes.create_unicode_buffer(length + 1)
        _user32.GetWindowTextW(hwnd, buf, length + 1)
        if title_substr in buf.value:
            matches.append(hwnd)
        return True

    _user32.EnumWindows(WNDENUMPROC(_cb), 0)
    if not matches:
        return False

    hwnd = matches[0]
    if _user32.IsIconic(hwnd):
        _user32.ShowWindow(hwnd, _SW_RESTORE)
    _user32.SetForegroundWindow(hwnd)
    return True
