"""Windows credential checks used to authorize destructive identity actions."""

from __future__ import annotations

import ctypes
import os
from ctypes import wintypes

_ERROR_LOGON_FAILURE = 1326
_ERROR_NO_SUCH_USER = 1317
_LOGON32_LOGON_INTERACTIVE = 2
_LOGON32_PROVIDER_DEFAULT = 0
_MAXIMUM_ALLOWED = 0x02000000
_SECURITY_IMPERSONATION = 2
_WIN_BUILTIN_ADMINISTRATORS_SID = 26
_SECURITY_MAX_SID_SIZE = 68
_TOKEN_IMPERSONATION = 2


def authenticate_windows_administrator(username: str, password: str) -> bool:
    """Return whether credentials authenticate a Windows administrator account."""
    if os.name != "nt":
        raise OSError("Windows administrator authentication is only available on Windows.")

    account = username.strip()
    secret = password
    if not account or not secret:
        return False

    if "\\" in account:
        domain, account = account.rsplit("\\", 1)
        if not domain or not account:
            return False
    elif "@" not in account:
        domain = "."
    else:
        domain = None

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    token = wintypes.HANDLE()
    logon_user = advapi32.LogonUserW
    logon_user.argtypes = (
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    )
    logon_user.restype = wintypes.BOOL

    if not logon_user(
        account,
        domain,
        secret,
        _LOGON32_LOGON_INTERACTIVE,
        _LOGON32_PROVIDER_DEFAULT,
        ctypes.byref(token),
    ):
        error = ctypes.get_last_error()
        if error in {_ERROR_LOGON_FAILURE, _ERROR_NO_SUCH_USER}:
            return False
        raise ctypes.WinError(error)

    impersonation_token = wintypes.HANDLE()
    try:
        duplicate_token = advapi32.DuplicateTokenEx
        duplicate_token.argtypes = (
            wintypes.HANDLE,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.HANDLE),
        )
        duplicate_token.restype = wintypes.BOOL
        if not duplicate_token(
            token,
            _MAXIMUM_ALLOWED,
            None,
            _SECURITY_IMPERSONATION,
            _TOKEN_IMPERSONATION,
            ctypes.byref(impersonation_token),
        ):
            raise ctypes.WinError(ctypes.get_last_error())

        sid_buffer = ctypes.create_string_buffer(_SECURITY_MAX_SID_SIZE)
        sid_size = wintypes.DWORD(_SECURITY_MAX_SID_SIZE)
        create_sid = advapi32.CreateWellKnownSid
        create_sid.argtypes = (
            wintypes.DWORD,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.DWORD),
        )
        create_sid.restype = wintypes.BOOL
        if not create_sid(
            _WIN_BUILTIN_ADMINISTRATORS_SID,
            None,
            ctypes.cast(sid_buffer, ctypes.c_void_p),
            ctypes.byref(sid_size),
        ):
            raise ctypes.WinError(ctypes.get_last_error())

        is_member = wintypes.BOOL()
        check_membership = advapi32.CheckTokenMembership
        check_membership.argtypes = (
            wintypes.HANDLE,
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.BOOL),
        )
        check_membership.restype = wintypes.BOOL
        if not check_membership(
            impersonation_token,
            ctypes.cast(sid_buffer, ctypes.c_void_p),
            ctypes.byref(is_member),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        return bool(is_member.value)
    finally:
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = (wintypes.HANDLE,)
        close_handle.restype = wintypes.BOOL
        if impersonation_token:
            close_handle(impersonation_token)
        close_handle(token)
