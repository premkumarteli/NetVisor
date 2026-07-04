from __future__ import annotations

import ctypes
import os
import secrets
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CRYPTPROTECT_UI_FORBIDDEN = 0x01


class DataProtector:
    def protect(self, data: bytes, *, description: str = "") -> bytes:
        raise NotImplementedError

    def unprotect(self, data: bytes) -> bytes:
        raise NotImplementedError


class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", ctypes.c_uint),
        ("pbData", ctypes.POINTER(ctypes.c_byte)),
    ]


class WindowsCurrentUserProtector(DataProtector):
    def __init__(self) -> None:
        self._available = os.name == "nt"
        if self._available:
            self._crypt32 = ctypes.windll.crypt32
            self._kernel32 = ctypes.windll.kernel32

    def _require_windows(self) -> None:
        if not self._available:
            raise RuntimeError("Windows DPAPI is only available on Windows gateways.")

    def _bytes_from_blob(self, blob: DATA_BLOB) -> bytes:
        try:
            return ctypes.string_at(blob.pbData, blob.cbData)
        finally:
            if blob.pbData:
                self._kernel32.LocalFree(blob.pbData)

    def protect(self, data: bytes, *, description: str = "") -> bytes:
        self._require_windows()
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("DPAPI protector expects bytes")

        input_buffer = ctypes.create_string_buffer(bytes(data), len(data))
        input_blob = DATA_BLOB(len(data), ctypes.cast(input_buffer, ctypes.POINTER(ctypes.c_byte)))
        output_blob = DATA_BLOB()
        description_value = ctypes.c_wchar_p(description or "")
        success = self._crypt32.CryptProtectData(
            ctypes.byref(input_blob),
            description_value,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(output_blob),
        )
        if not success:
            raise ctypes.WinError()
        return self._bytes_from_blob(output_blob)

    def unprotect(self, data: bytes) -> bytes:
        self._require_windows()
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("DPAPI protector expects bytes")

        input_buffer = ctypes.create_string_buffer(bytes(data), len(data))
        input_blob = DATA_BLOB(len(data), ctypes.cast(input_buffer, ctypes.POINTER(ctypes.c_byte)))
        output_blob = DATA_BLOB()
        success = self._crypt32.CryptUnprotectData(
            ctypes.byref(input_blob),
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(output_blob),
        )
        if not success:
            raise ctypes.WinError()
        return self._bytes_from_blob(output_blob)


class FileProtector(DataProtector):
    def __init__(self, key_path: Path | None = None) -> None:
        if key_path is None:
            self.key_path = Path.home() / ".netvisor" / "gateway_key.bin"
        else:
            self.key_path = Path(key_path)
        self._key: bytes | None = None

    def _get_key(self) -> bytes:
        if self._key is not None:
            return self._key

        if not self.key_path.exists():
            try:
                self.key_path.parent.mkdir(parents=True, exist_ok=True)
                key = secrets.token_bytes(32)
                self.key_path.write_bytes(key)
                if os.name != "nt":
                    try:
                        self.key_path.chmod(0o600)
                    except OSError:
                        pass
                self._key = key
            except Exception as exc:
                raise RuntimeError(f"Failed to generate and store fallback key at {self.key_path}: {exc}")
        else:
            try:
                if os.name != "nt":
                    try:
                        self.key_path.chmod(0o600)
                    except OSError:
                        pass
                self._key = self.key_path.read_bytes()
            except Exception as exc:
                raise RuntimeError(f"Failed to read fallback key from {self.key_path}: {exc}")
        
        return self._key

    def protect(self, data: bytes, *, description: str = "") -> bytes:
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("Protector expects bytes")
        key = self._get_key()
        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(12)
        ciphertext = aesgcm.encrypt(nonce, bytes(data), None)
        return b"v1:" + nonce + b":" + ciphertext

    def unprotect(self, data: bytes) -> bytes:
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("Protector expects bytes")
        data_bytes = bytes(data)
        if not data_bytes.startswith(b"v1:"):
            raise ValueError("Unsupported or corrupted payload format")
        
        try:
            parts = data_bytes.split(b":", 2)
            if len(parts) != 3:
                raise ValueError("Corrupted payload segments")
            nonce = parts[1]
            ciphertext = parts[2]
            key = self._get_key()
            aesgcm = AESGCM(key)
            return aesgcm.decrypt(nonce, ciphertext, None)
        except Exception as exc:
            raise ValueError(f"Failed to decrypt data: {exc}")


import json

class DynamicProtector(DataProtector):
    def __init__(self, key_path: Path | None = None) -> None:
        self.windows_protector = WindowsCurrentUserProtector()
        self.file_protector = FileProtector(key_path)
        self.is_windows = os.name == "nt"

    def protect(self, data: bytes, *, description: str = "") -> bytes:
        if self.is_windows:
            try:
                return self.windows_protector.protect(data, description=description)
            except Exception:
                pass
        return self.file_protector.protect(data, description=description)

    def unprotect(self, data: bytes) -> bytes:
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("Protector expects bytes")
        data_bytes = bytes(data)
        if data_bytes.startswith(b"v1:"):
            return self.file_protector.unprotect(data_bytes)
        if self.is_windows:
            return self.windows_protector.unprotect(data_bytes)
        
        # Fallback for unencrypted legacy JSON configuration on Unix
        try:
            json.loads(data_bytes.decode("utf-8"))
            return data_bytes
        except Exception:
            pass
            
        raise ValueError("Unsupported ciphertext format on this platform")
