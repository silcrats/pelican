"""
SMB2/3 client for the crawler, on smbprotocol's low-level API: one
connection, session and tree connect per share, with what the crawler needs
-- list a directory, read a file -- each request bounded by a timeout.

Replaces pysmb, which opens every connection with an SMB1-format negotiate
that current Samba servers (and so most NAS devices) ignore. smbprotocol
negotiates SMB 2.0.2 up to 3.1.1 directly, with signing and, if the share's
`encrypt: true` or the server requires it, encryption.

Kept identical to what the pysmb-based crawler recorded, so upgrading
doesn't make every file look changed or deleted:
  - modification times: (FILETIME - 1601->1970 offset) / 10**7 from the raw
    value, as pysmb computed it. smbprotocol's own parsing rounds to
    microseconds, which wouldn't compare equal with what the state DB holds.
  - which directory entries are returned (pysmb's default listPath filter).
"""

import struct
import uuid

from smbprotocol.connection import Connection
from smbprotocol.exceptions import EndOfFile, NoMoreFiles, NoSuchFile
from smbprotocol.file_info import FileAttributes, FileInformationClass
from smbprotocol.open import (CreateDisposition, CreateOptions, DirectoryAccessMask,
                              FilePipePrinterAccessMask, ImpersonationLevel, Open, ShareAccess,
                              SMB2QueryDirectoryResponse, SMB2ReadResponse)
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect

_EPOCH_FILETIME = 116444736000000000   # 1970-01-01 as a FILETIME
_SHARE_ALL = ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE | ShareAccess.FILE_SHARE_DELETE
_READ_CHUNK = 1024 * 1024
_LIST_BUFFER = 64 * 1024

# FILE_ID_FULL_DIRECTORY_INFORMATION ([MS-FSCC] 2.4.18), up to the name:
# next_entry_offset, file_index, creation, last_access, last_write, change,
# end_of_file, allocation_size, file_attributes, file_name_length, ea_size,
# reserved, file_id.
_DIR_ENTRY = struct.Struct("<IIQQQQQQIIIIQ")

# pysmb's default listPath() filter: an entry whose low 8 attribute bits are
# 0 or NORMAL is kept; otherwise it needs one of these bits.
_PYSMB_SEARCH = 0x01 | 0x02 | 0x04 | 0x10 | 0x20   # readonly, hidden, system, directory, archive


def filetime_to_epoch(filetime: int) -> float:
    return (filetime - _EPOCH_FILETIME) / 10000000.0


class SmbShareClient:
    """A connection to one share. Not for use from several threads at once:
    give each thread its own."""

    def __init__(self, server: str, share: str, user: str, password: str, domain: str = "",
                 encrypt: bool = False, connect_timeout: int = 30):
        self._connection = Connection(uuid.uuid4(), server, 445)
        self._connection.connect(timeout=connect_timeout)
        try:
            username = f"{domain}\\{user}" if domain else user
            self._session = Session(self._connection, username, password,
                                    require_encryption=encrypt, auth_protocol="ntlm")
            self._session.connect()
            self._tree = TreeConnect(self._session, rf"\\{server}\{share}")
            self._tree.connect()
        except Exception:
            self._connection.disconnect()
            raise

    def _call(self, message_and_parser, timeout: float):
        """Send a request built with send=False, wait up to `timeout` for the
        answer (raising on an error status), then parse it."""
        message, parse = message_and_parser
        request = self._connection.send(message, self._session.session_id, self._tree.tree_connect_id)
        self._connection.receive(request, timeout=timeout)
        return parse(request)

    def _raw_response(self, message_and_parser, timeout: float):
        message, _ = message_and_parser
        request = self._connection.send(message, self._session.session_id, self._tree.tree_connect_id)
        return self._connection.receive(request, timeout=timeout)["data"].get_value()

    def _open(self, path: str, directory: bool, timeout: float) -> Open:
        handle = Open(self._tree, path.replace("/", "\\").strip("\\"))
        if directory:
            access = DirectoryAccessMask.FILE_LIST_DIRECTORY | DirectoryAccessMask.FILE_READ_ATTRIBUTES
            options = CreateOptions.FILE_DIRECTORY_FILE
            attributes = FileAttributes.FILE_ATTRIBUTE_DIRECTORY
        else:
            access = FilePipePrinterAccessMask.FILE_READ_DATA | FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES
            options = CreateOptions.FILE_NON_DIRECTORY_FILE
            attributes = FileAttributes.FILE_ATTRIBUTE_NORMAL
        self._call(handle.create(ImpersonationLevel.Impersonation, access, attributes, _SHARE_ALL,
                                 CreateDisposition.FILE_OPEN, options, send=False), timeout)
        return handle

    def list_dir(self, path: str, timeout: float) -> list[tuple[str, bool, float]]:
        """(name, is_directory, last_write_time) for each entry of a
        directory, without "." and "..". Raises if the directory can't be
        opened or read; an empty directory returns []."""
        handle = self._open(path, directory=True, timeout=timeout)
        entries: list[tuple[str, bool, float]] = []
        try:
            while True:
                try:
                    data = self._raw_response(handle.query_directory(
                        "*", FileInformationClass.FILE_ID_FULL_DIRECTORY_INFORMATION,
                        max_output=_LIST_BUFFER, send=False), timeout)
                except (NoMoreFiles, NoSuchFile):
                    break
                response = SMB2QueryDirectoryResponse()
                response.unpack(data)
                entries.extend(_parse_entries(response["buffer"].get_value()))
        finally:
            self._close(handle, timeout)
        return entries

    def read_file(self, path: str, timeout: float) -> bytes:
        """The whole file. `timeout` bounds each request, not the transfer."""
        handle = self._open(path, directory=False, timeout=timeout)
        chunks = []
        try:
            size = handle.end_of_file
            chunk = min(_READ_CHUNK, self._connection.max_read_size)
            offset = 0
            while offset < size:
                try:
                    data = self._raw_response(handle.read(offset, min(chunk, size - offset), send=False), timeout)
                except EndOfFile:   # the file shrank while being read
                    break
                response = SMB2ReadResponse()
                response.unpack(data)
                piece = response["buffer"].get_value()
                if not piece:
                    break
                chunks.append(piece)
                offset += len(piece)
        finally:
            self._close(handle, timeout)
        return b"".join(chunks)

    def _close(self, handle: Open, timeout: float) -> None:
        """Close a handle without masking an error already on its way out."""
        try:
            self._call(handle.close(send=False), timeout)
        except Exception:
            pass

    def close(self) -> None:
        try:
            self._connection.disconnect()
        except Exception:
            pass   # already gone; nothing to release


def _parse_entries(buffer: bytes) -> list[tuple[str, bool, float]]:
    entries = []
    offset = 0
    while offset + _DIR_ENTRY.size <= len(buffer):
        (next_offset, _, _, _, last_write, _, _, _, attributes, name_length, _, _, _
         ) = _DIR_ENTRY.unpack_from(buffer, offset)
        name_start = offset + _DIR_ENTRY.size
        name = buffer[name_start:name_start + name_length].decode("utf-16-le", errors="replace")
        low = attributes & 0xFF
        keep = low in (0x00, 0x80) or bool(attributes & _PYSMB_SEARCH)
        if keep and name not in (".", ".."):
            entries.append((name, bool(attributes & 0x10), filetime_to_epoch(last_write)))
        if not next_offset:
            break
        offset += next_offset
    return entries
