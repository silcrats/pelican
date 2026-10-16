"""
Text from the binary Office formats of Word and PowerPoint 97-2003 (.doc,
.ppt and their template/show variants), in pure Python on olefile -- no
LibreOffice (hundreds of MB in the image) and no unmaintained C parser
(catdoc, antiword) reading untrusted files from shares.

Word ([MS-DOC]): the text is in the WordDocument stream, in pieces listed by
the piece table (the Clx, in the 0Table/1Table stream); each piece is either
8-bit (cp1252) or UTF-16. Field codes are dropped, keeping their results.

PowerPoint ([MS-PPT]): the text is in TextCharsAtom (UTF-16) and
TextBytesAtom (8-bit) records in the "PowerPoint Document" stream, including
speaker notes. The slide and notes masters are skipped (their placeholder
text such as "Click to edit Master title style" isn't the presentation's
content), as are slide-number placeholders ("*").

Word 6/95 files, encrypted files and anything malformed return "".
"""

import io
import struct

import olefile

_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

# Word special characters: paragraph/cell/line/page marks become line
# breaks; object anchors, footnote/comment references and optional hyphens
# are dropped.
_WORD_CHARS = str.maketrans({
    "\r": "\n", "\x07": "\t", "\x0b": "\n", "\x0c": "\n", "\x0e": "\n",
    "\x1e": "-", "\xa0": " ",
    "\x01": None, "\x02": None, "\x03": None, "\x04": None, "\x05": None, "\x08": None, "\x1f": None,
})
_FIELD_BEGIN, _FIELD_SEPARATOR, _FIELD_END = "\x13", "\x14", "\x15"


def is_ole(data: bytes) -> bool:
    return data[:8] == _OLE_MAGIC


def extract_doc(data: bytes) -> str:
    if not is_ole(data):
        return ""
    with olefile.OleFileIO(io.BytesIO(data)) as ole:
        if not ole.exists("WordDocument"):
            return ""
        word = ole.openstream("WordDocument").read()
        if len(word) < 34:
            return ""
        ident, nfib = struct.unpack_from("<HH", word, 0)
        flags = struct.unpack_from("<H", word, 0x0A)[0]
        if ident != 0xA5EC or nfib < 0x65 or flags & 0x0100:   # not Word 97+, or encrypted
            return ""
        table_name = "1Table" if flags & 0x0200 else "0Table"
        if not ole.exists(table_name):
            return ""
        table = ole.openstream(table_name).read()

    # FIB: FibBase (32 bytes), then three counted arrays; fcClx/lcbClx is
    # the 34th (fc, lcb) pair of the last one.
    pos = 32
    csw = struct.unpack_from("<H", word, pos)[0]
    pos += 2 + csw * 2
    cslw = struct.unpack_from("<H", word, pos)[0]
    pos += 2 + cslw * 4
    cb_fc_lcb = struct.unpack_from("<H", word, pos)[0]
    pos += 2
    if cb_fc_lcb <= 33 or pos + 34 * 8 > len(word):
        return ""
    fc_clx, lcb_clx = struct.unpack_from("<II", word, pos + 33 * 8)
    if not lcb_clx or fc_clx + lcb_clx > len(table):
        return ""
    return _clean_word_text(_word_pieces_text(word, table[fc_clx:fc_clx + lcb_clx]))


def _word_pieces_text(word: bytes, clx: bytes) -> str:
    # Clx: any number of Prc (0x01, u16 size, data), then one Pcdt (0x02,
    # u32 size, PlcPcd = n+1 character positions then n 8-byte Pcds).
    pos = 0
    while pos < len(clx) and clx[pos] == 0x01:
        pos += 3 + struct.unpack_from("<H", clx, pos + 1)[0]
    if pos + 5 > len(clx) or clx[pos] != 0x02:
        return ""
    size = struct.unpack_from("<I", clx, pos + 1)[0]
    plc = clx[pos + 5:pos + 5 + size]
    count = (len(plc) - 4) // 12
    if count <= 0:
        return ""
    cps = struct.unpack_from(f"<{count + 1}I", plc, 0)
    parts = []
    for i in range(count):
        chars = cps[i + 1] - cps[i]
        if chars <= 0:
            continue
        fc_value = struct.unpack_from("<I", plc, (count + 1) * 4 + i * 8 + 2)[0]
        fc = fc_value & 0x3FFFFFFF
        if fc_value & 0x40000000:   # 8-bit text, stored at fc / 2
            start = fc // 2
            parts.append(word[start:start + chars].decode("cp1252", errors="replace"))
        else:
            parts.append(word[fc:fc + 2 * chars].decode("utf-16-le", errors="replace"))
    return "".join(parts)


def _clean_word_text(text: str) -> str:
    """Drop field codes (between field-begin and separator or end, possibly
    nested) but keep their displayed results, then map special characters."""
    out = []
    depth_in_code = []   # one entry per open field: True while in its code part
    for ch in text:
        if ch == _FIELD_BEGIN:
            depth_in_code.append(True)
        elif ch == _FIELD_SEPARATOR and depth_in_code:
            depth_in_code[-1] = False
        elif ch == _FIELD_END and depth_in_code:
            depth_in_code.pop()
        elif not any(depth_in_code):
            out.append(ch)
    # A row ends with a cell mark plus a row mark: make that a line break,
    # and the remaining cell marks tabs.
    lines = "".join(out).replace("\x07\x07", "\n").translate(_WORD_CHARS).split("\n")
    return "\n".join(line.strip() for line in lines if line.strip())


# PowerPoint record types.
_PPT_TEXT_CHARS = 0x0FA0
_PPT_TEXT_BYTES = 0x0FA8
_PPT_MAIN_MASTER = 0x03F8
_PPT_NOTES = 0x03F0
_PPT_NOTES_ATOM = 0x03F1


def extract_ppt(data: bytes) -> str:
    if not is_ole(data):
        return ""
    with olefile.OleFileIO(io.BytesIO(data)) as ole:
        if not ole.exists("PowerPoint Document") or ole.exists("EncryptedSummary"):
            return ""
        stream = ole.openstream("PowerPoint Document").read()
    texts: list[str] = []
    _walk_ppt_records(stream, 0, len(stream), texts)
    # The same text is often stored twice (outline and slide); keep the first.
    seen = set()
    lines = []
    for text in texts:
        for line in text.replace("\r", "\n").replace("\x0b", "\n").split("\n"):
            line = line.strip()
            if line and line != "*" and line not in seen:
                seen.add(line)
                lines.append(line)
    return "\n".join(lines)


def _walk_ppt_records(stream: bytes, pos: int, end: int, texts: list[str]) -> None:
    while pos + 8 <= end:
        ver_instance, rec_type, length = struct.unpack_from("<HHI", stream, pos)
        body = pos + 8
        if body + length > end:
            return   # truncated or not a record: stop rather than misread
        if ver_instance & 0x000F == 0x000F:   # container: its records follow
            if rec_type != _PPT_MAIN_MASTER and not _is_notes_master(stream, rec_type, body, body + length):
                _walk_ppt_records(stream, body, body + length, texts)
        elif rec_type == _PPT_TEXT_CHARS:
            texts.append(stream[body:body + length].decode("utf-16-le", errors="replace"))
        elif rec_type == _PPT_TEXT_BYTES:
            texts.append(stream[body:body + length].decode("latin-1"))
        pos = body + length


def _is_notes_master(stream: bytes, rec_type: int, body: int, end: int) -> bool:
    """A Notes container whose NotesAtom links to no slide (slideIdRef 0)
    is the notes master, not a slide's speaker notes."""
    if rec_type != _PPT_NOTES or body + 12 > end:
        return False
    _, child_type, _ = struct.unpack_from("<HHI", stream, body)
    return child_type == _PPT_NOTES_ATOM and struct.unpack_from("<I", stream, body + 8)[0] == 0
