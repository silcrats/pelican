"""
Text from PowerPoint (.pptx), OpenDocument text (.odt) and RTF files, in
pure Python. .pptx and .odt are zip files of XML; each XML part read is
capped at MAX_XML_PART_BYTES uncompressed, so a "zip bomb" can't exhaust
memory. Malformed files raise; the caller (extract_text) logs and indexes
them without text.
"""

import re
import zipfile
from io import BytesIO
from xml.etree import ElementTree

MAX_XML_PART_BYTES = 50 * 1024 * 1024

_NS = {
    "a": "http://schemas.openxmlformats.org/drawingml/2006/main",
    "p": "http://schemas.openxmlformats.org/presentationml/2006/main",
    "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
    "rel": "http://schemas.openxmlformats.org/package/2006/relationships",
    "text": "urn:oasis:names:tc:opendocument:xmlns:text:1.0",
    "office": "urn:oasis:names:tc:opendocument:xmlns:office:1.0",
    "table": "urn:oasis:names:tc:opendocument:xmlns:table:1.0",
}
_NOTES_SLIDE_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/notesSlide"


def _read_part(zf: zipfile.ZipFile, name: str) -> bytes | None:
    try:
        info = zf.getinfo(name)
    except KeyError:
        return None
    if info.file_size > MAX_XML_PART_BYTES:
        raise ValueError(f"{name} is {info.file_size} bytes uncompressed, over the limit")
    with zf.open(info) as f:
        data = f.read(MAX_XML_PART_BYTES + 1)   # the declared size can lie
    if len(data) > MAX_XML_PART_BYTES:
        raise ValueError(f"{name} is over the uncompressed size limit")
    return data


def _resolve(base_dir: str, target: str) -> str:
    """A relationship target relative to the part's folder, as a zip path."""
    parts = (target.lstrip("/") if target.startswith("/") else f"{base_dir}/{target}").split("/")
    out: list[str] = []
    for part in parts:
        if part == "..":
            if out:
                out.pop()
        elif part and part != ".":
            out.append(part)
    return "/".join(out)


def _relationships(zf: zipfile.ZipFile, part: str) -> dict[str, tuple[str, str]]:
    """rId -> (type, zip path) for a part's relationships."""
    folder, _, name = part.rpartition("/")
    data = _read_part(zf, f"{folder}/_rels/{name}.rels")
    if data is None:
        return {}
    return {rel.get("Id"): (rel.get("Type"), _resolve(folder, rel.get("Target", "")))
            for rel in ElementTree.fromstring(data).findall("rel:Relationship", _NS)}


def _drawing_paragraphs(xml: bytes) -> list[str]:
    """Each DrawingML paragraph's text (runs and line breaks; fields such
    as slide numbers and dates skipped)."""
    lines = []
    for para in ElementTree.fromstring(xml).iter(f"{{{_NS['a']}}}p"):
        pieces = []
        for el in para:
            if el.tag == f"{{{_NS['a']}}}r":
                pieces.append("".join(t.text or "" for t in el.iter(f"{{{_NS['a']}}}t")))
            elif el.tag == f"{{{_NS['a']}}}br":
                pieces.append("\n")
        text = "".join(pieces).strip()
        if text:
            lines.append(text)
    return lines


def extract_pptx(data: bytes) -> str:
    with zipfile.ZipFile(BytesIO(data)) as zf:
        presentation = _read_part(zf, "ppt/presentation.xml")
        if presentation is None:
            return ""
        rels = _relationships(zf, "ppt/presentation.xml")
        slide_ids = ElementTree.fromstring(presentation).findall("p:sldIdLst/p:sldId", _NS)
        lines: list[str] = []
        for slide_id in slide_ids:   # presentation order, hidden slides included
            _, slide_part = rels.get(slide_id.get(f"{{{_NS['r']}}}id"), (None, None))
            slide = _read_part(zf, slide_part) if slide_part else None
            if slide is None:
                continue
            lines += _drawing_paragraphs(slide)
            for rel_type, target in _relationships(zf, slide_part).values():
                if rel_type == _NOTES_SLIDE_REL:
                    notes = _read_part(zf, target)
                    if notes is not None:
                        lines += _notes_text(notes)
        return "\n".join(lines)


def _notes_text(xml: bytes) -> list[str]:
    """A notes slide's speaker notes: only its body placeholder (not the
    slide image or slide number)."""
    root = ElementTree.fromstring(xml)
    lines = []
    for shape in root.iter(f"{{{_NS['p']}}}sp"):
        placeholder = shape.find("p:nvSpPr/p:nvPr/p:ph", _NS)
        if placeholder is not None and placeholder.get("type") == "body":
            lines += _drawing_paragraphs(ElementTree.tostring(shape))
    return lines


def extract_odt(data: bytes) -> str:
    with zipfile.ZipFile(BytesIO(data)) as zf:
        content = _read_part(zf, "content.xml")
    if content is None:
        return ""
    body = ElementTree.fromstring(content).find("office:body", _NS)
    if body is None:
        return ""
    lines: list[str] = []
    paragraph_tags = {f"{{{_NS['text']}}}p", f"{{{_NS['text']}}}h"}

    def paragraphs(el, into: list[str]) -> None:
        if el.tag in paragraph_tags:
            text = _odf_inline(el).strip()
            if text:
                into.append(text)
            return   # nested paragraphs (notes) are inside _odf_inline's walk
        if el.tag == f"{{{_NS['table']}}}table-row":
            # One line per row, cells separated by tabs (as for .doc and .rtf).
            cells = []
            for cell in el.findall("table:table-cell", _NS):
                cell_lines: list[str] = []
                paragraphs(cell, cell_lines)
                cells.append(" ".join(cell_lines))
            if any(cells):
                into.append("\t".join(cells).strip())
            return
        for child in el:
            paragraphs(child, into)

    paragraphs(body, lines)
    return "\n".join(lines)


def _odf_inline(el) -> str:
    """A paragraph's text, with ODF's space, tab and line-break elements."""
    out = [el.text or ""]
    for child in el:
        tag = child.tag.rsplit("}", 1)[-1]
        if tag == "s":
            out.append(" " * int(child.get(f"{{{_NS['text']}}}c", "1")))
        elif tag == "tab":
            out.append("\t")
        elif tag == "line-break":
            out.append("\n")
        elif tag not in ("annotation", "bookmark", "bookmark-start", "bookmark-end"):
            out.append(_odf_inline(child))
        out.append(child.tail or "")
    return "".join(out)


# --- RTF -------------------------------------------------------------------

_RTF_TOKEN = re.compile(rb"\\([a-zA-Z]+)(-?\d+)? ?|\\'([0-9a-fA-F]{2})|\\(.)|([{}])|[\r\n]+|([^\\{}\r\n]+)", re.S)
# Groups whose content isn't document text.
_RTF_SKIP = {b"fonttbl", b"colortbl", b"stylesheet", b"info", b"pict", b"object", b"themedata",
             b"colorschememapping", b"datastore", b"latentstyles", b"listtable", b"listoverridetable",
             b"rsidtbl", b"generator", b"xmlnstbl", b"filetbl", b"revtbl", b"fldinst", b"header",
             b"footer", b"headerl", b"headerr", b"footerl", b"footerr", b"mmathPr", b"wgrffmtfilter"}
_RTF_BREAKS = {b"par": "\n", b"line": "\n", b"row": "\n", b"page": "\n", b"sect": "\n",
               b"tab": "\t", b"cell": "\t", b"emdash": "\u2014", b"endash": "\u2013",
               b"bullet": "\u2022", b"lquote": "\u2018", b"rquote": "\u2019",
               b"ldblquote": "\u201c", b"rdblquote": "\u201d"}


def extract_rtf(data: bytes) -> str:
    if not data.lstrip().startswith(b"{\\rtf"):
        return ""
    codepage = "cp1252"
    m = re.search(rb"\\ansicpg(\d+)", data[:2000])
    if m:
        codepage = f"cp{int(m.group(1))}"
        try:
            "".encode(codepage)
        except LookupError:
            codepage = "cp1252"

    out: list[str] = []
    pending = bytearray()      # \'hh bytes, decoded together (multi-byte code pages)
    stack: list[tuple[bool, int]] = []
    skipping = False           # inside a group that isn't document text
    uc = 1                     # characters to skip after each \uN
    skip_next = 0
    group_start = False        # just after "{": the next control word can name a destination

    def flush() -> None:
        if pending:
            out.append(pending.decode(codepage, errors="replace"))
            pending.clear()

    for m in _RTF_TOKEN.finditer(data):
        word, arg, hexbyte, symbol, brace, text = m.groups()
        if not (word or hexbyte or symbol or brace or text):
            continue           # a line break in the RTF source, not in the text
        if brace == b"{":
            flush()
            stack.append((skipping, uc))
            group_start = True
            continue
        if brace == b"}":
            flush()
            skipping, uc = stack.pop() if stack else (False, 1)
            group_start = False
            continue
        starts_group, group_start = group_start, False
        if skip_next and (text or hexbyte or symbol):
            # Skip the fallback characters after a \uN.
            if text:
                n = min(skip_next, len(text))
                skip_next -= n
                text = text[n:]
                if not text:
                    continue
            else:
                skip_next -= 1
                continue
        if symbol == b"*" and starts_group:
            skipping = True    # an ignorable destination: {\* ...}
            continue
        if skipping:
            continue           # (\bin data is only expected inside skipped groups, e.g. pictures)
        if word:
            if starts_group and word in _RTF_SKIP:
                skipping = True
                continue
            flush()
            if word == b"u" and arg is not None:
                code = int(arg)
                out.append(chr(code + 65536 if code < 0 else code))
                skip_next = uc
            elif word == b"uc" and arg is not None:
                uc = int(arg)
            elif word in _RTF_BREAKS:
                out.append(_RTF_BREAKS[word])
        elif hexbyte:
            pending.append(int(hexbyte, 16))
        elif symbol:
            flush()
            if symbol in (b"\\", b"{", b"}"):
                out.append(symbol.decode())
            elif symbol == b"~":
                out.append("\u00a0")
            elif symbol == b"_":
                out.append("-")    # non-breaking hyphen; \- (optional hyphen) is dropped
            elif symbol in (b"\n", b"\r"):
                out.append("\n")
        elif text:
            flush()
            out.append(text.decode(codepage, errors="replace"))
    flush()
    lines = "".join(out).replace("\u00a0", " ").split("\n")
    return "\n".join(line.strip() for line in lines if line.strip())
