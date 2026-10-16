"""
Local text extraction, dispatched by file extension. No external API calls --
everything runs in-process so mailbox/document content never leaves this
container.
"""

import email
import io
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from email import policy
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser

from .extract_legacy_office import extract_doc, extract_ppt
from .extract_office_text import extract_odt, extract_pptx, extract_rtf

PDF_TIMEOUT_SECONDS = int(os.environ.get("PDF_TIMEOUT_SECONDS", "30"))


class _HTMLTextExtractor(HTMLParser):
    """Minimal HTML-to-text fallback for HTML-only email bodies."""
    def __init__(self):
        super().__init__()
        self._parts: list[str] = []

    def handle_data(self, data):
        self._parts.append(data)

    def text(self) -> str:
        return " ".join(self._parts)


def _split_addresses(value: str) -> list[str]:
    """Splits a raw 'To'/'Cc' header (comma-separated, possibly with
    display names) into a clean list of individual recipients. Also splits
    on ';', which is what extract-msg returns for Outlook .msg recipients."""
    if not value:
        return []
    return [addr.strip() for addr in value.replace(";", ",").split(",") if addr.strip()]


def _parse_email_date(value) -> str | None:
    """Best-effort parse of an email Date header (or extract-msg's .date,
    which may already be a datetime) into an ISO8601 UTC string. Real
    mailbox exports contain plenty of slightly malformed date headers, so
    this returns None on failure rather than raising -- the caller falls
    back to the file's real SMB modification time in that case, not a
    fake "now" placeholder."""
    if not value:
        return None
    try:
        dt = value if isinstance(value, datetime) else parsedate_to_datetime(str(value))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    except Exception:
        # Deliberately broad: parsedate_to_datetime has been seen raising
        # IndexError (not just the documented TypeError/ValueError) on some
        # malformed real-world Date headers -- and whatever it raises, the
        # contract here is "never raise, fall back to None" either way.
        return None


def _extract_eml(data: bytes) -> tuple[str, dict]:
    msg = email.message_from_bytes(data, policy=policy.default)
    subject = msg.get("Subject", "")
    sender = msg.get("From", "")
    to = msg.get("To", "")
    cc = msg.get("Cc", "")
    date = msg.get("Date", "")
    message_id = msg.get("Message-ID", "")

    body = ""
    attachments: list[str] = []
    image_metas: list[dict] = []
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if part.get_content_disposition() == "attachment":
                filename = part.get_filename()
                if filename:
                    attachments.append(filename)
                    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
                    if ext in _IMAGE_EXTENSIONS:
                        try:
                            m = _image_exif_metadata(part.get_content())
                            if m:
                                image_metas.append(m)
                        except Exception as exc:
                            print(f"  EXIF extraction failed for attachment '{filename}': {exc}")
                continue
            if content_type == "text/plain":
                body = part.get_content()
                break
            if content_type == "text/html" and not body:
                parser = _HTMLTextExtractor()
                parser.feed(part.get_content())
                body = parser.text()
    else:
        content_type = msg.get_content_type()
        if content_type == "text/html":
            parser = _HTMLTextExtractor()
            parser.feed(msg.get_content())
            body = parser.text()
        else:
            body = msg.get_content()

    text = f"Subject: {subject}\nFrom: {sender}\nTo: {to}\nCc: {cc}\nDate: {date}\n\n{body}"
    metadata = {
        "email_from": sender.strip(),
        "email_to": _split_addresses(to),
        "email_subject": subject.strip(),
    }
    if cc.strip():
        metadata["email_cc"] = _split_addresses(cc)
    email_date_iso = _parse_email_date(date)
    if email_date_iso:
        metadata["email_date"] = email_date_iso
    if attachments:
        metadata["email_attachments"] = attachments
    if message_id.strip():
        metadata["email_message_id"] = message_id.strip()
    metadata.update(_aggregate_image_attachments(image_metas))
    return text, metadata


def _dms_to_decimal(dms, ref: str) -> float | None:
    """Converts an EXIF GPS (degrees, minutes, seconds) tuple -- each itself
    a rational -- to signed decimal degrees, or None if the tuple is
    malformed (seen in the wild from some camera/phone firmware)."""
    try:
        degrees, minutes, seconds = (float(x) for x in dms)
    except (TypeError, ValueError, ZeroDivisionError):
        return None
    value = degrees + minutes / 60 + seconds / 3600
    return -value if ref in ("S", "W") else value


def _parse_exif_datetime(value: str, offset: str | None) -> str | None:
    """EXIF stores capture time as 'YYYY:MM:DD HH:MM:SS' (note the colons in
    the date part), with no timezone unless the camera also wrote a
    companion Offset* tag alongside it (e.g. OffsetTimeOriginal, '+10:00').
    Returns an ISO 8601 UTC string when an offset is available; otherwise
    the naive local time is reformatted as-is rather than guessed at --
    consistent with how a file's own mtime is used elsewhere in this module
    with no timezone conversion either."""
    try:
        dt = datetime.strptime(str(value).strip(), "%Y:%m:%d %H:%M:%S")
    except (ValueError, TypeError):
        return None
    if offset:
        try:
            sign = 1 if offset[0] == "+" else -1
            hours, minutes = offset[1:].split(":")
            dt -= sign * timedelta(hours=int(hours), minutes=int(minutes))
            return dt.replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        except (ValueError, IndexError):
            pass  # malformed offset -- fall through and treat as naive local time
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _image_exif_metadata(data: bytes) -> dict:
    """The actual EXIF/GPS extraction -- factored out of _extract_image so
    the identical logic also covers an image found as an *attachment* on an
    email (see _extract_eml/_extract_msg), not just a standalone image file.
    Camera make/model come straight from EXIF tags. GPS coordinates, if
    present, are resolved to a place name via reverse_geocoder, which ships
    its own bundled city dataset and resolves entirely offline -- no network
    call, no coordinates ever leave this container, same as every other
    extractor in this module (see the module docstring)."""
    from PIL import ExifTags, Image

    try:
        exif = Image.open(io.BytesIO(data)).getexif()
    except Exception:
        return {}
    if not exif:
        return {}

    tags = {ExifTags.TAGS.get(k, k): v for k, v in exif.items()}
    metadata: dict = {}
    make = str(tags.get("Make") or "").strip().rstrip("\x00")
    model = str(tags.get("Model") or "").strip().rstrip("\x00")
    if make:
        metadata["image_camera_make"] = make
    if model:
        metadata["image_camera_model"] = model

    # DateTimeOriginal/DateTimeDigitized (and their Offset* companions) live in
    # the separate "Exif" sub-IFD, not the top-level tags dict above -- only
    # the plain DateTime (file-saved time, not capture time) tag lives there,
    # kept as a last-resort fallback.
    exif_ifd = exif.get_ifd(ExifTags.IFD.Exif) or {}
    exif_tags = {ExifTags.TAGS.get(k, k): v for k, v in exif_ifd.items()}
    date_taken = exif_tags.get("DateTimeOriginal") or exif_tags.get("DateTimeDigitized") or tags.get("DateTime")
    offset = exif_tags.get("OffsetTimeOriginal") or exif_tags.get("OffsetTimeDigitized") or exif_tags.get("OffsetTime")
    if date_taken:
        iso = _parse_exif_datetime(date_taken, offset)
        if iso:
            metadata["image_date_taken"] = iso

    gps_ifd = exif.get_ifd(ExifTags.IFD.GPSInfo)
    if gps_ifd:
        gps = {ExifTags.GPSTAGS.get(k, k): v for k, v in gps_ifd.items()}
        lat = _dms_to_decimal(gps["GPSLatitude"], gps.get("GPSLatitudeRef", "N")) if gps.get("GPSLatitude") else None
        lon = _dms_to_decimal(gps["GPSLongitude"], gps.get("GPSLongitudeRef", "E")) if gps.get("GPSLongitude") else None
        if lat is not None and lon is not None:
            metadata["image_gps_lat"] = lat
            metadata["image_gps_lon"] = lon
            try:
                import reverse_geocoder as rg
                result = rg.search((lat, lon), mode=1)[0]
                place = ", ".join(p for p in (result.get("name"), result.get("admin1"), result.get("cc")) if p)
                if place:
                    metadata["image_location"] = place
            except Exception as exc:
                print(f"  reverse geocoding failed for ({lat}, {lon}): {exc}")

    return metadata


def _aggregate_image_attachments(image_metas: list[dict]) -> dict:
    """Combines each image attachment's own EXIF metadata (see
    _image_exif_metadata) into list-valued fields on the parent email.
    Unlike a standalone image file -- one photo, scalar fields -- a message
    can carry several photos, each with its own camera and/or location, so
    nothing here can be a single value without silently dropping the rest.

    Camera make/model are kept aligned by index to each other, among
    attachments that had either; GPS lat/lon/location are separately
    aligned by index to each other, among attachments that had GPS. The two
    families are independent since one attachment can have one without the
    other -- e.g. attachment 2 might be the only one with GPS, so
    image_location[0] is attachment 2's location, not attachment 1's.

    image_date_taken is deliberately not collected here: with several
    photos it has no single meaningful value, and nothing displays it
    directly anyway (only a standalone image's own document timestamp uses
    it -- see pelican/index.py build_doc)."""
    out: dict = {}
    camera_metas = [m for m in image_metas if m.get("image_camera_make") or m.get("image_camera_model")]
    if camera_metas:
        out["image_camera_make"] = [m.get("image_camera_make", "") for m in camera_metas]
        out["image_camera_model"] = [m.get("image_camera_model", "") for m in camera_metas]
    gps_metas = [m for m in image_metas if "image_gps_lat" in m]
    if gps_metas:
        out["image_gps_lat"] = [m["image_gps_lat"] for m in gps_metas]
        out["image_gps_lon"] = [m["image_gps_lon"] for m in gps_metas]
        out["image_location"] = [m.get("image_location", "") for m in gps_metas]
    return out


def _extract_image(data: bytes) -> tuple[str, dict]:
    """A standalone image file: EXIF-derived metadata only, there's no body
    text in a photo. See _image_exif_metadata for the extraction itself."""
    metadata = _image_exif_metadata(data)
    # Matches the search UI's "Camera - Location" title format -- make/model
    # stay space-joined as one unit, dashed against location if both exist.
    camera = " ".join(v for v in (metadata.get("image_camera_make"), metadata.get("image_camera_model")) if v)
    text = " - ".join(v for v in (camera, metadata.get("image_location")) if v)
    return text, metadata


def _extract_pdf(data: bytes, path: str) -> tuple[str, bool]:
    """Runs pypdf in a separate process (see pdf_extract_worker.py), not
    in-thread. Two reasons: pypdf is pure Python, so a slow/complex parse
    holds the GIL and can stall every other worker thread in the pool; and
    a genuinely malformed PDF can cause the parser to hang indefinitely,
    which a subprocess timeout can actually kill (a stuck Python thread
    cannot be force-terminated).

    Returns (text, timed_out) -- timed_out is tracked separately from
    other extraction failures (corrupt file, decompression limits, etc.)
    so the status page can report specifically how many files hit the
    PDF_TIMEOUT_SECONDS wall, since that's the one failure mode that's
    actually tunable (raise the timeout) rather than a broken source file."""
    worker_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pdf_extract_worker.py")
    try:
        result = subprocess.run(
            [sys.executable, worker_path],
            input=data,
            capture_output=True,
            timeout=PDF_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        print(f"  PDF extraction timed out after {PDF_TIMEOUT_SECONDS}s, skipping content: {path}")
        return "", True

    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="ignore").strip()
        print(f"  PDF extraction failed: {stderr} -- {path}")
        return "", False

    return result.stdout.decode("utf-8", errors="ignore"), False


def _extract_docx(data: bytes) -> str:
    from docx import Document
    doc = Document(io.BytesIO(data))
    parts = [p.text for p in doc.paragraphs]
    for table in doc.tables:
        for row in table.rows:
            parts.append(" | ".join(cell.text for cell in row.cells))
    return "\n".join(parts)


def _extract_msg(data: bytes) -> tuple[str, dict]:
    import extract_msg
    msg = extract_msg.Message(io.BytesIO(data))
    try:
        subject = msg.subject or ""
        sender = msg.sender or ""
        to = msg.to or ""
        cc = getattr(msg, "cc", None) or ""
        date = str(msg.date) if msg.date else ""
        body = msg.body or ""
        message_id = getattr(msg, "messageId", None) or ""
        text = f"Subject: {subject}\nFrom: {sender}\nTo: {to}\nCc: {cc}\nDate: {date}\n\n{body}"
        metadata = {
            "email_from": sender.strip(),
            "email_to": _split_addresses(to),
            "email_subject": subject.strip(),
        }
        if cc.strip():
            metadata["email_cc"] = _split_addresses(cc)
        email_date_iso = _parse_email_date(msg.date)
        if email_date_iso:
            metadata["email_date"] = email_date_iso
        if message_id.strip():
            metadata["email_message_id"] = message_id.strip()
        attachments = []
        image_metas: list[dict] = []
        for att in getattr(msg, "attachments", []) or []:
            filename = getattr(att, "longFilename", None) or getattr(att, "shortFilename", None)
            if filename:
                attachments.append(filename)
                ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
                if ext in _IMAGE_EXTENSIONS:
                    try:
                        m = _image_exif_metadata(att.data)
                        if m:
                            image_metas.append(m)
                    except Exception as exc:
                        print(f"  EXIF extraction failed for attachment '{filename}': {exc}")
        if attachments:
            metadata["email_attachments"] = attachments
        metadata.update(_aggregate_image_attachments(image_metas))
        return text, metadata
    finally:
        msg.close()


# Word and PowerPoint 97-2003; see extract_legacy_office.py.
_LEGACY_WORD_EXTENSIONS = {"doc", "dot"}
_LEGACY_POWERPOINT_EXTENSIONS = {"ppt", "pps", "pot"}

# When extraction for a type is added or improved, add an entry here: files
# of these types indexed before a crawler first runs this code are fetched
# and extracted again once, even though they haven't changed (see
# state.extraction_cutoffs). Never rename or remove an entry.
EXTRACTION_REVISIONS: dict[str, set[str]] = {
    "2026-10-office-formats": _LEGACY_WORD_EXTENSIONS | _LEGACY_POWERPOINT_EXTENSIONS | {"pptx", "odt", "rtf"},
}
_PLAIN_TEXT_EXTENSIONS = {"txt", "md", "csv", "log", "json", "xml", "html", "htm", "yaml", "yml", "ini", "conf"}
_IMAGE_EXTENSIONS = {"jpg", "jpeg", "tif", "tiff", "png", "webp"}


def extract_text(path: str, data: bytes) -> tuple[str, dict]:
    """Return (extracted_text, metadata) for a file. metadata is {} for
    every type except .eml/.msg (email_from/email_to/email_subject/...,
    plus the same image_* fields below from the first image attachment
    with usable EXIF, if any), images (image_camera_make/
    image_camera_model/image_gps_lat/image_gps_lon/image_location/
    image_date_taken, each only if present in the file's EXIF),
    and PDFs that time out, which set extraction_timeout. metadata's
    extraction_timeout key is transient -- read by the crawlers to
    update the status page, never written into the indexed document itself.
    Returns ("", {}) if the type isn't handled (the file still gets indexed
    by filename/metadata, just no body text). `path` should be the full
    SMB-relative path where possible (not just the bare filename), so
    failures/timeouts can be traced back to the real file on the share --
    extension detection works the same either way since it only looks at
    the trailing suffix."""
    filename = path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    try:
        if ext == "eml":
            return _extract_eml(data)
        if ext == "pdf":
            text, timed_out = _extract_pdf(data, path)
            return text, ({"extraction_timeout": True} if timed_out else {})
        if ext == "docx":
            return _extract_docx(data), {}
        if ext in _LEGACY_WORD_EXTENSIONS:
            if data[:2] == b"PK":   # really a .docx with an old extension
                return _extract_docx(data), {}
            if data.lstrip()[:5] == b"{\\rtf":   # Word can save RTF as .doc
                return extract_rtf(data), {}
            return extract_doc(data), {}
        if ext in _LEGACY_POWERPOINT_EXTENSIONS:
            return extract_ppt(data), {}
        if ext == "pptx":
            return extract_pptx(data), {}
        if ext == "odt":
            return extract_odt(data), {}
        if ext == "rtf":
            return extract_rtf(data), {}
        if ext == "msg":
            return _extract_msg(data)
        if ext in _IMAGE_EXTENSIONS:
            return _extract_image(data)
        if ext in _PLAIN_TEXT_EXTENSIONS:
            return data.decode("utf-8", errors="ignore"), {}
    except Exception as exc:
        print(f"  extraction failed for {path}: {exc}")
        return "", {}

    return "", {}  # unsupported type -- indexed by filename only