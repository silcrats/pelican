"""
Writes the files the integration test's SMB share serves: one per text
extractor the SMB crawler uses, each containing a phrase the test then
looks for in the index. Run in the crawler image (it has python-docx).

  python make_smb_fixtures.py <dir>
"""

import gzip
import os
import sys

from docx import Document
from PIL import ExifTags, Image

EXPECTED = {
    "Finance/notes.txt": "Pelican plain text fixture",
    "Finance/report.docx": "Pelican Word fixture",
    "Finance/scan.pdf": "Pelican PDF fixture",
}
# Office files made with LibreOffice (they can't be generated here), stored
# gzipped in fixtures/.
OFFICE = {
    "Finance/legacy-word.doc": "Ελληνικά 中文",
    "Finance/legacy-powerpoint.ppt": "secret word walrus",   # from the speaker notes
    "Finance/slides.pptx": "secret word walrus",
    "Finance/slides.odp": "secret word walrus",
    "Finance/report.odt": "Ελληνικά 中文",
    "Finance/report.rtf": "Ελληνικά 中文",
}
# Emails with each combination of thread headers, for the email_thread_* fields:
# run.sh checks what's indexed for each. Thread-Index is 27 bytes of base64.
THREAD_INDEX = "Ac8AAAECAwQFBgcICQoLDA0ODxAREhMUFRYX"
EMAILS = {
    "Finance/thread-start.eml": "Message-ID: <root@test>\n",
    "Finance/thread-reply.eml": "Message-ID: <reply@test>\nIn-Reply-To: <root@test>\nReferences: <root@test>\n",
    "Finance/thread-reply-2.eml": "Message-ID: <reply2@test>\nIn-Reply-To: <reply@test>\nReferences: <root@test>\n <reply@test>\n",
    "Finance/thread-parent-only.eml": "Message-ID: <child@test>\nIn-Reply-To: <parent@test>\n",
    "Finance/thread-outlook.eml": f"Message-ID: <outlook@test>\nThread-Index: {THREAD_INDEX}\n",
    "Finance/thread-bad-headers.eml": "Message-ID: <bad@test>\nIn-Reply-To: not an id\nThread-Index: !!not base64!!\n",
}
FIXTURES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
# A photo with EXIF camera, date taken (with its UTC offset) and GPS, which
# the crawler reads with Pillow: run.sh checks the values it indexes.
PHOTO = "Finance/photo.jpg"


def write_photo(path: str) -> None:
    exif = Image.Exif()
    exif[0x010F], exif[0x0110] = "Canon", "EOS 5D"           # Make, Model
    sub = exif.get_ifd(ExifTags.IFD.Exif)
    sub[0x9003], sub[0x9011] = "2007:06:15 14:30:00", "+10:00"  # DateTimeOriginal, OffsetTimeOriginal
    gps = exif.get_ifd(ExifTags.IFD.GPSInfo)
    gps[1], gps[2] = "S", (33.0, 51.0, 54.5)                  # Sydney
    gps[3], gps[4] = "E", (151.0, 12.0, 35.6)
    Image.new("RGB", (64, 48), (120, 160, 200)).save(path, "JPEG", exif=exif)


def write_pdf(path: str, text: str) -> None:
    """A minimal one-page PDF with a line of text, xref offsets computed."""
    stream = f"BT /F1 18 Tf 72 720 Td ({text}) Tj ET".encode()
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length %d >>\nstream\n%s\nendstream" % (len(stream), stream),
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n%s\nendobj\n" % (i, body)
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    out += b"".join(b"%010d 00000 n \n" % o for o in offsets)
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objects) + 1, xref)
    with open(path, "wb") as f:
        f.write(out)


def main(root: str) -> None:
    os.makedirs(os.path.join(root, "Finance"), exist_ok=True)
    for rel, text in EXPECTED.items():
        path = os.path.join(root, rel)
        if rel.endswith(".txt"):
            with open(path, "w") as f:
                f.write(text + "\n")
        elif rel.endswith(".docx"):
            doc = Document()
            doc.add_paragraph(text)
            doc.save(path)
        else:
            write_pdf(path, text)
        os.chmod(path, 0o644)
    for rel in OFFICE:
        path = os.path.join(root, rel)
        with gzip.open(os.path.join(FIXTURES_DIR, os.path.basename(rel) + ".gz")) as src, open(path, "wb") as out:
            out.write(src.read())
        os.chmod(path, 0o644)
    for rel, headers in EMAILS.items():
        path = os.path.join(root, rel)
        with open(path, "w") as f:
            f.write(f"{headers}From: a@test\nTo: b@test\nSubject: Fixture thread\n\nPelican email fixture {os.path.basename(rel)}\n")
        os.chmod(path, 0o644)
    write_photo(os.path.join(root, PHOTO))
    os.chmod(os.path.join(root, PHOTO), 0o644)
    # Excluded by config/shares.yaml's exclude_extensions: must not be indexed.
    with open(os.path.join(root, "Finance", "skip.zip"), "wb") as f:
        f.write(b"PK\x05\x06" + b"\0" * 18)
    print(f"wrote {len(EXPECTED) + len(OFFICE) + len(EMAILS) + 2} files under {root}/Finance")


if __name__ == "__main__":
    main(sys.argv[1])
