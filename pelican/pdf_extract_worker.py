"""
Runs as a subprocess (see extract_text.py's _extract_pdf). Reads PDF bytes
from stdin, prints extracted text to stdout. Isolated in its own process so
a malformed/pathological PDF that hangs or loops during parsing can be
killed via subprocess timeout.

Uses pypdfium2 (Google's PDFium, via a permissively-licensed binding)
instead of pypdf -- faster on both text extraction and malformed-file
handling since PDFium is a mature C++ parser rather than a pure-Python one.
The subprocess+timeout wrapper stays regardless: even a fast C parser can
still spin on a genuinely pathological file, and a hard timeout is the
only real backstop for that.
"""
import sys

import pypdfium2 as pdfium


def main() -> None:
    data = sys.stdin.buffer.read()
    pdf = pdfium.PdfDocument(data)
    try:
        pages_text = []
        for page in pdf:
            textpage = page.get_textpage()
            try:
                pages_text.append(textpage.get_text_range())
            finally:
                textpage.close()
                page.close()
        text = "\n".join(pages_text)
    finally:
        pdf.close()

    sys.stdout.write(text)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"pdf_extract_worker error: {exc}", file=sys.stderr)
        sys.exit(1)