import json
import os
import tempfile
import threading
import time
import traceback
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

# IMPORTANT:
# Keep this file in the SAME FOLDER as your working sigpdf.py.
#
# This GUI imports and uses your existing working functions:
#   batch_sign
#   parse_box
#
# Updates in this version:
#   - Certificate picker button.
#   - Timestamp is generated from the computer date/time when signing starts.
#   - Reason and Location fields removed.
#   - Layout redesigned so the Log panel is always visible.
#   - Sample certificate PDF mapper for drawing the signature position and size.
#   - Print Certificates dialog: 2-up A5-on-A4 with cutting line, preview,
#     margin control, file selection, and printer selection.
#
# Run:
#   python sigpdf_gui_final.py

try:
    import sigpdf
    from sigpdf import (
        parse_box,
        find_certificate_by_thumbprint,
        WindowsStoreRSASigner,
        create_signature_appearance_image,
        sign_one_pdf,
    )
except Exception as import_error:
    sigpdf = None
    parse_box = None
    find_certificate_by_thumbprint = None
    WindowsStoreRSASigner = None
    create_signature_appearance_image = None
    sign_one_pdf = None
    IMPORT_ERROR = import_error
else:
    IMPORT_ERROR = None


def clean_thumbprint_for_display(value):
    return "".join(ch for ch in str(value) if ch.lower() in "0123456789abcdef").upper()


def get_settings_file_path():
    appdata = os.environ.get("APPDATA")
    if appdata:
        base_dir = Path(appdata)
    else:
        base_dir = Path.home() / ".config"

    return base_dir / "ca-batch-sign" / "settings.json"


def load_gui_settings():
    path = get_settings_file_path()

    if not path.exists():
        return {}, None

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {}, exc

    if not isinstance(data, dict):
        return {}, RuntimeError(f"Settings file is not a JSON object: {path}")

    return data, None


def save_gui_settings(data):
    path = get_settings_file_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def delete_gui_settings():
    path = get_settings_file_path()
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def get_computer_timestamp_text():
    """
    Returns date/time based on the computer's local clock.

    Format:
        Date: 2026-05-26
        10:55+08:00
    """
    now = datetime.now().astimezone()
    date_line = now.strftime("Date: %Y-%m-%d")
    time_line = now.strftime("%H:%M%z")

    # Convert +0800 to +08:00
    if len(time_line) >= 5:
        time_line = time_line[:-2] + ":" + time_line[-2:]

    return date_line, time_line




def format_local_datetime(dt=None):
    """
    Returns local date/time like:
        2026-05-26 21:01:03 +08:00
    """
    if dt is None:
        dt = datetime.now().astimezone()

    stamp = dt.strftime("%Y-%m-%d %H:%M:%S %z")

    if len(stamp) >= 5:
        stamp = stamp[:-2] + ":" + stamp[-2:]

    return stamp


def format_duration(seconds):
    return f"{seconds:.2f}s"


def format_thumbprint_colons(thumbprint):
    clean = clean_thumbprint_for_display(thumbprint)
    return ":".join(clean[i:i + 2] for i in range(0, len(clean), 2))


def parse_cert_subject(subject):
    """
    Extracts common fields from a Windows certificate subject string.
    Example subject parts:
        CN=Name, OU=Unit, O=Organization, C=PH
    """
    result = {}

    for part in str(subject).split(","):
        part = part.strip()

        if "=" not in part:
            continue

        key, value = part.split("=", 1)
        result[key.strip().upper()] = value.strip()

    return result


def get_signer_name_from_cert_subject(subject):
    fields = parse_cert_subject(subject)
    return fields.get("CN", "").strip()


def count_pdf_pages(pdf_path):
    """
    Counts pages for logging. Uses PyMuPDF if available.
    Returns None if the file cannot be read.
    """
    try:
        import fitz
        doc = fitz.open(str(pdf_path))
        try:
            return int(doc.page_count)
        finally:
            doc.close()
    except Exception:
        return None


def write_log_line(log_file_path, line):
    log_file_path.parent.mkdir(parents=True, exist_ok=True)

    with log_file_path.open("a", encoding="utf-8") as f:
        f.write(line + "\n")


def select_certificate_from_windows_store(store_location_name="CurrentUser"):
    """
    Opens the native Windows certificate selection dialog and returns:
        (thumbprint, subject)

    Requires pythonnet, already required by sigpdf.py.
    """
    import clr

    clr.AddReference("System")
    clr.AddReference("System.Security")
    clr.AddReference("System.Windows.Forms")

    from System.Security.Cryptography.X509Certificates import (
        X509Store,
        StoreName,
        StoreLocation,
        OpenFlags,
        X509Certificate2Collection,
        X509Certificate2UI,
        X509SelectionFlag,
    )

    if store_location_name.lower() == "currentuser":
        store_location = StoreLocation.CurrentUser
    elif store_location_name.lower() == "localmachine":
        store_location = StoreLocation.LocalMachine
    else:
        raise RuntimeError("Invalid store location. Use CurrentUser or LocalMachine.")

    store = X509Store(StoreName.My, store_location)
    store.Open(OpenFlags.ReadOnly)

    try:
        certs_with_private_key = X509Certificate2Collection()

        for cert in store.Certificates:
            try:
                if cert.HasPrivateKey:
                    certs_with_private_key.Add(cert)
            except Exception:
                pass

        if certs_with_private_key.Count == 0:
            raise RuntimeError(
                f"No certificates with private keys were found in {store_location_name}\\My."
            )

        selected = X509Certificate2UI.SelectFromCollection(
            certs_with_private_key,
            "Select Digital Signing Certificate",
            "Select the certificate to use for PDF digital signing.",
            X509SelectionFlag.SingleSelection,
        )

        if selected.Count == 0:
            return None, None

        cert = selected[0]
        thumbprint = clean_thumbprint_for_display(cert.Thumbprint)
        subject = str(cert.Subject)

        return thumbprint, subject

    finally:
        store.Close()





def detailed_batch_sign(settings, log_callback):
    """
    Signs PDFs one by one and writes a detailed batch log.

    This replaces the simple batch_sign() call so the GUI can show:
      - certificate information
      - each filename being signed
      - pages
      - success/failure
      - duration
      - summary
      - saved log file path
    """
    input_folder = settings["input_folder"]
    output_folder = settings["output_folder"]
    thumbprint = settings["thumbprint"]
    store_location = settings["store_location"]
    page_number = settings["page_number"]
    box = settings["box"]
    signature_image = settings["signature_image"]
    signature_text = settings["signature_text"]
    logo_image = settings.get("logo_image") or None
    field_prefix = settings["field_prefix"]

    run_start_dt = datetime.now().astimezone()
    run_start_time = time.perf_counter()

    logs_dir = Path.cwd() / "logs"
    log_file_path = logs_dir / f"signing_{run_start_dt.strftime('%Y%m%d_%H%M%S')}.log"

    def emit(line=""):
        log_callback(line + "\n")
        write_log_line(log_file_path, line)

    if not input_folder.exists():
        raise RuntimeError(f"Input folder does not exist: {input_folder}")

    if not input_folder.is_dir():
        raise RuntimeError(f"Input path is not a folder: {input_folder}")

    output_folder.mkdir(parents=True, exist_ok=True)

    pdf_files = sorted(input_folder.glob("*.pdf"))

    if not pdf_files:
        raise RuntimeError(f"No PDF files found in: {input_folder}")

    dotnet_cert = find_certificate_by_thumbprint(
        thumbprint=thumbprint,
        store_location=store_location,
    )

    signer = WindowsStoreRSASigner(dotnet_cert)

    subject_fields = parse_cert_subject(dotnet_cert.Subject)

    signer_name = settings.get("signer_name") or subject_fields.get("CN", "")
    organization = subject_fields.get("O", "")
    unit = subject_fields.get("OU", "")
    country = subject_fields.get("C", "")
    serial_no = str(dotnet_cert.SerialNumber)

    try:
        valid_until = dotnet_cert.NotAfter.ToString("yyyy-MM-dd")
    except Exception:
        valid_until = str(dotnet_cert.NotAfter)

    page_index = page_number - 1

    if page_index < 0:
        raise RuntimeError("Page number must be 1 or higher.")

    temp_dir = Path(tempfile.gettempdir())
    appearance_png_path = temp_dir / "pyhanko_visible_signature_appearance.png"

    create_signature_appearance_image(
        signature_image_path=signature_image,
        signature_text=signature_text,
        output_png_path=str(appearance_png_path),
        logo_image_path=logo_image,
    )

    total_files = len(pdf_files)
    successes = 0
    failures = 0
    total_pages = 0
    failed_files = []

    emit("================================================================")
    emit(f"  PDF BATCH SIGNING — {format_local_datetime(run_start_dt)}")
    emit("================================================================")
    emit("")
    emit("CERTIFICATE")
    emit(f"  Signer       : {signer_name}")
    emit(f"  Organization : {organization}")
    emit(f"  Unit         : {unit}")
    emit(f"  Country      : {country}")
    emit(f"  Serial No.   : {serial_no}")
    emit(f"  Thumbprint   : {format_thumbprint_colons(thumbprint)}")
    emit(f"  Valid until  : {valid_until}")
    emit("")
    emit("")
    emit("INPUT / OUTPUT")
    emit(f"  Source folder: {input_folder}")
    emit(f"  Output folder: {output_folder}")
    emit(f"  Files queued : {total_files}")
    emit("")
    emit("----------------------------------------------------------------")
    emit("  PROCESSING")
    emit("----------------------------------------------------------------")
    emit("  #   Time      File                              Pages  Status   Duration")
    emit("  ---  --------  --------------------------------  -----  -------  --------")

    for index, pdf_path in enumerate(pdf_files, start=1):
        file_start_dt = datetime.now().astimezone()
        file_start_time = time.perf_counter()
        file_time = file_start_dt.strftime("%H:%M:%S")
        pages = count_pdf_pages(pdf_path)
        pages_display = str(pages) if pages is not None else "—"

        output_pdf = output_folder / f"{pdf_path.stem}_signed.pdf"
        field_name = f"{field_prefix}_{index}"

        try:
            sign_one_pdf(
                input_pdf=pdf_path,
                output_pdf=output_pdf,
                signer=signer,
                page_index=page_index,
                box=box,
                field_name=field_name,
                appearance_png_path=str(appearance_png_path),
                reason=None,
                location=None,
            )

            duration = time.perf_counter() - file_start_time
            successes += 1

            if pages is not None:
                total_pages += pages

            emit(
                f"  {index}/{total_files:<2}  {file_time}  "
                f"{pdf_path.name[:32]:<32}  {pages_display:>5}  "
                f"✓ OK     {format_duration(duration):>8}"
            )

        except Exception as e:
            duration = time.perf_counter() - file_start_time
            failures += 1

            error_type = type(e).__name__
            error_message = str(e)
            failed_files.append((pdf_path.name, error_type, error_message))

            emit(
                f"  {index}/{total_files:<2}  {file_time}  "
                f"{pdf_path.name[:32]:<32}  {pages_display:>5}  "
                f"✗ FAIL   {format_duration(duration):>8}"
            )
            emit(f"       └─ Error: {error_type} — {error_message}")

    elapsed = time.perf_counter() - run_start_time
    avg_per_file = elapsed / total_files if total_files else 0

    success_pct = (successes / total_files) * 100 if total_files else 0
    failure_pct = (failures / total_files) * 100 if total_files else 0

    emit("")
    emit("----------------------------------------------------------------")
    emit("  SUMMARY")
    emit("----------------------------------------------------------------")
    emit(f"  Total files  : {total_files}")
    emit(f"  Succeeded    : {successes}  ({success_pct:.1f}%)")
    emit(f"  Failed       : {failures}  ({failure_pct:.1f}%)")
    emit(f"  Total pages  : {total_pages}")
    emit(f"  Elapsed time : {format_duration(elapsed)}")
    emit(f"  Avg per file : {format_duration(avg_per_file)}")
    emit("")

    if failed_files:
        emit("  Failed files:")

        for filename, error_type, error_message in failed_files:
            emit(f"    • {filename} — {error_type}: {error_message}")

        emit("")

    emit(f"  Output written to: {output_folder}")
    emit(f"  Log saved to     : {log_file_path}")
    emit("")
    emit("================================================================")
    emit(f"  Finished at {format_local_datetime()}")
    emit("================================================================")

    return {
        "total_files": total_files,
        "successes": successes,
        "failures": failures,
        "total_pages": total_pages,
        "elapsed": elapsed,
        "log_file_path": log_file_path,
    }


# =============================================================================
#   PRINTING — 2-up A5-on-A4 layout helpers
# =============================================================================
# A4 portrait dimensions in PDF points (1 pt = 1/72 inch):
#   Width  =  595 pt  (210 mm)
#   Height =  842 pt  (297 mm)
A4_WIDTH_PT  = 595.276
A4_HEIGHT_PT = 841.890

# Conversion factor: millimeters to PDF points.
MM_TO_PT = 72.0 / 25.4


def mm_to_pt(mm_value):
    return float(mm_value) * MM_TO_PT


def list_system_printers():
    """
    Return a list of (printer_name, is_default) tuples for printers installed
    on the current system. On non-Windows or when win32print is unavailable,
    returns an empty list.
    """
    try:
        import win32print
    except Exception:
        return []

    try:
        default_name = win32print.GetDefaultPrinter()
    except Exception:
        default_name = ""

    try:
        flags = win32print.PRINTER_ENUM_LOCAL | win32print.PRINTER_ENUM_CONNECTIONS
        printers = win32print.EnumPrinters(flags, None, 2)
    except Exception:
        return []

    results = []
    for printer_info in printers:
        # Each entry is a dict in level 2.
        name = printer_info.get("pPrinterName", "")
        if not name:
            continue
        results.append((name, name == default_name))

    return results


def build_a4_2up_pdf(
    input_pdf_paths,
    output_pdf_path,
    margin_top_mm=0.0,
    margin_bottom_mm=0.0,
    margin_left_mm=0.0,
    margin_right_mm=0.0,
    inter_gap_mm=6.0,
    draw_cut_line=True,
    render_dpi=300,
):
    """
    Produce a new PDF where each output A4 portrait page contains TWO source
    A5 certificates stacked vertically (one on the top half, one on the bottom
    half), with a dashed cutting line at the vertical midpoint of the A4 page.

    The two slots on each A4 page are filled in order from the supplied list of
    input PDFs. The FIRST PAGE of each input PDF is used as the certificate.
    If there is an odd number of inputs, the last A4 page contains only one
    certificate on the top half and an empty bottom half.

    Margins are measured from the edges of the A4 paper (all four sides). The
    inter_gap_mm is the small space between the bottom of the top certificate
    and the cutting line (and likewise above the bottom certificate), so the
    cut doesn't slice into either page.

    Source pages are rendered with annotations included before placement. This
    preserves visible digital signature widgets, which show_pdf_page() can omit.
    """
    import fitz  # PyMuPDF

    if not input_pdf_paths:
        raise RuntimeError("No PDF files were selected for printing.")

    margin_top    = mm_to_pt(margin_top_mm)
    margin_bottom = mm_to_pt(margin_bottom_mm)
    margin_left   = mm_to_pt(margin_left_mm)
    margin_right  = mm_to_pt(margin_right_mm)
    inter_gap     = mm_to_pt(inter_gap_mm)

    # Each "slot" on the A4 page is bounded by the page margins on left/right,
    # the page top/bottom margin on the outer edge, and the page midline (with
    # an inter_gap buffer) on the inner edge.
    usable_width = A4_WIDTH_PT - margin_left - margin_right
    midline_y    = A4_HEIGHT_PT / 2.0

    if usable_width <= 10:
        raise RuntimeError("Left + right margins are too large for A4.")

    top_slot = fitz.Rect(
        margin_left,
        margin_top,
        margin_left + usable_width,
        midline_y - inter_gap,
    )
    bottom_slot = fitz.Rect(
        margin_left,
        midline_y + inter_gap,
        margin_left + usable_width,
        A4_HEIGHT_PT - margin_bottom,
    )

    if top_slot.height <= 10 or bottom_slot.height <= 10:
        raise RuntimeError("Top/bottom margins are too large for A4 2-up layout.")

    out_doc = fitz.open()

    def place_cert_in_slot(out_page, slot_rect, src_pdf_path):
        """
        Place the first page of src_pdf_path inside slot_rect on out_page.

        If the source page orientation does not match the slot orientation
        (portrait vs. landscape), rotate the source by 90 degrees so its
        longer side aligns with the slot's longer side. This makes A5
        certificates fill the available half-A4 space efficiently regardless
        of whether the source is A5 portrait or A5 landscape.
        """
        with fitz.open(str(src_pdf_path)) as src:
            if src.page_count < 1:
                return

            src_page = src[0]
            src_w = float(src_page.rect.width)
            src_h = float(src_page.rect.height)

            slot_landscape = slot_rect.width >= slot_rect.height
            src_landscape  = src_w >= src_h

            rotation = 0 if (slot_landscape == src_landscape) else 90

            pix = src_page.get_pixmap(
                dpi=int(render_dpi),
                alpha=False,
                annots=True,
            )

            out_page.insert_image(
                slot_rect,
                pixmap=pix,
                keep_proportion=True,
                rotate=rotation,
            )

    # Group input PDFs into pairs (top, bottom). An odd final input pairs with None.
    paired = []
    i = 0
    while i < len(input_pdf_paths):
        first  = input_pdf_paths[i]
        second = input_pdf_paths[i + 1] if i + 1 < len(input_pdf_paths) else None
        paired.append((first, second))
        i += 2

    for top_path, bottom_path in paired:
        out_page = out_doc.new_page(
            width=A4_WIDTH_PT, height=A4_HEIGHT_PT
        )

        # Place the top certificate.
        place_cert_in_slot(out_page, top_slot, top_path)

        # Place the bottom certificate (if any).
        if bottom_path is not None:
            place_cert_in_slot(out_page, bottom_slot, bottom_path)

        if draw_cut_line:
            # Draw a dashed cutting line spanning the full A4 width at midline.
            cut_line_start = fitz.Point(0, midline_y)
            cut_line_end   = fitz.Point(A4_WIDTH_PT, midline_y)
            out_page.draw_line(
                cut_line_start,
                cut_line_end,
                color=(0.45, 0.45, 0.45),
                width=0.6,
                dashes="[4 3] 0",
            )

            # Small scissor hint glyph at both ends of the line.
            for x_pos in (margin_left * 0.4, A4_WIDTH_PT - margin_left * 0.4):
                out_page.insert_text(
                    fitz.Point(x_pos - 4, midline_y + 3),
                    "\u2702",       # scissors
                    fontsize=8,
                    color=(0.45, 0.45, 0.45),
                )

    out_doc.save(str(output_pdf_path))
    out_doc.close()


def render_pdf_page_to_image(pdf_path, page_index=0, dpi=110):
    """
    Render a single page of a PDF to a PIL Image. Used by the print preview.
    """
    import fitz
    from PIL import Image

    doc = fitz.open(str(pdf_path))
    try:
        if page_index < 0 or page_index >= doc.page_count:
            raise RuntimeError(
                f"Page {page_index + 1} is out of range for {pdf_path.name}."
            )
        page = doc[page_index]
        zoom = dpi / 72.0
        matrix = fitz.Matrix(zoom, zoom)
        pix = page.get_pixmap(matrix=matrix, alpha=False)
        image = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
        return image
    finally:
        doc.close()


def send_pdf_to_printer(pdf_path, printer_name=None):
    """
    Send a PDF file to a Windows printer using the 'printto' shell verb. This
    relies on the system's registered PDF handler (Edge, Adobe Reader, etc.)
    to perform the actual rendering.

    If printer_name is None or empty, prints to the default printer using the
    'print' verb instead.

    Returns nothing; raises RuntimeError on failure.
    """
    import sys

    if sys.platform != "win32":
        raise RuntimeError(
            "Direct printing is supported on Windows only. "
            "Use the 'Open Generated PDF' button to print manually on this system."
        )

    try:
        import win32api
    except Exception as e:
        raise RuntimeError(
            "win32api is required for printing. Install with:\n"
            "    python -m pip install pywin32\n\n"
            f"Original error: {e}"
        )

    pdf_path = str(pdf_path)

    try:
        if printer_name:
            # The "printto" verb takes the printer name as the parameters arg.
            win32api.ShellExecute(
                0,
                "printto",
                pdf_path,
                f'"{printer_name}"',
                ".",
                0,
            )
        else:
            win32api.ShellExecute(
                0,
                "print",
                pdf_path,
                None,
                ".",
                0,
            )
    except Exception as e:
        raise RuntimeError(f"Failed to send PDF to printer: {e}")


class PrintLayoutDialog(tk.Toplevel):
    """
    A dialog that lets the user:
      * pick a source folder containing signed Certificate of Appearance PDFs
        (which are A5-sized),
      * choose which files to include in the print job,
      * set top/bottom/left/right A4 margins,
      * pick a printer,
      * preview the resulting A4 2-up layout (with a dashed cutting line in
        the middle of each A4 page),
      * print the layout.

    The generated layout is saved to a temp file. The user can also open the
    generated PDF in their default viewer to print manually.
    """

    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent

        self.title("Print Certificates — A4 (2 per page)")
        self.configure(background=COLOR_BG)
        self.transient(parent)
        self.grab_set()

        # Open at 80% of screen, centered.
        screen_w = self.winfo_screenwidth()
        screen_h = self.winfo_screenheight()
        win_w = min(int(screen_w * 0.80), 1400)
        win_h = int(screen_h * 0.85)
        win_w = max(win_w, 950)
        win_h = max(win_h, 620)
        pos_x = max((screen_w - win_w) // 2, 0)
        pos_y = max((screen_h - win_h) // 2, 0)
        self.geometry(f"{win_w}x{win_h}+{pos_x}+{pos_y}")
        self.minsize(900, 600)

        # ---- State -----------------------------------------------------------
        self.source_folder = tk.StringVar()
        self.printer_name  = tk.StringVar()
        self.margin_top    = tk.StringVar(value="0")
        self.margin_bottom = tk.StringVar(value="0")
        self.margin_left   = tk.StringVar(value="0")
        self.margin_right  = tk.StringVar(value="0")

        self.available_pdfs = []          # list of Path objects in source folder
        self.preview_doc = None           # fitz.Document for the current preview
        self.preview_page_index = 0
        self.preview_total_pages = 0
        self.preview_photo = None         # keep a reference so it isn't GC'd
        self.last_generated_pdf = None    # Path of the most recent generated layout

        self._build_ui()
        self._populate_printers()

    # -------------------------------------------------------------------------
    #  UI construction
    # -------------------------------------------------------------------------
    def _build_ui(self):
        outer = ttk.Frame(self, padding=12)
        outer.pack(fill="both", expand=True)

        outer.columnconfigure(0, weight=2, minsize=380)
        outer.columnconfigure(1, weight=3, minsize=460)
        outer.rowconfigure(0, weight=1)

        # --- LEFT: controls --------------------------------------------------
        left = ttk.Frame(outer)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        left.columnconfigure(0, weight=1)
        left.rowconfigure(1, weight=1)

        # Source folder card
        src_card = ttk.LabelFrame(
            left, text="  Source Folder  ", padding=10, style="Card.TLabelframe"
        )
        src_card.grid(row=0, column=0, sticky="ew")
        src_card.columnconfigure(0, weight=1)

        ttk.Entry(
            src_card,
            textvariable=self.source_folder,
            foreground=COLOR_TEXT,
        ).grid(row=0, column=0, sticky="ew", padx=(0, 8))
        ttk.Button(
            src_card,
            text="Browse Folder",
            command=self._choose_source_folder,
        ).grid(row=0, column=1, sticky="e")

        # File list card
        files_card = ttk.LabelFrame(
            left, text="  Files to Print  ", padding=10, style="Card.TLabelframe"
        )
        files_card.grid(row=1, column=0, sticky="nsew", pady=(8, 0))
        files_card.columnconfigure(0, weight=1)
        files_card.rowconfigure(0, weight=1)

        # Scrollable area that holds one Checkbutton per PDF file.
        # We use a Canvas + inner Frame so the checkbuttons can scroll
        # vertically when there are many files.
        listbox_wrap = ttk.Frame(files_card, style="Card.TFrame")
        listbox_wrap.grid(row=0, column=0, sticky="nsew")
        listbox_wrap.columnconfigure(0, weight=1)
        listbox_wrap.rowconfigure(0, weight=1)

        self.file_canvas = tk.Canvas(
            listbox_wrap,
            background=COLOR_SURFACE,
            highlightthickness=1,
            highlightbackground=COLOR_BORDER,
            borderwidth=0,
        )
        self.file_canvas.grid(row=0, column=0, sticky="nsew")

        list_scroll = ttk.Scrollbar(
            listbox_wrap, orient="vertical", command=self.file_canvas.yview
        )
        list_scroll.grid(row=0, column=1, sticky="ns")
        self.file_canvas.configure(yscrollcommand=list_scroll.set)

        # Inner frame that actually holds the checkbuttons.
        self.file_check_frame = tk.Frame(
            self.file_canvas,
            background=COLOR_SURFACE,
        )
        self._file_check_window = self.file_canvas.create_window(
            (0, 0),
            window=self.file_check_frame,
            anchor="nw",
        )

        # Keep the inner frame's width matched to the canvas width so
        # checkbutton rows fill horizontally and wrap nicely.
        def _on_canvas_configure(event):
            self.file_canvas.itemconfigure(self._file_check_window, width=event.width)

        self.file_canvas.bind("<Configure>", _on_canvas_configure)

        # Update scrollregion whenever the inner frame's size changes.
        def _on_inner_configure(event):
            self.file_canvas.configure(scrollregion=self.file_canvas.bbox("all"))

        self.file_check_frame.bind("<Configure>", _on_inner_configure)

        # Mouse-wheel scrolling support (Windows-style delta).
        def _on_mousewheel(event):
            self.file_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        self.file_canvas.bind(
            "<Enter>",
            lambda e: self.file_canvas.bind_all("<MouseWheel>", _on_mousewheel),
        )
        self.file_canvas.bind(
            "<Leave>",
            lambda e: self.file_canvas.unbind_all("<MouseWheel>"),
        )

        # Per-file state: list of BooleanVar, parallel to self.available_pdfs.
        self.file_check_vars = []

        list_btns = ttk.Frame(files_card, style="Card.TFrame")
        list_btns.grid(row=1, column=0, sticky="ew", pady=(8, 0))
        list_btns.columnconfigure(3, weight=1)

        ttk.Button(list_btns, text="Select All",
                   command=self._select_all_files).grid(row=0, column=0)
        ttk.Button(list_btns, text="Select None",
                   command=self._select_no_files).grid(row=0, column=1, padx=(6, 0))
        ttk.Label(
            list_btns,
            textvariable=self._selection_summary_var(),
            background=COLOR_SURFACE,
            foreground=COLOR_TEXT_MUTED,
            font=(FONT_FAMILY, 9),
        ).grid(row=0, column=3, sticky="e")

        # Margins card
        margins_card = ttk.LabelFrame(
            left, text="  A4 Margins (mm)  ", padding=10, style="Card.TLabelframe"
        )
        margins_card.grid(row=2, column=0, sticky="ew", pady=(8, 0))
        for c in (1, 3):
            margins_card.columnconfigure(c, weight=1)

        ttk.Label(margins_card, text="Top", style="FieldLabel.TLabel").grid(
            row=0, column=0, sticky="w", pady=4
        )
        ttk.Entry(
            margins_card,
            textvariable=self.margin_top,
            width=8,
            foreground=COLOR_TEXT,
        ).grid(row=0, column=1, sticky="w", pady=4, padx=(6, 12))

        ttk.Label(margins_card, text="Bottom", style="FieldLabel.TLabel").grid(
            row=0, column=2, sticky="w", pady=4
        )
        ttk.Entry(
            margins_card,
            textvariable=self.margin_bottom,
            width=8,
            foreground=COLOR_TEXT,
        ).grid(row=0, column=3, sticky="w", pady=4, padx=(6, 0))

        ttk.Label(margins_card, text="Left", style="FieldLabel.TLabel").grid(
            row=1, column=0, sticky="w", pady=4
        )
        ttk.Entry(
            margins_card,
            textvariable=self.margin_left,
            width=8,
            foreground=COLOR_TEXT,
        ).grid(row=1, column=1, sticky="w", pady=4, padx=(6, 12))

        ttk.Label(margins_card, text="Right", style="FieldLabel.TLabel").grid(
            row=1, column=2, sticky="w", pady=4
        )
        ttk.Entry(
            margins_card,
            textvariable=self.margin_right,
            width=8,
            foreground=COLOR_TEXT,
        ).grid(row=1, column=3, sticky="w", pady=4, padx=(6, 0))

        # Printer card
        printer_card = ttk.LabelFrame(
            left, text="  Printer  ", padding=10, style="Card.TLabelframe"
        )
        printer_card.grid(row=3, column=0, sticky="ew", pady=(8, 0))
        printer_card.columnconfigure(0, weight=1)

        self.printer_combo = ttk.Combobox(
            printer_card,
            textvariable=self.printer_name,
            state="readonly",
            foreground=COLOR_TEXT,
        )
        self.printer_combo.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        ttk.Button(
            printer_card,
            text="Refresh",
            command=self._populate_printers,
        ).grid(row=0, column=1, sticky="e")

        # Action buttons
        actions = ttk.Frame(left)
        actions.grid(row=4, column=0, sticky="ew", pady=(10, 0))
        actions.columnconfigure(0, weight=1)
        actions.columnconfigure(1, weight=1)
        actions.columnconfigure(2, weight=1)

        ttk.Button(
            actions,
            text="Update Preview",
            command=self._generate_preview,
        ).grid(row=0, column=0, sticky="ew", padx=(0, 4))
        ttk.Button(
            actions,
            text="Open Generated PDF",
            command=self._open_generated_pdf,
        ).grid(row=0, column=1, sticky="ew", padx=4)
        ttk.Button(
            actions,
            text="Print",
            command=self._send_to_printer,
            style="Accent.TButton",
        ).grid(row=0, column=2, sticky="ew", padx=(4, 0))

        ttk.Button(
            left,
            text="Close",
            command=self._on_close,
        ).grid(row=5, column=0, sticky="e", pady=(8, 0))

        # --- RIGHT: preview ---------------------------------------------------
        right = ttk.LabelFrame(
            outer, text="  Preview (A4 portrait, 2 certificates per page)  ",
            padding=10, style="Card.TLabelframe",
        )
        right.grid(row=0, column=1, sticky="nsew")
        right.columnconfigure(0, weight=1)
        right.rowconfigure(0, weight=1)

        preview_wrap = ttk.Frame(right, style="Card.TFrame")
        preview_wrap.grid(row=0, column=0, sticky="nsew")
        preview_wrap.columnconfigure(0, weight=1)
        preview_wrap.rowconfigure(0, weight=1)

        self.preview_canvas = tk.Canvas(
            preview_wrap,
            background="#dde3ea",
            highlightthickness=1,
            highlightbackground=COLOR_BORDER,
        )
        self.preview_canvas.grid(row=0, column=0, sticky="nsew")

        pv = ttk.Scrollbar(preview_wrap, orient="vertical",
                           command=self.preview_canvas.yview)
        pv.grid(row=0, column=1, sticky="ns")
        ph = ttk.Scrollbar(preview_wrap, orient="horizontal",
                           command=self.preview_canvas.xview)
        ph.grid(row=1, column=0, sticky="ew")
        self.preview_canvas.configure(yscrollcommand=pv.set, xscrollcommand=ph.set)

        # Page navigation row
        nav = ttk.Frame(right, style="Card.TFrame")
        nav.grid(row=1, column=0, sticky="ew", pady=(8, 0))
        nav.columnconfigure(2, weight=1)

        self.prev_btn = ttk.Button(nav, text="◀ Prev",
                                   command=self._preview_prev, state="disabled")
        self.prev_btn.grid(row=0, column=0)

        self.next_btn = ttk.Button(nav, text="Next ▶",
                                   command=self._preview_next, state="disabled")
        self.next_btn.grid(row=0, column=1, padx=(6, 0))

        self.preview_status = tk.StringVar(value="No preview yet.")
        ttk.Label(
            nav,
            textvariable=self.preview_status,
            background=COLOR_SURFACE,
            foreground=COLOR_TEXT_MUTED,
            font=(FONT_FAMILY, 9),
        ).grid(row=0, column=2, sticky="e", padx=(8, 0))

        # Show a placeholder message until preview is generated.
        self._draw_preview_placeholder()

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _selection_summary_var(self):
        if not hasattr(self, "_selection_summary"):
            self._selection_summary = tk.StringVar(value="0 selected")
        return self._selection_summary

    # -------------------------------------------------------------------------
    #  Source folder & file list
    # -------------------------------------------------------------------------
    def _choose_source_folder(self):
        folder = filedialog.askdirectory(
            title="Select folder containing Certificate of Appearance PDFs",
            parent=self,
        )
        if folder:
            self.source_folder.set(folder)
            self._load_files_from_folder(Path(folder))

    def _load_files_from_folder(self, folder):
        # Clear any existing checkbutton rows.
        for child in self.file_check_frame.winfo_children():
            child.destroy()

        self.file_check_vars = []
        self.available_pdfs = []

        if not folder.exists() or not folder.is_dir():
            self._refresh_selection_summary()
            return

        pdfs = sorted(folder.glob("*.pdf"))
        for pdf in pdfs:
            # Select all by default — most common workflow is
            # "print everything signed".
            var = tk.BooleanVar(value=True)
            self.file_check_vars.append(var)
            self.available_pdfs.append(pdf)

            cb = tk.Checkbutton(
                self.file_check_frame,
                text=pdf.name,
                variable=var,
                onvalue=True,
                offvalue=False,
                command=self._refresh_selection_summary,
                background=COLOR_SURFACE,
                foreground=COLOR_TEXT,
                activebackground=COLOR_SURFACE,
                activeforeground=COLOR_TEXT,
                selectcolor=COLOR_SURFACE,
                font=(FONT_FAMILY, 10),
                anchor="w",
                padx=6,
                pady=2,
                borderwidth=0,
                highlightthickness=0,
            )
            cb.pack(fill="x", anchor="w")

        # Reset scroll position to top.
        self.file_canvas.yview_moveto(0)

        self._refresh_selection_summary()

    def _select_all_files(self):
        for var in self.file_check_vars:
            var.set(True)
        self._refresh_selection_summary()

    def _select_no_files(self):
        for var in self.file_check_vars:
            var.set(False)
        self._refresh_selection_summary()

    def _refresh_selection_summary(self):
        n_sel = sum(1 for v in self.file_check_vars if v.get())
        total = len(self.available_pdfs)
        a4_pages = (n_sel + 1) // 2
        self._selection_summary_var().set(
            f"{n_sel} of {total} selected → {a4_pages} A4 page(s)"
        )

    def _get_selected_paths(self):
        return [
            pdf
            for pdf, var in zip(self.available_pdfs, self.file_check_vars)
            if var.get()
        ]

    # -------------------------------------------------------------------------
    #  Printer enumeration
    # -------------------------------------------------------------------------
    def _populate_printers(self):
        printers = list_system_printers()

        if not printers:
            # Could be non-Windows or pywin32 missing.
            self.printer_combo["values"] = ["(no printers available)"]
            self.printer_combo.current(0)
            self.printer_combo.configure(state="disabled")
            self.printer_name.set("")
            return

        names = [p[0] for p in printers]
        self.printer_combo["values"] = names
        self.printer_combo.configure(state="readonly")

        # Pick the default printer if there is one.
        default_index = 0
        for i, (_, is_default) in enumerate(printers):
            if is_default:
                default_index = i
                break

        self.printer_combo.current(default_index)

    # -------------------------------------------------------------------------
    #  Margin parsing
    # -------------------------------------------------------------------------
    def _parse_margins(self):
        def parse(value, name):
            try:
                v = float(value)
            except (TypeError, ValueError):
                raise RuntimeError(f"{name} margin must be a number (in mm).")
            if v < 0 or v > 50:
                raise RuntimeError(
                    f"{name} margin must be between 0 and 50 mm."
                )
            return v

        return (
            parse(self.margin_top.get(), "Top"),
            parse(self.margin_bottom.get(), "Bottom"),
            parse(self.margin_left.get(), "Left"),
            parse(self.margin_right.get(), "Right"),
        )

    # -------------------------------------------------------------------------
    #  Preview generation
    # -------------------------------------------------------------------------
    def _generate_preview(self):
        try:
            selected = self._get_selected_paths()
            if not selected:
                raise RuntimeError("Please select at least one PDF file.")

            top, bottom, left, right = self._parse_margins()

            tmp_dir = Path(tempfile.gettempdir())
            out_pdf = tmp_dir / "dilg_certificate_print_layout.pdf"

            build_a4_2up_pdf(
                input_pdf_paths=selected,
                output_pdf_path=out_pdf,
                margin_top_mm=top,
                margin_bottom_mm=bottom,
                margin_left_mm=left,
                margin_right_mm=right,
            )
            self.last_generated_pdf = out_pdf

            # Open the freshly generated PDF for paging through the preview.
            try:
                import fitz
            except Exception as e:
                raise RuntimeError(
                    "PyMuPDF is required for preview rendering.\n"
                    "Install with:  python -m pip install pymupdf pillow\n\n"
                    f"Original error: {e}"
                )

            if self.preview_doc is not None:
                try:
                    self.preview_doc.close()
                except Exception:
                    pass
                self.preview_doc = None

            self.preview_doc = fitz.open(str(out_pdf))
            self.preview_total_pages = self.preview_doc.page_count
            self.preview_page_index = 0

            self._render_current_preview_page()
            self._update_nav_buttons()

        except Exception as e:
            messagebox.showerror("Preview failed", str(e), parent=self)

    def _render_current_preview_page(self):
        if self.preview_doc is None or self.preview_total_pages == 0:
            self._draw_preview_placeholder()
            return

        try:
            from PIL import Image, ImageTk
            import fitz
        except Exception as e:
            messagebox.showerror(
                "Missing packages",
                "Preview needs PyMuPDF and Pillow.\n"
                "Install with:  python -m pip install pymupdf pillow\n\n"
                f"Original error: {e}",
                parent=self,
            )
            return

        page = self.preview_doc[self.preview_page_index]

        # Size the preview to fit comfortably inside the canvas.
        canvas_w = self.preview_canvas.winfo_width()
        canvas_h = self.preview_canvas.winfo_height()
        if canvas_w < 50 or canvas_h < 50:
            # Canvas not yet realized — fall back to a reasonable default.
            canvas_w, canvas_h = 520, 720

        pdf_w = float(page.rect.width)
        pdf_h = float(page.rect.height)
        zoom_w = (canvas_w - 30) / pdf_w
        zoom_h = (canvas_h - 30) / pdf_h
        zoom = max(0.2, min(zoom_w, zoom_h))

        matrix = fitz.Matrix(zoom, zoom)
        pix = page.get_pixmap(matrix=matrix, alpha=False)

        image = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
        self.preview_photo = ImageTk.PhotoImage(image)

        self.preview_canvas.delete("all")

        # Add a subtle shadow rectangle behind the page for that "paper" feel.
        shadow_offset = 6
        self.preview_canvas.create_rectangle(
            15 + shadow_offset,
            15 + shadow_offset,
            15 + shadow_offset + pix.width,
            15 + shadow_offset + pix.height,
            fill="#c5cdd4",
            outline="",
        )
        self.preview_canvas.create_image(15, 15, image=self.preview_photo, anchor="nw")
        self.preview_canvas.configure(
            scrollregion=(0, 0, pix.width + 40, pix.height + 40)
        )

        self.preview_status.set(
            f"Page {self.preview_page_index + 1} of {self.preview_total_pages}"
        )

    def _draw_preview_placeholder(self):
        self.preview_canvas.delete("all")
        self.preview_canvas.create_text(
            260, 200,
            text="Choose a folder, select files, then click\n"
                 "“Update Preview” to render the A4 layout here.",
            fill=COLOR_TEXT_MUTED,
            font=(FONT_FAMILY, 11),
            justify="center",
        )
        self.preview_canvas.configure(scrollregion=(0, 0, 0, 0))

    def _update_nav_buttons(self):
        if self.preview_total_pages <= 1:
            self.prev_btn.configure(state="disabled")
            self.next_btn.configure(state="disabled")
        else:
            self.prev_btn.configure(
                state="normal" if self.preview_page_index > 0 else "disabled"
            )
            self.next_btn.configure(
                state="normal"
                if self.preview_page_index < self.preview_total_pages - 1
                else "disabled"
            )

    def _preview_prev(self):
        if self.preview_page_index > 0:
            self.preview_page_index -= 1
            self._render_current_preview_page()
            self._update_nav_buttons()

    def _preview_next(self):
        if (self.preview_doc is not None
                and self.preview_page_index < self.preview_total_pages - 1):
            self.preview_page_index += 1
            self._render_current_preview_page()
            self._update_nav_buttons()

    # -------------------------------------------------------------------------
    #  Open / Print
    # -------------------------------------------------------------------------
    def _open_generated_pdf(self):
        if self.last_generated_pdf is None or not Path(self.last_generated_pdf).exists():
            messagebox.showwarning(
                "No layout generated",
                "Click “Update Preview” first to generate the A4 layout.",
                parent=self,
            )
            return

        try:
            import os
            os.startfile(str(self.last_generated_pdf))
        except Exception as e:
            messagebox.showerror(
                "Could not open file", f"Failed to open the PDF:\n{e}", parent=self
            )

    def _send_to_printer(self):
        try:
            selected = self._get_selected_paths()
            if not selected:
                raise RuntimeError("Please select at least one PDF file.")

            # Regenerate the layout each time Print is clicked so margin/file
            # changes since the last preview are reflected.
            top, bottom, left, right = self._parse_margins()

            tmp_dir = Path(tempfile.gettempdir())
            out_pdf = tmp_dir / "dilg_certificate_print_layout.pdf"

            build_a4_2up_pdf(
                input_pdf_paths=selected,
                output_pdf_path=out_pdf,
                margin_top_mm=top,
                margin_bottom_mm=bottom,
                margin_left_mm=left,
                margin_right_mm=right,
            )
            self.last_generated_pdf = out_pdf

            printer = self.printer_name.get().strip()
            if printer == "(no printers available)":
                printer = ""

            send_pdf_to_printer(out_pdf, printer_name=printer)

            messagebox.showinfo(
                "Sent to printer",
                f"The A4 layout was sent to:\n{printer or '(default printer)'}\n\n"
                f"{(len(selected) + 1) // 2} page(s) queued.",
                parent=self,
            )

        except Exception as e:
            messagebox.showerror("Print failed", str(e), parent=self)

    # -------------------------------------------------------------------------
    #  Lifecycle
    # -------------------------------------------------------------------------
    def _on_close(self):
        if self.preview_doc is not None:
            try:
                self.preview_doc.close()
            except Exception:
                pass
            self.preview_doc = None
        self.destroy()


class PdfBoxMapper(tk.Toplevel):
    """
    Preview a sample certificate PDF and draw the visible digital signature box.

    Requirement:
        python -m pip install pymupdf pillow

    The drawn screen rectangle is converted to PDF coordinates:
        x1,y1,x2,y2
    PDF coordinates start at the bottom-left corner.
    """

    def __init__(self, parent, pdf_path, current_box, on_apply):
        super().__init__(parent)

        self.parent = parent
        self.pdf_path = Path(pdf_path)
        self.current_box = current_box
        self.on_apply = on_apply

        self.title("Map Digital Signature Position")
        self.geometry("980x720")
        self.minsize(850, 620)
        self.transient(parent)
        self.grab_set()

        self.doc = None
        self.page = None
        self.pdf_width = None
        self.pdf_height = None
        self.zoom = None
        self.render_width = None
        self.render_height = None
        self.photo = None
        self.rect_id = None
        self.start_x = None
        self.start_y = None
        self.current_canvas_box = None

        self._build_ui()
        self._load_pdf_preview()

    def _build_ui(self):
        self.configure(background=COLOR_BG)

        outer = ttk.Frame(self, padding=12)
        outer.pack(fill="both", expand=True)

        outer.columnconfigure(0, weight=1)
        outer.rowconfigure(1, weight=1)
        outer.rowconfigure(2, weight=0)

        ttk.Label(
            outer,
            text=(
                "Draw the signature box on the sample certificate. "
                "Click and drag on the PDF preview, then click Apply Position. "
                "The rectangle controls both position and size of the visible signature."
            ),
            wraplength=920,
            justify="left",
            background=COLOR_BG,
            foreground=COLOR_TEXT,
            font=(FONT_FAMILY, 10),
        ).grid(row=0, column=0, sticky="ew", pady=(0, 10))

        canvas_frame = ttk.Frame(outer)
        canvas_frame.grid(row=1, column=0, sticky="nsew")
        canvas_frame.columnconfigure(0, weight=1)
        canvas_frame.rowconfigure(0, weight=1)

        self.canvas = tk.Canvas(
            canvas_frame,
            background="#d9d9d9",
            cursor="crosshair",
            highlightthickness=1,
            highlightbackground=COLOR_BORDER,
        )
        self.canvas.grid(row=0, column=0, sticky="nsew")

        vbar = ttk.Scrollbar(canvas_frame, orient="vertical", command=self.canvas.yview)
        hbar = ttk.Scrollbar(canvas_frame, orient="horizontal", command=self.canvas.xview)
        self.canvas.configure(yscrollcommand=vbar.set, xscrollcommand=hbar.set)

        vbar.grid(row=0, column=1, sticky="ns")
        hbar.grid(row=1, column=0, sticky="ew")

        self.canvas.bind("<ButtonPress-1>", self.on_mouse_down)
        self.canvas.bind("<B1-Motion>", self.on_mouse_drag)
        self.canvas.bind("<ButtonRelease-1>", self.on_mouse_up)

        bottom = ttk.Frame(outer)
        bottom.grid(row=2, column=0, sticky="ew", pady=(10, 0))
        bottom.columnconfigure(1, weight=1)

        ttk.Label(
            bottom,
            text="Mapped PDF box",
            background=COLOR_BG,
            foreground=COLOR_TEXT,
        ).grid(row=0, column=0, sticky="w")
        self.mapped_box = tk.StringVar(value="")
        ttk.Entry(
            bottom,
            textvariable=self.mapped_box,
            foreground=COLOR_TEXT,
            font=(FONT_MONO, 10),
        ).grid(row=0, column=1, sticky="ew", padx=(8, 8))

        ttk.Button(
            bottom,
            text="Apply Position",
            command=self.apply_position,
            style="Accent.TButton",
        ).grid(row=0, column=2, sticky="e")
        ttk.Button(bottom, text="Cancel", command=self.destroy).grid(
            row=0, column=3, sticky="e", padx=(8, 0)
        )

    def _load_pdf_preview(self):
        try:
            import fitz
            from PIL import Image, ImageTk
        except Exception as e:
            messagebox.showerror(
                "Missing PDF Preview Package",
                "PDF preview requires PyMuPDF and Pillow.\n\n"
                "Install them using:\n"
                "python -m pip install pymupdf pillow\n\n"
                f"Original error: {e}",
            )
            self.destroy()
            return

        if not self.pdf_path.exists():
            messagebox.showerror("File not found", f"Sample PDF not found:\n{self.pdf_path}")
            self.destroy()
            return

        try:
            self.doc = fitz.open(str(self.pdf_path))
            self.page = self.doc[0]

            rect = self.page.rect
            self.pdf_width = float(rect.width)
            self.pdf_height = float(rect.height)

            target_width = 850
            self.zoom = target_width / self.pdf_width

            matrix = fitz.Matrix(self.zoom, self.zoom)
            pix = self.page.get_pixmap(matrix=matrix, alpha=False)

            self.render_width = pix.width
            self.render_height = pix.height

            image = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
            self.photo = ImageTk.PhotoImage(image)

            self.canvas.create_image(0, 0, image=self.photo, anchor="nw")
            self.canvas.configure(scrollregion=(0, 0, self.render_width, self.render_height))

            self.draw_existing_box()

        except Exception as e:
            messagebox.showerror("Preview error", f"Could not render sample PDF:\n{e}")
            self.destroy()

    def draw_existing_box(self):
        if not self.current_box:
            return

        try:
            x1, y1, x2, y2 = parse_box(self.current_box)
        except Exception:
            return

        canvas_x1 = x1 * self.zoom
        canvas_y1 = (self.pdf_height - y2) * self.zoom
        canvas_x2 = x2 * self.zoom
        canvas_y2 = (self.pdf_height - y1) * self.zoom

        self.rect_id = self.canvas.create_rectangle(
            canvas_x1,
            canvas_y1,
            canvas_x2,
            canvas_y2,
            outline="red",
            width=2,
        )
        self.current_canvas_box = (canvas_x1, canvas_y1, canvas_x2, canvas_y2)
        self.update_mapped_box_from_canvas_box()

    def canvas_xy(self, event):
        return self.canvas.canvasx(event.x), self.canvas.canvasy(event.y)

    def clamp_to_page(self, x, y):
        x = max(0, min(x, self.render_width))
        y = max(0, min(y, self.render_height))
        return x, y

    def on_mouse_down(self, event):
        x, y = self.canvas_xy(event)
        x, y = self.clamp_to_page(x, y)

        self.start_x = x
        self.start_y = y

        if self.rect_id:
            self.canvas.delete(self.rect_id)

        self.rect_id = self.canvas.create_rectangle(
            x,
            y,
            x,
            y,
            outline="red",
            width=2,
        )

    def on_mouse_drag(self, event):
        if self.rect_id is None:
            return

        x, y = self.canvas_xy(event)
        x, y = self.clamp_to_page(x, y)

        self.canvas.coords(self.rect_id, self.start_x, self.start_y, x, y)
        self.current_canvas_box = (self.start_x, self.start_y, x, y)
        self.update_mapped_box_from_canvas_box()

    def on_mouse_up(self, event):
        if self.rect_id is None:
            return

        x, y = self.canvas_xy(event)
        x, y = self.clamp_to_page(x, y)

        self.canvas.coords(self.rect_id, self.start_x, self.start_y, x, y)
        self.current_canvas_box = (self.start_x, self.start_y, x, y)
        self.update_mapped_box_from_canvas_box()

    def update_mapped_box_from_canvas_box(self):
        if not self.current_canvas_box:
            return

        cx1, cy1, cx2, cy2 = self.current_canvas_box

        left = min(cx1, cx2)
        right = max(cx1, cx2)
        top = min(cy1, cy2)
        bottom = max(cy1, cy2)

        if abs(right - left) < 2 or abs(bottom - top) < 2:
            self.mapped_box.set("")
            return

        pdf_x1 = left / self.zoom
        pdf_x2 = right / self.zoom
        pdf_y1 = self.pdf_height - (bottom / self.zoom)
        pdf_y2 = self.pdf_height - (top / self.zoom)

        self.mapped_box.set(f"{pdf_x1:.0f},{pdf_y1:.0f},{pdf_x2:.0f},{pdf_y2:.0f}")

    def apply_position(self):
        box = self.mapped_box.get().strip()

        if not box:
            messagebox.showwarning("No box selected", "Please draw a signature box first.")
            return

        try:
            parse_box(box)
        except Exception as e:
            messagebox.showerror("Invalid box", str(e))
            return

        self.on_apply(box)
        self.destroy()


# =============================================================================
#   THEME / STYLE CONSTANTS
# =============================================================================
COLOR_BG          = "#f4f6f8"   # window background (cool light gray)
COLOR_SURFACE     = "#ffffff"   # card / labelframe interior
COLOR_BORDER      = "#d6dde3"   # subtle borders
COLOR_TEXT        = "#000000"   # primary text — black, per requirement
COLOR_TEXT_MUTED  = "#5a6470"   # secondary text
COLOR_HEADER_BG   = "#1f3d5a"   # deep navy header bar
COLOR_HEADER_FG   = "#ffffff"
COLOR_ACCENT      = "#2563eb"   # primary action blue
COLOR_ACCENT_HOV  = "#1d4ed8"
COLOR_SUCCESS     = "#15803d"
COLOR_DANGER      = "#b91c1c"
COLOR_LOG_BG      = "#0f1720"   # log panel dark background
COLOR_LOG_FG      = "#e6edf3"   # log panel text

FONT_FAMILY       = "Segoe UI"
FONT_MONO         = "Consolas"


class PdfSignerGUI(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("DILG X Certificate of Appearance Batch Sign")
        self.configure(background=COLOR_BG)
        self.minsize(1000, 600)

        # Open at 90% of the current screen height with a proportional width,
        # capped at 1600px wide so the layout doesn't stretch awkwardly on very
        # large monitors. Center the window on the screen.
        screen_w = self.winfo_screenwidth()
        screen_h = self.winfo_screenheight()

        win_h = int(screen_h * 0.90)
        win_w = min(int(screen_w * 0.90), 1600)

        # Respect the minimum size.
        win_w = max(win_w, 1000)
        win_h = max(win_h, 600)

        pos_x = max((screen_w - win_w) // 2, 0)
        pos_y = max((screen_h - win_h) // 2, 0)

        self.geometry(f"{win_w}x{win_h}+{pos_x}+{pos_y}")

        self._apply_theme()

        self.input_folder = tk.StringVar()
        self.output_folder = tk.StringVar()
        self.signature_image = tk.StringVar()
        self.logo_image = tk.StringVar()
        self.sample_certificate = tk.StringVar()
        self.remember_selections = tk.BooleanVar(value=False)

        self.thumbprint = tk.StringVar()
        self.store_location = tk.StringVar(value="CurrentUser")
        self.selected_cert_subject = tk.StringVar(value="No certificate selected")

        self.signer_name = tk.StringVar()
        self.page_number = tk.StringVar(value="1")
        self.signature_box = tk.StringVar(value="220,90,400,145")
        self.field_prefix = tk.StringVar(value="Signature")

        saved_settings, self._settings_load_error = load_gui_settings()
        self._remembered_settings_loaded = self._apply_saved_settings(saved_settings)

        self.timestamp_preview = tk.StringVar()
        self.update_timestamp_preview()

        self._build_ui()

        if self._settings_load_error is not None:
            self.log(f"Could not load saved selections: {self._settings_load_error}\n")

        if self._remembered_settings_loaded:
            self.log("Loaded remembered certificate, signature image and logo selections.\n")

        if IMPORT_ERROR is not None:
            self.log(
                "ERROR: Could not import your sigpdf.py.\n"
                "Make sure sigpdf_gui_final.py is saved in the same folder as sigpdf.py.\n\n"
                f"Import error: {IMPORT_ERROR}\n"
            )

    def _apply_saved_settings(self, data):
        if not data.get("remember_selections"):
            return False

        self.remember_selections.set(True)
        self.signature_image.set(str(data.get("signature_image") or ""))
        self.logo_image.set(str(data.get("logo_image") or ""))
        self.sample_certificate.set(str(data.get("sample_certificate") or ""))

        thumbprint = clean_thumbprint_for_display(data.get("thumbprint") or "")
        self.thumbprint.set(thumbprint)

        store_location = str(data.get("store_location") or "CurrentUser")
        if store_location not in ("CurrentUser", "LocalMachine"):
            store_location = "CurrentUser"
        self.store_location.set(store_location)

        subject = str(data.get("selected_cert_subject") or "").strip()
        if subject:
            self.selected_cert_subject.set(subject)
            self.signer_name.set(get_signer_name_from_cert_subject(subject))
        elif thumbprint:
            self.selected_cert_subject.set("Remembered certificate loaded")
            self.signer_name.set("")

        return True

    def _apply_theme(self):
        """Configure a clean, modern ttk theme with consistent typography and colors."""
        style = ttk.Style(self)

        # 'clam' gives us the most control over colors of all built-in themes.
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        base_font     = (FONT_FAMILY, 10)
        label_font    = (FONT_FAMILY, 10)
        entry_font    = (FONT_FAMILY, 10)
        section_font  = (FONT_FAMILY, 10, "bold")
        button_font   = (FONT_FAMILY, 10)

        # --- Root containers --------------------------------------------------
        style.configure("TFrame", background=COLOR_BG)
        style.configure("Card.TFrame", background=COLOR_SURFACE)

        # Header bar (navy band behind the title)
        style.configure(
            "Header.TFrame",
            background=COLOR_HEADER_BG,
        )
        style.configure(
            "Header.TLabel",
            background=COLOR_HEADER_BG,
            foreground=COLOR_HEADER_FG,
            font=(FONT_FAMILY, 14, "bold"),
            padding=(14, 8, 14, 0),
        )
        style.configure(
            "HeaderSub.TLabel",
            background=COLOR_HEADER_BG,
            foreground="#cbd5e1",
            font=(FONT_FAMILY, 9),
            padding=(14, 0, 14, 8),
        )

        # --- Labels -----------------------------------------------------------
        style.configure(
            "TLabel",
            background=COLOR_BG,
            foreground=COLOR_TEXT,
            font=label_font,
        )
        style.configure(
            "Surface.TLabel",
            background=COLOR_SURFACE,
            foreground=COLOR_TEXT,
            font=label_font,
        )
        style.configure(
            "FieldLabel.TLabel",
            background=COLOR_SURFACE,
            foreground=COLOR_TEXT,
            font=label_font,
        )
        style.configure(
            "Muted.TLabel",
            background=COLOR_BG,
            foreground=COLOR_TEXT_MUTED,
            font=(FONT_FAMILY, 9),
        )
        style.configure(
            "SurfaceMuted.TLabel",
            background=COLOR_SURFACE,
            foreground=COLOR_TEXT_MUTED,
            font=(FONT_FAMILY, 9),
        )
        style.configure(
            "Value.TLabel",
            background=COLOR_SURFACE,
            foreground=COLOR_TEXT,
            font=(FONT_FAMILY, 10, "bold"),
        )

        # --- LabelFrames (section cards) -------------------------------------
        style.configure(
            "Card.TLabelframe",
            background=COLOR_SURFACE,
            foreground=COLOR_TEXT,
            bordercolor=COLOR_BORDER,
            lightcolor=COLOR_BORDER,
            darkcolor=COLOR_BORDER,
            relief="solid",
            borderwidth=1,
        )
        style.configure(
            "Card.TLabelframe.Label",
            background=COLOR_SURFACE,
            foreground=COLOR_HEADER_BG,
            font=section_font,
            padding=(4, 0),
        )

        # --- Entries / Combobox ----------------------------------------------
        style.configure(
            "TEntry",
            fieldbackground=COLOR_SURFACE,
            foreground=COLOR_TEXT,           # text inside entries is BLACK
            bordercolor=COLOR_BORDER,
            lightcolor=COLOR_BORDER,
            darkcolor=COLOR_BORDER,
            insertcolor=COLOR_TEXT,
            padding=4,
            font=entry_font,
        )
        style.map(
            "TEntry",
            bordercolor=[("focus", COLOR_ACCENT)],
            lightcolor=[("focus", COLOR_ACCENT)],
            darkcolor=[("focus", COLOR_ACCENT)],
            foreground=[("readonly", COLOR_TEXT)],
            fieldbackground=[("readonly", "#f0f3f6")],
        )

        style.configure(
            "TCombobox",
            fieldbackground=COLOR_SURFACE,
            background=COLOR_SURFACE,
            foreground=COLOR_TEXT,
            bordercolor=COLOR_BORDER,
            arrowcolor=COLOR_HEADER_BG,
            padding=3,
        )
        style.map(
            "TCombobox",
            fieldbackground=[("readonly", COLOR_SURFACE)],
            foreground=[("readonly", COLOR_TEXT)],
            bordercolor=[("focus", COLOR_ACCENT)],
        )

        # --- Checkbuttons -----------------------------------------------------
        style.configure(
            "TCheckbutton",
            background=COLOR_SURFACE,
            foreground=COLOR_TEXT,
            font=label_font,
        )
        style.map(
            "TCheckbutton",
            background=[("active", COLOR_SURFACE)],
            foreground=[("disabled", COLOR_TEXT_MUTED)],
        )

        # --- Buttons ----------------------------------------------------------
        # Secondary / default button — soft gray-bordered look
        style.configure(
            "TButton",
            background="#e9eef3",
            foreground=COLOR_TEXT,
            bordercolor=COLOR_BORDER,
            lightcolor=COLOR_BORDER,
            darkcolor=COLOR_BORDER,
            focusthickness=0,
            padding=(12, 6),
            font=button_font,
            relief="flat",
        )
        style.map(
            "TButton",
            background=[
                ("active", "#dce4ec"),
                ("disabled", "#eef1f4"),
            ],
            foreground=[
                ("disabled", "#9aa3ad"),
            ],
        )

        # Primary action button — accent blue (used for Sign PDFs)
        style.configure(
            "Accent.TButton",
            background=COLOR_ACCENT,
            foreground="#ffffff",
            bordercolor=COLOR_ACCENT,
            lightcolor=COLOR_ACCENT,
            darkcolor=COLOR_ACCENT,
            focusthickness=0,
            padding=(18, 9),
            font=(FONT_FAMILY, 10, "bold"),
            relief="flat",
        )
        style.map(
            "Accent.TButton",
            background=[
                ("active", COLOR_ACCENT_HOV),
                ("disabled", "#93b4f5"),
            ],
            foreground=[("disabled", "#eef2ff")],
        )

        # Accent button placed ON the navy header bar
        style.configure(
            "HeaderAccent.TButton",
            background=COLOR_ACCENT,
            foreground="#ffffff",
            bordercolor=COLOR_ACCENT,
            lightcolor=COLOR_ACCENT,
            darkcolor=COLOR_ACCENT,
            focusthickness=0,
            padding=(16, 7),
            font=(FONT_FAMILY, 10, "bold"),
            relief="flat",
        )
        style.map(
            "HeaderAccent.TButton",
            background=[
                ("active", COLOR_ACCENT_HOV),
                ("disabled", "#3c5b85"),
            ],
        )

        # Status bar
        style.configure("Status.TFrame", background="#e9eef3")
        style.configure(
            "Status.TLabel",
            background="#e9eef3",
            foreground=COLOR_TEXT_MUTED,
            font=(FONT_FAMILY, 9),
            padding=(8, 6),
        )

        # Scrollbar tidy-up
        style.configure(
            "Vertical.TScrollbar",
            background=COLOR_BG,
            troughcolor=COLOR_BG,
            bordercolor=COLOR_BG,
            arrowcolor=COLOR_HEADER_BG,
        )
        style.configure(
            "Horizontal.TScrollbar",
            background=COLOR_BG,
            troughcolor=COLOR_BG,
            bordercolor=COLOR_BG,
            arrowcolor=COLOR_HEADER_BG,
        )

        self.option_add("*Font", base_font)

    def _build_ui(self):
        outer = ttk.Frame(self, padding=0)
        outer.pack(fill="both", expand=True)

        outer.columnconfigure(0, weight=1)
        outer.rowconfigure(1, weight=1)

        # =====================================================================
        # HEADER BAR
        # =====================================================================
        header_bar = ttk.Frame(outer, style="Header.TFrame")
        header_bar.grid(row=0, column=0, sticky="ew")
        header_bar.columnconfigure(0, weight=1)

        title = ttk.Label(
            header_bar,
            text="  DILG X — Certificate of Appearance Batch Sign",
            style="Header.TLabel",
        )
        title.grid(row=0, column=0, sticky="w")

        subtitle = ttk.Label(
            header_bar,
            text="  Digitally sign multiple PDF certificates in one batch",
            style="HeaderSub.TLabel",
        )
        subtitle.grid(row=1, column=0, sticky="w")

        # Right-aligned action buttons in the header.
        header_actions = ttk.Frame(header_bar, style="Header.TFrame")
        header_actions.grid(row=0, column=1, rowspan=2, sticky="e", padx=14, pady=8)

        self.print_button = ttk.Button(
            header_actions,
            text="🖶  Print Certificates",
            command=self.open_print_dialog,
            style="HeaderAccent.TButton",
        )
        self.print_button.grid(row=0, column=0, sticky="e", padx=(0, 8))

        self.sign_button = ttk.Button(
            header_actions,
            text="✓  Sign PDFs",
            command=self.start_signing,
            style="HeaderAccent.TButton",
        )
        self.sign_button.grid(row=0, column=1, sticky="e")

        # =====================================================================
        # BODY
        # =====================================================================
        body = ttk.Frame(outer, padding=10, style="TFrame")
        body.grid(row=1, column=0, sticky="nsew")

        # Two-column body: left controls, right log panel.
        body.columnconfigure(0, weight=3, minsize=560)
        body.columnconfigure(1, weight=5, minsize=420)
        body.rowconfigure(0, weight=1)

        # --- LEFT column (controls) ------------------------------------------
        left_panel = ttk.Frame(body)
        left_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        left_panel.columnconfigure(0, weight=1)

        # --- RIGHT column (activity log) -------------------------------------
        right_panel = ttk.Frame(body)
        right_panel.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        right_panel.columnconfigure(0, weight=1)
        right_panel.rowconfigure(0, weight=1)

        files_frame = ttk.LabelFrame(
            left_panel, text="  Files  ", padding=10, style="Card.TLabelframe"
        )
        files_frame.grid(row=0, column=0, sticky="ew")
        files_frame.columnconfigure(1, weight=1)

        self._path_row(
            files_frame,
            row=0,
            label="Input folder",
            variable=self.input_folder,
            command=self.choose_input_folder,
        )

        self._path_row(
            files_frame,
            row=1,
            label="Output folder",
            variable=self.output_folder,
            command=self.choose_output_folder,
        )

        self._path_row(
            files_frame,
            row=2,
            label="Signature image",
            variable=self.signature_image,
            command=self.choose_signature_image,
            file_button=True,
        )

        self._path_row(
            files_frame,
            row=3,
            label="Logo image (optional)",
            variable=self.logo_image,
            command=self.choose_logo_image,
            file_button=True,
        )

        self._path_row(
            files_frame,
            row=4,
            label="Sample certificate PDF",
            variable=self.sample_certificate,
            command=self.choose_sample_certificate,
            file_button=True,
        )

        ttk.Checkbutton(
            files_frame,
            text="Remember selected certificate, signature image and logo",
            variable=self.remember_selections,
            command=self.on_remember_selections_changed,
        ).grid(row=5, column=1, columnspan=2, sticky="w", pady=(6, 0), padx=(8, 0))

        # ---- Certificate card ----------------------------------------------
        cert_frame = ttk.LabelFrame(
            left_panel, text="  Certificate  ", padding=10, style="Card.TLabelframe"
        )
        cert_frame.grid(row=1, column=0, sticky="ew", pady=(8, 0))
        cert_frame.columnconfigure(1, weight=1)

        ttk.Label(cert_frame, text="Store", style="FieldLabel.TLabel").grid(
            row=0, column=0, sticky="w", pady=5
        )
        store_combo = ttk.Combobox(
            cert_frame,
            textvariable=self.store_location,
            values=["CurrentUser", "LocalMachine"],
            state="readonly",
            width=18,
            foreground=COLOR_TEXT,
        )
        store_combo.grid(row=0, column=1, sticky="w", pady=5, padx=(8, 0))
        store_combo.bind(
            "<<ComboboxSelected>>",
            lambda _event: self.update_remembered_selections(),
        )

        ttk.Button(
            cert_frame,
            text="Select Certificate",
            command=self.choose_certificate,
        ).grid(row=0, column=2, sticky="e", padx=(8, 0), pady=5)

        ttk.Label(cert_frame, text="Thumbprint", style="FieldLabel.TLabel").grid(
            row=1, column=0, sticky="w", pady=5
        )
        ttk.Entry(
            cert_frame,
            textvariable=self.thumbprint,
            foreground=COLOR_TEXT,
        ).grid(row=1, column=1, columnspan=2, sticky="ew", pady=5, padx=(8, 0))

        ttk.Label(cert_frame, text="Selected", style="FieldLabel.TLabel").grid(
            row=2, column=0, sticky="nw", pady=5
        )
        ttk.Label(
            cert_frame,
            textvariable=self.selected_cert_subject,
            foreground=COLOR_TEXT,             # black
            background=COLOR_SURFACE,
            wraplength=420,
            font=(FONT_FAMILY, 9),
        ).grid(row=2, column=1, columnspan=2, sticky="w", pady=5, padx=(8, 0))

        # ---- Signature appearance card --------------------------------------
        sig_frame = ttk.LabelFrame(
            left_panel,
            text="  Signature Appearance  ",
            padding=10,
            style="Card.TLabelframe",
        )
        sig_frame.grid(row=2, column=0, sticky="ew", pady=(8, 0))
        sig_frame.columnconfigure(1, weight=1)

        ttk.Label(sig_frame, text="Signer name", style="FieldLabel.TLabel").grid(
            row=0, column=0, sticky="w", pady=5
        )
        ttk.Entry(
            sig_frame,
            textvariable=self.signer_name,
            state="readonly",
            foreground=COLOR_TEXT,             # signer name text is BLACK
            font=(FONT_FAMILY, 10),
        ).grid(row=0, column=1, columnspan=2, sticky="ew", pady=5, padx=(8, 0))

        ttk.Label(
            sig_frame, text="Computer timestamp", style="FieldLabel.TLabel"
        ).grid(row=1, column=0, sticky="w", pady=5)
        ttk.Label(
            sig_frame,
            textvariable=self.timestamp_preview,
            background=COLOR_SURFACE,
            foreground=COLOR_TEXT,             # timestamp text is BLACK
            font=(FONT_MONO, 10),
        ).grid(row=1, column=1, sticky="w", pady=5, padx=(8, 0))
        ttk.Button(
            sig_frame,
            text="Refresh",
            command=self.update_timestamp_preview,
        ).grid(row=1, column=2, sticky="e", padx=(8, 0), pady=5)

        ttk.Label(sig_frame, text="Signature box", style="FieldLabel.TLabel").grid(
            row=2, column=0, sticky="w", pady=5
        )
        ttk.Entry(
            sig_frame,
            textvariable=self.signature_box,
            state="readonly",
            foreground=COLOR_TEXT,
            font=(FONT_MONO, 10),
        ).grid(row=2, column=1, sticky="ew", pady=5, padx=(8, 0))
        ttk.Button(
            sig_frame,
            text="Map Position on Sample PDF",
            command=self.open_box_mapper,
        ).grid(row=2, column=2, sticky="e", padx=(8, 0), pady=5)

        # ---- Text preview card ----------------------------------------------
        preview_frame = ttk.LabelFrame(
            left_panel,
            text="  Signature Text Preview  ",
            padding=10,
            style="Card.TLabelframe",
        )
        preview_frame.grid(row=3, column=0, sticky="ew", pady=(8, 0))
        preview_frame.columnconfigure(0, weight=1, minsize=380)

        self.preview_text = tk.Text(
            preview_frame,
            height=4,
            wrap="word",
            foreground=COLOR_TEXT,             # preview text BLACK
            background="#fafbfc",
            relief="flat",
            borderwidth=1,
            highlightthickness=1,
            highlightbackground=COLOR_BORDER,
            highlightcolor=COLOR_ACCENT,
            font=(FONT_FAMILY, 10),
            padx=10,
            pady=8,
            insertbackground=COLOR_TEXT,
        )
        self.preview_text.grid(row=0, column=0, sticky="ew")
        self.preview_text.configure(state="disabled")

        ttk.Button(
            preview_frame,
            text="Update Preview",
            command=self.update_text_preview,
            width=18,
        ).grid(row=0, column=1, sticky="ne", padx=(8, 0))

        # ---- Log card --------------------------------------------------------
        log_frame = ttk.LabelFrame(
            right_panel, text="  Activity Log  ", padding=10, style="Card.TLabelframe"
        )
        log_frame.grid(row=0, column=0, sticky="nsew")
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)

        self.log_box = scrolledtext.ScrolledText(
            log_frame,
            wrap="word",
            font=(FONT_MONO, 10),
            foreground=COLOR_LOG_FG,
            background=COLOR_LOG_BG,
            insertbackground=COLOR_LOG_FG,
            relief="flat",
            borderwidth=0,
            padx=10,
            pady=8,
        )
        self.log_box.grid(row=0, column=0, sticky="nsew")

        log_buttons = ttk.Frame(log_frame, style="Card.TFrame")
        log_buttons.grid(row=1, column=0, sticky="ew", pady=(10, 0))
        log_buttons.columnconfigure(2, weight=1)

        ttk.Button(log_buttons, text="Clear Log", command=self.clear_log).grid(
            row=0, column=0, sticky="w"
        )
        ttk.Button(
            log_buttons,
            text="Open Output Folder",
            command=self.open_output_folder,
        ).grid(row=0, column=1, sticky="w", padx=(8, 0))

        # ---- Footer status bar ----------------------------------------------
        status_bar = ttk.Frame(outer, style="Status.TFrame")
        status_bar.grid(row=2, column=0, sticky="ew")
        status_bar.columnconfigure(0, weight=1)

        ttk.Label(
            status_bar,
            text="© 2026 DILG X — RICTU",
            anchor="center",
            style="Status.TLabel",
        ).grid(row=0, column=0, sticky="ew")

        self.update_text_preview()

    def _path_row(self, parent, row, label, variable, command, file_button=False):
        ttk.Label(parent, text=label, style="FieldLabel.TLabel").grid(
            row=row, column=0, sticky="w", pady=6
        )
        ttk.Entry(
            parent,
            textvariable=variable,
            foreground=COLOR_TEXT,             # path entry text BLACK
        ).grid(row=row, column=1, sticky="ew", pady=6, padx=(8, 8))
        ttk.Button(
            parent,
            text="Browse File" if file_button else "Browse Folder",
            command=command,
        ).grid(row=row, column=2, sticky="ew", pady=6)

    def _remembered_selection_payload(self):
        return {
            "remember_selections": True,
            "signature_image": self.signature_image.get().strip(),
            "logo_image": self.logo_image.get().strip(),
            "sample_certificate": self.sample_certificate.get().strip(),
            "thumbprint": clean_thumbprint_for_display(self.thumbprint.get()),
            "store_location": self.store_location.get().strip() or "CurrentUser",
            "selected_cert_subject": self.selected_cert_subject.get().strip(),
        }

    def save_remembered_selections(self):
        if not self.remember_selections.get():
            return

        save_gui_settings(self._remembered_selection_payload())

    def on_remember_selections_changed(self):
        if self.remember_selections.get():
            try:
                self.save_remembered_selections()
            except Exception as exc:
                self.remember_selections.set(False)
                messagebox.showerror("Remember selections failed", str(exc))
                return

            self.log("Remembering selected certificate, signature image and logo.\n")
            return

        try:
            delete_gui_settings()
        except Exception as exc:
            messagebox.showerror("Clear saved selections failed", str(exc))
            return

        self.log("Cleared remembered certificate, signature image and logo selections.\n")

    def update_remembered_selections(self):
        if not self.remember_selections.get():
            return

        try:
            self.save_remembered_selections()
        except Exception as exc:
            self.log(f"Could not save remembered selections: {exc}\n")

    def choose_input_folder(self):
        folder = filedialog.askdirectory(title="Select input folder containing PDF files")
        if folder:
            self.input_folder.set(folder)

    def choose_output_folder(self):
        folder = filedialog.askdirectory(title="Select output folder for signed PDF files")
        if folder:
            self.output_folder.set(folder)

    def choose_signature_image(self):
        file_path = filedialog.askopenfilename(
            title="Select signature image",
            filetypes=[
                ("Image files", "*.png;*.jpg;*.jpeg;*.bmp;*.gif"),
                ("All files", "*.*"),
            ],
        )
        if file_path:
            self.signature_image.set(file_path)
            self.update_remembered_selections()

    def choose_logo_image(self):
        file_path = filedialog.askopenfilename(
            title="Select logo image",
            filetypes=[
                ("Image files", "*.png;*.jpg;*.jpeg;*.bmp;*.gif"),
                ("All files", "*.*"),
            ],
        )
        if file_path:
            self.logo_image.set(file_path)
            self.update_remembered_selections()

    def choose_sample_certificate(self):
        file_path = filedialog.askopenfilename(
            title="Select sample certificate PDF",
            filetypes=[
                ("PDF files", "*.pdf"),
                ("All files", "*.*"),
            ],
        )
        if file_path:
            self.sample_certificate.set(file_path)
            self.update_remembered_selections()

    def open_box_mapper(self):
        pdf_path = self.sample_certificate.get().strip()

        if not pdf_path:
            messagebox.showwarning(
                "Sample certificate required",
                "Please select a sample certificate PDF first.",
            )
            return

        def apply_box(mapped_box):
            self.signature_box.set(mapped_box)
            self.log(f"Mapped signature box from sample PDF: {mapped_box}\n")

        PdfBoxMapper(
            parent=self,
            pdf_path=pdf_path,
            current_box=self.signature_box.get().strip(),
            on_apply=apply_box,
        )

    def open_print_dialog(self):
        """Open the 2-up A4 print dialog. Pre-populates the source folder
        with the output folder from the signing section, since that's where
        freshly signed Certificates of Appearance will live."""
        dialog = PrintLayoutDialog(parent=self)

        # If the user has already chosen an output folder for signing, use it
        # as a starting point so they don't have to browse again.
        starter = self.output_folder.get().strip()
        if starter and Path(starter).is_dir():
            dialog.source_folder.set(starter)
            dialog._load_files_from_folder(Path(starter))

        self.log("Opened Print Certificates dialog.\n")

    def choose_certificate(self):
        try:
            store_location = self.store_location.get().strip() or "CurrentUser"

            thumbprint, subject = select_certificate_from_windows_store(store_location)

            if not thumbprint:
                self.log("Certificate selection cancelled.\n")
                return

            self.thumbprint.set(thumbprint)
            self.selected_cert_subject.set(subject)
            self.signer_name.set(get_signer_name_from_cert_subject(subject))
            self.update_text_preview()
            self.update_remembered_selections()
            self.log(f"Selected certificate: {subject}\n")
            self.log(f"Thumbprint: {thumbprint}\n")

        except Exception as e:
            self.log("ERROR selecting certificate:\n")
            self.log(str(e) + "\n\n")
            messagebox.showerror("Certificate selection failed", str(e))

    def get_signature_text(self):
        date_line, time_line = get_computer_timestamp_text()
        signer_name = self.signer_name.get().strip()

        lines = ["Digitally signed by"]
        if signer_name:
            lines.append(signer_name)
        lines.extend([date_line, time_line])

        return "\n".join(lines)

    def update_timestamp_preview(self):
        date_line, time_line = get_computer_timestamp_text()
        self.timestamp_preview.set(f"{date_line}  {time_line}")

        if hasattr(self, "preview_text"):
            self.update_text_preview()

    def update_text_preview(self):
        text = self.get_signature_text()

        self.preview_text.configure(state="normal")
        self.preview_text.delete("1.0", "end")
        self.preview_text.insert("1.0", text)
        self.preview_text.configure(state="disabled")

    def log(self, message):
        self.log_box.insert("end", message)
        self.log_box.see("end")
        self.update_idletasks()

    def clear_log(self):
        self.log_box.delete("1.0", "end")

    def open_output_folder(self):
        folder = self.output_folder.get().strip()
        if not folder:
            messagebox.showwarning("Missing folder", "Please select an output folder first.")
            return

        path = Path(folder)
        if not path.exists():
            messagebox.showwarning("Folder not found", f"Output folder does not exist:\n{path}")
            return

        try:
            import os
            os.startfile(str(path))
        except Exception as e:
            messagebox.showerror("Error", f"Could not open folder:\n{e}")

    def validate_inputs(self):
        if IMPORT_ERROR is not None:
            raise RuntimeError(
                "Could not import sigpdf.py. Save this GUI file in the same folder as sigpdf.py."
            )

        if not self.input_folder.get().strip():
            raise RuntimeError("Please select an input folder.")

        if not self.output_folder.get().strip():
            raise RuntimeError("Please select an output folder.")

        if not self.signature_image.get().strip():
            raise RuntimeError("Please select a signature image.")

        logo_image = self.logo_image.get().strip()
        if logo_image and not Path(logo_image).exists():
            raise RuntimeError(f"Logo image does not exist:\n{logo_image}")

        if not self.thumbprint.get().strip():
            raise RuntimeError("Please select or enter the certificate thumbprint.")

        try:
            dotnet_cert = find_certificate_by_thumbprint(
                thumbprint=self.thumbprint.get().strip(),
                store_location=self.store_location.get().strip() or "CurrentUser",
            )
        except Exception as exc:
            raise RuntimeError(f"Could not load selected certificate:\n{exc}")

        cert_subject = str(dotnet_cert.Subject)
        signer_name = get_signer_name_from_cert_subject(cert_subject)
        self.selected_cert_subject.set(cert_subject)
        self.signer_name.set(signer_name)
        self.update_text_preview()

        try:
            page = int(self.page_number.get().strip())
        except ValueError:
            raise RuntimeError("Page must be a number.")

        if page < 1:
            raise RuntimeError("Page must be 1 or higher.")

        box_text = self.signature_box.get().strip()
        box = parse_box(box_text)

        return {
            "input_folder": Path(self.input_folder.get().strip()),
            "output_folder": Path(self.output_folder.get().strip()),
            "thumbprint": self.thumbprint.get().strip(),
            "store_location": self.store_location.get().strip(),
            "page_number": page,
            "box": box,
            "signature_image": self.signature_image.get().strip(),
            "signature_text": self.get_signature_text(),
            "logo_image": logo_image,
            # Reason and location are intentionally removed from the GUI.
            # Passing None keeps these metadata fields blank.
            "reason": None,
            "location": None,
            "field_prefix": self.field_prefix.get().strip() or "Signature",
            "signer_name": signer_name,
        }

    def start_signing(self):
        try:
            settings = self.validate_inputs()
        except Exception as e:
            messagebox.showerror("Check settings", str(e))
            return

        self.update_timestamp_preview()
        settings["signature_text"] = self.get_signature_text()
        self.update_remembered_selections()

        self.sign_button.config(state="disabled")
        self.log("Starting PDF signing...\n")
        self.log("Visible signature text:\n")
        self.log(settings["signature_text"] + "\n\n")

        worker = threading.Thread(
            target=self.signing_worker,
            args=(settings,),
            daemon=True,
        )
        worker.start()

    def signing_worker(self, settings):
        try:
            result = detailed_batch_sign(settings, self.log)

            messagebox.showinfo(
                "Done",
                "PDF signing completed.\n\n"
                f"Succeeded: {result['successes']}\n"
                f"Failed: {result['failures']}\n"
                f"Log saved to:\n{result['log_file_path']}"
            )

        except Exception as e:
            self.log("\nERROR:\n")
            self.log(str(e) + "\n\n")
            self.log(traceback.format_exc() + "\n")
            messagebox.showerror("Signing failed", str(e))

        finally:
            self.sign_button.config(state="normal")


if __name__ == "__main__":
    app = PdfSignerGUI()
    app.mainloop()
