# ca-batch-sign

Windows desktop tool for batch-signing PDF Certificates of Appearance using a certificate from the Windows Certificate Store.

The app can create a visible digital signature with:

- handwritten signature image on the left
- optional logo in the middle
- black signature text on the right
- timestamp from the computer clock

It also includes a PDF position mapper and a print dialog for arranging signed A5 certificates two per A4 page.

## Requirements

- Windows
- Python 3.10 or newer
- A signing certificate with an accessible RSA private key in `CurrentUser\My` or `LocalMachine\My`
- Required Python packages:

```powershell
python -m pip install pythonnet pyhanko pyhanko-certvalidator asn1crypto pillow pymupdf pywin32
```

`pywin32` is mainly needed for printer detection and direct printing.

## Run The GUI

Keep `ca-batch-sign.py` and `sigpdf.py` in the same folder, then run:

```powershell
python ca-batch-sign.py
```

## Basic Workflow

1. Select the input folder containing unsigned PDF certificates.
2. Select the output folder for signed PDFs.
3. Select a handwritten signature image.
4. Optionally select a logo image.
5. Select a sample certificate PDF.
6. Choose the signing certificate from the Windows store.
7. Map the visible signature position on the sample PDF.
8. Click `Sign PDFs`.

Enable `Remember selected certificate, signature image and logo` if you want the GUI
to reload the same signing certificate, sample certificate PDF, signature image, and
logo the next time it opens.

Signed files are saved as:

```text
original_filename_signed.pdf
```

Batch logs are written to:

```text
logs/signing_YYYYMMDD_HHMMSS.log
```

## Signature Appearance

When a logo is selected, the visible signature is arranged as:

```text
[signature image]   [logo]   Digitally signed by
                             Signer Name
                             Date: YYYY-MM-DD
                             HH:MM+08:00
```

The signature image is converted to black ink while preserving transparency. Opaque white-background signature scans are also cleaned so the white background does not become a solid block.

Without a logo, the app keeps the compact signature-plus-text layout.

## Mapping Signature Position

Use `Map Position on Sample PDF` to draw the signature box directly on a preview of the certificate.

The resulting box is stored as PDF coordinates:

```text
x1,y1,x2,y2
```

The default is:

```text
220,90,400,145
```

## Print Certificates

Click `Print Certificates` to open the print layout dialog.

Features:

- loads signed PDFs from a selected folder
- lets you select which files to print
- creates A4 portrait pages with two certificates per page
- includes a dashed cutting line
- supports margin adjustment
- previews the generated A4 layout
- sends the generated PDF to a selected printer

The print layout renders source pages with annotations included, so visible digital signatures appear in the preview and printed output.

## Command-Line Signing

You can also use `sigpdf.py` directly:

```powershell
python sigpdf.py `
  --input-folder "C:\path\to\input" `
  --output-folder "C:\path\to\output" `
  --thumbprint "CERTIFICATE_THUMBPRINT" `
  --store-location CurrentUser `
  --page 1 `
  --box "220,90,400,145" `
  --image "C:\path\to\signature.png" `
  --logo "C:\path\to\logo.png" `
  --text "Digitally signed by`nSigner Name`nDate: 2026-05-27`n14:20+08:00"
```

The `--logo` argument is optional.

## Notes

- The GUI leaves PDF signature reason and location metadata blank.
- The computer's local date and time are used when signing starts.
- The certificate must support RSA signing.
- If the print preview or mapper fails, confirm that `pymupdf` and `pillow` are installed.
