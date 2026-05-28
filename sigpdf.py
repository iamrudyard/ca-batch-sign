import argparse
import re
import tempfile
from pathlib import Path

import clr

clr.AddReference("System")
clr.AddReference("System.Security")

from System import Array, Byte
from System.Security.Cryptography import (
    HashAlgorithmName,
    RSASignaturePadding,
)
from System.Security.Cryptography.X509Certificates import (
    X509Store,
    StoreName,
    StoreLocation,
    OpenFlags,
    RSACertificateExtensions,
)

from asn1crypto import algos, x509
from PIL import Image, ImageDraw, ImageFont

from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.images import PdfImage
from pyhanko.sign import fields, signers
from pyhanko.stamp import TextStampStyle
from pyhanko_certvalidator.registry import SimpleCertificateStore


def clean_thumbprint(value: str) -> str:
    return re.sub(r"[^0-9a-fA-F]", "", value).upper()


def bytes_to_dotnet_byte_array(data: bytes):
    return Array[Byte](data)


def find_certificate_by_thumbprint(thumbprint: str, store_location: str = "CurrentUser"):
    expected_thumbprint = clean_thumbprint(thumbprint)

    if store_location.lower() == "currentuser":
        location = StoreLocation.CurrentUser
    elif store_location.lower() == "localmachine":
        location = StoreLocation.LocalMachine
    else:
        raise RuntimeError("Invalid store location. Use CurrentUser or LocalMachine.")

    store = X509Store(StoreName.My, location)
    store.Open(OpenFlags.ReadOnly)

    try:
        for cert in store.Certificates:
            actual_thumbprint = clean_thumbprint(str(cert.Thumbprint))

            if actual_thumbprint == expected_thumbprint:
                if not cert.HasPrivateKey:
                    raise RuntimeError(
                        "Certificate found, but it has no accessible private key."
                    )
                return cert

        raise RuntimeError(
            f"Certificate with thumbprint {expected_thumbprint} "
            f"was not found in {store_location}\\My."
        )

    finally:
        store.Close()


def load_windows_cert_as_pyhanko_cert(dotnet_cert):
    signing_cert = x509.Certificate.load(bytes(dotnet_cert.RawData))
    cert_store = SimpleCertificateStore()

    try:
        cert_store.register(signing_cert)
    except Exception:
        pass

    return signing_cert, cert_store


class WindowsStoreRSASigner(signers.Signer):
    def __init__(self, dotnet_cert):
        self.dotnet_cert = dotnet_cert

        signing_cert, cert_store = load_windows_cert_as_pyhanko_cert(dotnet_cert)

        rsa = RSACertificateExtensions.GetRSAPrivateKey(dotnet_cert)

        if rsa is None:
            try:
                rsa = dotnet_cert.PrivateKey
            except Exception:
                rsa = None

        if rsa is None:
            raise RuntimeError(
                "This script supports RSA certificates only. "
                "The selected certificate does not expose an accessible RSA private key."
            )

        self.rsa = rsa

        try:
            self.signature_size = int(rsa.KeySize / 8)
        except Exception:
            self.signature_size = 256

        super().__init__(
            signing_cert=signing_cert,
            cert_registry=cert_store,
            signature_mechanism=algos.SignedDigestAlgorithm(
                {"algorithm": "rsassa_pkcs1v15"}
            ),
        )

    async def async_sign_raw(
        self,
        data: bytes,
        digest_algorithm: str,
        dry_run=False,
    ) -> bytes:
        if dry_run:
            return bytes(self.signature_size)

        digest_algorithm = digest_algorithm.lower()

        if digest_algorithm == "sha1":
            hash_alg = HashAlgorithmName.SHA1
        elif digest_algorithm == "sha256":
            hash_alg = HashAlgorithmName.SHA256
        elif digest_algorithm == "sha384":
            hash_alg = HashAlgorithmName.SHA384
        elif digest_algorithm == "sha512":
            hash_alg = HashAlgorithmName.SHA512
        else:
            raise RuntimeError(f"Unsupported digest algorithm: {digest_algorithm}")

        dotnet_data = bytes_to_dotnet_byte_array(data)

        try:
            signature = self.rsa.SignData(
                dotnet_data,
                hash_alg,
                RSASignaturePadding.Pkcs1,
            )
            return bytes(signature)

        except Exception as sign_error:
            raise RuntimeError(
                "Windows RSA signing failed. "
                "The certificate/private key may not support this operation. "
                f"Original error: {sign_error}"
            )


def parse_box(box_text: str):
    parts = [float(p.strip()) for p in box_text.split(",")]

    if len(parts) != 4:
        raise ValueError("Box must be x1,y1,x2,y2")

    x1, y1, x2, y2 = parts

    if x2 <= x1 or y2 <= y1:
        raise ValueError("Invalid box. x2/y2 must be greater than x1/y1.")

    return x1, y1, x2, y2


def load_font(size: int):
    possible_fonts = [
        r"C:\Windows\Fonts\arial.ttf",
        r"C:\Windows\Fonts\calibri.ttf",
        r"C:\Windows\Fonts\times.ttf",
    ]

    for font_path in possible_fonts:
        if Path(font_path).exists():
            return ImageFont.truetype(font_path, size=size)

    return ImageFont.load_default()


def load_signature_text_font(size: int):
    possible_fonts = [
        r"C:\Windows\Fonts\arialbi.ttf",
        r"C:\Windows\Fonts\calibriz.ttf",
        r"C:\Windows\Fonts\arialbd.ttf",
        r"C:\Windows\Fonts\calibrib.ttf",
    ]

    for font_path in possible_fonts:
        if Path(font_path).exists():
            return ImageFont.truetype(font_path, size=size)

    return load_font(size)


def make_black_ink_image(image):
    """
    Convert an artwork image to black ink while keeping transparency.

    Transparent PNGs keep their alpha channel. Opaque scans/photos infer alpha
    from brightness so white paper disappears and darker strokes become black.
    """
    rgba = image.convert("RGBA")
    source_alpha = rgba.getchannel("A")

    if source_alpha.getextrema()[0] < 255:
        ink_alpha = source_alpha
    else:
        luminance = rgba.convert("L")
        ink_alpha = luminance.point(
            lambda px: 0 if px > 245 else min(255, int((255 - px) * 2.2))
        )

    black = Image.new("RGBA", rgba.size, (0, 0, 0, 0))
    black.putalpha(ink_alpha)
    return black


def create_signature_appearance_image(
    signature_image_path: str,
    signature_text: str,
    output_png_path: str,
    logo_image_path: str | None = None,
    width_px: int = 750,
    height_px: int = 190,
):
    """
    Creates a transparent PNG like:

        [signature image]   [logo]   Digitally signed by
                                      Gomez Rudyard Ramos
                                      Date: 2026-05-26
                                      10:55+8:00

    This PNG is used as the visible signature appearance.
    """
    output_path = Path(output_png_path)
    sig_path = Path(signature_image_path)

    if not sig_path.exists():
        raise RuntimeError(f"Signature image not found: {sig_path}")

    canvas = Image.new("RGBA", (width_px, height_px), (255, 255, 255, 0))

    sig_img = make_black_ink_image(Image.open(sig_path))
    draw = ImageDraw.Draw(canvas)
    lines = signature_text.replace("\\n", "\n").splitlines()
    logo_path = Path(logo_image_path) if logo_image_path else None

    if logo_path:
        if not logo_path.exists():
            raise RuntimeError(f"Logo image not found: {logo_path}")

        # Sample-style layout: black signature, logo, then black text.
        font = load_signature_text_font(31)
        text_x = int(width_px * 0.51)
        text_y = 22
        line_gap = 34

        logo_img = Image.open(logo_path).convert("RGBA")
        logo_img.thumbnail(
            (int(width_px * 0.12), int(height_px * 0.64)),
            Image.LANCZOS,
        )
        logo_x = int(width_px * 0.38)
        logo_y = int((height_px - logo_img.height) / 2)
        canvas.alpha_composite(logo_img, (logo_x, logo_y))

        sig_img.thumbnail(
            (int(width_px * 0.40), int(height_px * 0.90)),
            Image.LANCZOS,
        )
        signature_logo_gap = 10
        sig_x = max(8, logo_x - sig_img.width - signature_logo_gap)
        sig_y = int((height_px - sig_img.height) / 2)
        canvas.alpha_composite(sig_img, (sig_x, sig_y))

        for i, line in enumerate(lines):
            draw.text(
                (text_x, text_y + i * line_gap),
                line,
                fill=(0, 0, 0, 255),
                font=font,
            )

    else:
        # Original no-logo layout, with the signature rendered as black ink.
        left_area_width = int(width_px * 0.38)
        left_area_height = int(height_px * 0.80)
        sig_img.thumbnail((left_area_width, left_area_height), Image.LANCZOS)

        sig_x = 10
        sig_y = int((height_px - sig_img.height) / 2)
        canvas.alpha_composite(sig_img, (sig_x, sig_y))

        font = load_signature_text_font(34)
        text_x = int(width_px * 0.40)
        text_y = 30
        line_gap = 38

        for i, line in enumerate(lines):
            draw.text(
                (text_x, text_y + i * line_gap),
                line,
                fill=(0, 0, 0, 255),
                font=font,
            )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    canvas.save(output_path)


def build_stamp_style(appearance_png_path: str):
    """
    Uses the generated appearance image as the visible digital signature.

    border_width=0 removes the visible rectangle/border around the signature.
    """
    try:
        return TextStampStyle(
            stamp_text="",
            background=PdfImage(appearance_png_path),
            border_width=0,
        )
    except TypeError:
        # Fallback for older pyHanko versions where border_width is not
        # accepted in the constructor.
        style = TextStampStyle(
            stamp_text="",
            background=PdfImage(appearance_png_path),
        )
        style.border_width = 0
        return style


def sign_one_pdf(
    input_pdf: Path,
    output_pdf: Path,
    signer: WindowsStoreRSASigner,
    page_index: int,
    box,
    field_name: str,
    appearance_png_path: str,
    reason: str | None,
    location: str | None,
):
    stamp_style = build_stamp_style(appearance_png_path)

    with input_pdf.open("rb") as inf:
        writer = IncrementalPdfFileWriter(inf, strict=False)

        fields.append_signature_field(
            writer,
            sig_field_spec=fields.SigFieldSpec(
                sig_field_name=field_name,
                on_page=page_index,
                box=box,
            ),
        )

        metadata = signers.PdfSignatureMetadata(
            field_name=field_name,
            reason=reason,
            location=location,
            md_algorithm="sha256",
        )

        pdf_signer = signers.PdfSigner(
            signature_meta=metadata,
            signer=signer,
            stamp_style=stamp_style,
        )

        output_pdf.parent.mkdir(parents=True, exist_ok=True)

        with output_pdf.open("wb") as outf:
            pdf_signer.sign_pdf(writer, output=outf)


def batch_sign(
    input_folder: Path,
    output_folder: Path,
    thumbprint: str,
    store_location: str,
    page_number: int,
    box,
    signature_image: str,
    signature_text: str,
    reason: str | None,
    location: str | None,
    field_prefix: str,
    logo_image: str | None = None,
):
    if not input_folder.exists():
        raise RuntimeError(f"Input folder does not exist: {input_folder}")

    if not input_folder.is_dir():
        raise RuntimeError(f"Input path is not a folder: {input_folder}")

    dotnet_cert = find_certificate_by_thumbprint(
        thumbprint=thumbprint,
        store_location=store_location,
    )

    signer = WindowsStoreRSASigner(dotnet_cert)

    page_index = page_number - 1

    if page_index < 0:
        raise RuntimeError("Page number must be 1 or higher.")

    pdf_files = sorted(input_folder.glob("*.pdf"))

    if not pdf_files:
        raise RuntimeError(f"No PDF files found in: {input_folder}")

    temp_dir = Path(tempfile.gettempdir())
    appearance_png_path = temp_dir / "pyhanko_visible_signature_appearance.png"

    create_signature_appearance_image(
        signature_image_path=signature_image,
        signature_text=signature_text,
        output_png_path=str(appearance_png_path),
        logo_image_path=logo_image,
    )

    print(f"Found {len(pdf_files)} PDF file(s).")
    print(f"Using certificate: {dotnet_cert.Subject}")
    print(f"Using visible signature appearance: {appearance_png_path}")
    print(f"Saving signed PDFs to: {output_folder}")
    print("")

    for index, pdf_path in enumerate(pdf_files, start=1):
        output_pdf = output_folder / f"{pdf_path.stem}_signed.pdf"
        field_name = f"{field_prefix}_{index}"

        print(f"[{index}/{len(pdf_files)}] Signing: {pdf_path.name}")

        try:
            sign_one_pdf(
                input_pdf=pdf_path,
                output_pdf=output_pdf,
                signer=signer,
                page_index=page_index,
                box=box,
                field_name=field_name,
                appearance_png_path=str(appearance_png_path),
                reason=reason,
                location=location,
            )

            print(f"    Saved: {output_pdf}")

        except Exception as e:
            print(f"    ERROR signing {pdf_path.name}: {e}")

    print("")
    print("Done.")


def main():
    parser = argparse.ArgumentParser(
        description="Batch sign PDF files using a Windows Certificate Store certificate."
    )

    parser.add_argument(
        "--input-folder",
        required=True,
        help="Folder containing PDF files to sign.",
    )

    parser.add_argument(
        "--output-folder",
        required=True,
        help="Folder where signed PDF files will be saved.",
    )

    parser.add_argument(
        "--thumbprint",
        required=True,
        help="Certificate thumbprint from Windows Certificate Store.",
    )

    parser.add_argument(
        "--store-location",
        default="CurrentUser",
        choices=["CurrentUser", "LocalMachine"],
        help="Windows certificate store location. Default: CurrentUser.",
    )

    parser.add_argument(
        "--page",
        type=int,
        default=1,
        help="Page number where the visible signature will appear. Default: 1.",
    )

    parser.add_argument(
        "--box",
        default="225,95,390,150",
        help="Signature rectangle in PDF points: x1,y1,x2,y2",
    )

    parser.add_argument(
        "--image",
        required=True,
        help="Handwritten signature image, for example: G:\\My Drive\\gmz.png",
    )

    parser.add_argument(
        "--logo",
        default=None,
        help="Optional logo image to place in the visible signature.",
    )

    parser.add_argument(
        "--text",
        default=(
            "Digitally signed by\n"
            "Gomez Rudyard Ramos\n"
            "Date: 2026-05-26\n"
            "10:55+8:00"
        ),
        help="Text displayed on the right side of the visible signature.",
    )

    parser.add_argument(
        "--reason",
        default="Approved",
        help="PDF signature reason metadata.",
    )

    parser.add_argument(
        "--location",
        default="Philippines",
        help="PDF signature location metadata.",
    )

    parser.add_argument(
        "--field-prefix",
        default="Signature",
        help="Prefix for PDF signature field names.",
    )

    args = parser.parse_args()

    batch_sign(
        input_folder=Path(args.input_folder),
        output_folder=Path(args.output_folder),
        thumbprint=args.thumbprint,
        store_location=args.store_location,
        page_number=args.page,
        box=parse_box(args.box),
        signature_image=args.image,
        signature_text=args.text,
        logo_image=args.logo,
        reason=args.reason,
        location=args.location,
        field_prefix=args.field_prefix,
    )


if __name__ == "__main__":
    main()
