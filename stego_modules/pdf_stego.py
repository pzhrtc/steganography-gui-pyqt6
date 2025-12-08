import os
from crypto.crypto_utils import encrypt_bytes, decrypt_bytes

class PDFStego:
    """
    Hide and extract text files inside a PDF by appending encrypted payload 
    after the EOF marker using a unique identifier marker.
    """

    MARKER = b"STEGO_PDF_V1:"
    SIZE_BYTES = 8  # 8 bytes (64-bit) for payload size

    def hide(self, carrier_pdf, secret_txt, output_pdf, password=None):
        try:
            # Read carrier PDF
            with open(carrier_pdf, "rb") as f:
                pdf_data = f.read()

            # Read secret text file
            with open(secret_txt, "rb") as f:
                secret_data = f.read()

            # Optional encryption
            if password:
                secret_data = encrypt_bytes(secret_data, password)

            # Build the appended structure:
            # MARKER + [8-byte size] + PAYLOAD
            payload_size = len(secret_data).to_bytes(self.SIZE_BYTES, "big")
            appended = self.MARKER + payload_size + secret_data

            # Write new PDF
            with open(output_pdf, "wb") as f:
                f.write(pdf_data + appended)

            return True

        except Exception as e:
            print(f"[PDFStego] Hide failed: {e}")
            return False

    def extract(self, stego_pdf, output_txt, password=None):
        try:
            with open(stego_pdf, "rb") as f:
                data = f.read()

            # Find marker
            idx = data.find(self.MARKER)
            if idx == -1:
                print("[PDFStego] No hidden data found.")
                return False

            # Extract payload size
            size_start = idx + len(self.MARKER)
            size_end = size_start + self.SIZE_BYTES
            payload_size = int.from_bytes(data[size_start:size_end], "big")

            # Extract encrypted or raw payload
            payload = data[size_end:size_end + payload_size]

            # Decrypt if needed
            if password:
                try:
                    payload = decrypt_bytes(payload, password)
                except Exception:
                    print("[PDFStego] Wrong password or corrupt data.")
                    return False

            # Write extracted file
            with open(output_txt, "wb") as f:
                f.write(payload)

            return True

        except Exception as e:
            print(f"[PDFStego] Extract failed: {e}")
            return False
