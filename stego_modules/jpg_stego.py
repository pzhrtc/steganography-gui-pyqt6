from PIL import Image
import os
from crypto.crypto_utils import encrypt_bytes, decrypt_bytes


class JPGStego:
    MARKER = b"STEGO_JPG_V1"
    SIZE_BYTES = 4  # 32-bit payload size
    BITS_PER_PIXEL = 3  # Using R, G, B LSBs

    def _bytes_to_bits(self, data: bytes):
        """Convert bytes to a list of bits."""
        bits = []
        for byte in data:
            for i in range(8):
                bits.append((byte >> (7 - i)) & 1)
        return bits

    def _bits_to_bytes(self, bits):
        """Convert list of bits back to bytes."""
        out = bytearray()
        for b in range(0, len(bits), 8):
            byte = 0
            for i in range(8):
                byte = (byte << 1) | bits[b + i]
            out.append(byte)
        return bytes(out)

    def hide(self, carrier_img, secret_txt, output_img, password=None):
        try:
            img = Image.open(carrier_img)
            img = img.convert("RGB")
            pixels = img.load()

            # Read secret file
            with open(secret_txt, "rb") as f:
                secret_data = f.read()

            # Encrypt optional
            if password:
                secret_data = encrypt_bytes(secret_data, password)

            payload = self.MARKER + \
                      len(secret_data).to_bytes(self.SIZE_BYTES, "big") + \
                      secret_data

            bits = self._bytes_to_bits(payload)
            required_pixels = len(bits) // self.BITS_PER_PIXEL + 1

            if required_pixels > img.width * img.height:
                print("[JPGStego] Image too small for payload.")
                return False

            bit_index = 0
            for y in range(img.height):
                for x in range(img.width):
                    if bit_index >= len(bits):
                        break

                    r, g, b = pixels[x, y]
                    rgb = [r, g, b]

                    for i in range(3):
                        if bit_index < len(bits):
                            rgb[i] = (rgb[i] & 0xFE) | bits[bit_index]
                            bit_index += 1

                    pixels[x, y] = tuple(rgb)

                if bit_index >= len(bits):
                    break

            img.save(output_img)
            return True

        except Exception as e:
            print(f"[JPGStego] Hide failed: {e}")
            return False

    def extract(self, stego_img, output_txt, password=None):
        try:
            img = Image.open(stego_img)
            img = img.convert("RGB")
            pixels = img.load()

            bits = []

            # Extract bits from the entire image
            for y in range(img.height):
                for x in range(img.width):
                    r, g, b = pixels[x, y]
                    bits.append(r & 1)
                    bits.append(g & 1)
                    bits.append(b & 1)

            # Convert to bytes progressively to find marker
            data = self._bits_to_bytes(bits)

            idx = data.find(self.MARKER)
            if idx == -1:
                print("[JPGStego] Marker not found.")
                return False

            size_start = idx + len(self.MARKER)
            size_end = size_start + self.SIZE_BYTES
            payload_size = int.from_bytes(data[size_start:size_end], "big")

            payload_start = size_end
            payload_end = payload_start + payload_size

            payload = data[payload_start:payload_end]

            # Decrypt optional
            if password:
                try:
                    payload = decrypt_bytes(payload, password)
                except Exception:
                    print("[JPGStego] Wrong password or corrupt payload.")
                    return False

            with open(output_txt, "wb") as f:
                f.write(payload)

            return True

        except Exception as e:
            print(f"[JPGStego] Extract failed: {e}")
            return False
