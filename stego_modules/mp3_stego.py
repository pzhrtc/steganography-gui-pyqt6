# stego_modules/mp3_stego.py
from mutagen.id3 import ID3, ID3NoHeaderError, GEOB, Frames, Encoding
from mutagen.mp3 import MP3
from crypto.crypto_utils import encrypt_bytes, decrypt_bytes

class MP3Stego:
    """
    Store a binary payload inside an MP3 file using an ID3v2 GEOB (General Encapsulated Object) frame.
    The GEOB frame allows arbitrary binary data with a MIME type and description.
    """

    GEOB_DESC = "stegano_payload"  # description used to find our frame

    def hide(self, carrier_mp3: str, secret_txt: str, output_mp3: str, password: str = None) -> bool:
        try:
            # Read secret
            with open(secret_txt, "rb") as f:
                payload = f.read()

            # Optional encryption
            if password:
                payload = encrypt_bytes(payload, password)

            # Ensure we have ID3 tag (mutagen will add one if missing when saving)
            try:
                tags = ID3(carrier_mp3)
            except ID3NoHeaderError:
                tags = ID3()

            # Create GEOB frame with MIME application/octet-stream and our description
            geob = GEOB(
                encoding=Encoding.UTF8,
                mime='application/octet-stream',
                desc=self.GEOB_DESC,
                data=payload
            )

            # Remove existing GEOB frames with the same description (clean up)
            to_remove = [k for k, v in tags.items() if k.startswith("GEOB") and getattr(v, "desc", "") == self.GEOB_DESC]
            for k in to_remove:
                del tags[k]

            # Add the new GEOB
            tags.add(geob)

            # Save to a new file: mutagen's save requires a file on disk; copy original MP3 first
            # We'll copy the file bytes, then write tags to the copied file.
            with open(carrier_mp3, "rb") as src, open(output_mp3, "wb") as dst:
                dst.write(src.read())

            tags.save(output_mp3)
            return True

        except Exception as e:
            print(f"[MP3Stego] Hide failed: {e}")
            return False

    def extract(self, stego_mp3: str, output_txt: str, password: str = None) -> bool:
        try:
            try:
                tags = ID3(stego_mp3)
            except ID3NoHeaderError:
                print("[MP3Stego] No ID3 tag present.")
                return False

            # Find GEOB frame with our description
            geob_frame = None
            for frame in tags.getall("GEOB"):
                # GEOB.desc is a python str
                if getattr(frame, "desc", "") == self.GEOB_DESC:
                    geob_frame = frame
                    break

            if geob_frame is None:
                print("[MP3Stego] No stego GEOB frame found.")
                return False

            payload = geob_frame.data

            # Decrypt if requested
            if password:
                try:
                    payload = decrypt_bytes(payload, password)
                except Exception:
                    print("[MP3Stego] Decryption failed (wrong password or corrupt payload).")
                    return False

            # Write extracted secret
            with open(output_txt, "wb") as f:
                f.write(payload)

            return True

        except Exception as e:
            print(f"[MP3Stego] Extract failed: {e}")
            return False
