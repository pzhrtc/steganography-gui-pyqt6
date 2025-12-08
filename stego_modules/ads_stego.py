import os
import platform

from crypto.crypto_utils import encrypt_bytes, decrypt_bytes

class ADSStego:
    """
    Write/read binary payloads to/from NTFS Alternate Data Streams (ADS).
    Only supported on Windows/NTFS. Optional AES encryption via crypto_utils.
    """

    def is_windows_ntfs(self, host_path: str) -> bool:
        # Quick OS check
        if os.name != "nt":
            return False
        # Basic check: path must exist and be on an NTFS filesystem
        try:
            if not os.path.exists(host_path):
                # If host doesn't exist yet, check parent directory
                host_path = os.path.dirname(host_path) or "."
            # Use os.statvfs on POSIX doesn't apply; on Windows rely on drive formatting via os.stat
            # We'll assume Windows + existing path generally indicates NTFS in typical cases.
            return True
        except Exception:
            return False

    def hide(self, host_file: str, secret_file: str, stream_name: str = "secret", password: str = None) -> bool:
        """
        Write secret_file bytes into host_file:stream_name optionally encrypted.
        - host_file: path to the host file (must be on NTFS)
        - secret_file: path to the file to hide (binary)
        - stream_name: name of the ADS stream (no colon)
        """
        try:
            if os.name != "nt":
                raise EnvironmentError("ADS is supported only on Windows (NTFS).")

            if not os.path.exists(secret_file):
                raise FileNotFoundError(f"Secret file not found: {secret_file}")

            # Read secret bytes
            with open(secret_file, "rb") as sf:
                data = sf.read()

            # Optional encryption
            if password:
                data = encrypt_bytes(data, password)

            # Build ADS path
            # Example: C:\path\to\host.txt:streamname
            ads_path = f"{host_file}:{stream_name}"

            # Ensure host file exists (create an empty file if it doesn't)
            if not os.path.exists(host_file):
                # create an empty host file to attach ADS to
                open(host_file, "ab").close()

            # Write ADS
            with open(ads_path, "wb") as af:
                af.write(data)

            return True

        except Exception as e:
            # Let caller show message; include text for debugging in console
            print(f"[ADSStego] Hide error: {e}")
            return False

    def extract(self, host_file: str, stream_name: str, output_file: str, password: str = None) -> bool:
        """
        Read host_file:stream_name and write to output_file (optionally decrypting).
        """
        try:
            if os.name != "nt":
                raise EnvironmentError("ADS extraction is supported only on Windows (NTFS).")

            ads_path = f"{host_file}:{stream_name}"
            if not os.path.exists(ads_path):
                # If the host exists but stream doesn't, os.path.exists may return False.
                # Attempt to open to provide clearer error.
                try:
                    open(ads_path, "rb").close()
                except Exception:
                    print(f"[ADSStego] ADS not found: {ads_path}")
                    return False

            with open(ads_path, "rb") as af:
                data = af.read()

            # Optional decryption
            if password:
                try:
                    data = decrypt_bytes(data, password)
                except Exception as e:
                    print("[ADSStego] Decryption failed (wrong password or corrupt data).")
                    return False

            # Write extracted data
            with open(output_file, "wb") as out:
                out.write(data)

            return True

        except Exception as e:
            print(f"[ADSStego] Extract error: {e}")
            return False
