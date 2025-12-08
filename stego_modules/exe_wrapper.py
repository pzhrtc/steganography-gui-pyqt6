# stego_wrappers/exe_wrapper.py
from pathlib import Path
from exe_stego import SteganoEXE

class ExeStego:
    def __init__(self):
        self._impl = SteganoEXE()

    def hide(self, carrier_path, secret_path, output_path, password=None):
        return self._impl.hide_file(carrier_path, secret_path, output_path, password)

    def extract(self, stego_exe_path, output_path, password=None):
        return self._impl.extract_file(stego_exe_path, output_path, password)
