import os
from pathlib import Path


from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QTabWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QFileDialog, QCheckBox, QMessageBox
)
from PyQt6.QtCore import Qt
from pathlib import Path



from stego_modules.exe_stego import SteganoEXE
from stego_modules.pdf_stego import PDFStego
from stego_modules.jpg_stego import JPGStego
from stego_modules.mp3_stego import MP3Stego
from stego_modules.ads_stego import ADSStego




class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SteganoSuite — PyQt6")
        self.setMinimumSize(800, 500)
        self._init_ui()

    def _init_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout()
        central.setLayout(layout)

        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)

        # Create tabs
        self.tabs.addTab(self._create_pdf_tab(), "PDF")
        self.tabs.addTab(self._create_jpg_tab(), "JPG")
        self.tabs.addTab(self._create_exe_tab(), "EXE")
        self.tabs.addTab(self._create_mp3_tab(), "MP3")
        self.tabs.addTab(self._create_ads_tab(), "ADS (Windows)")

    # ---------- Generic small helpers ----------
    def _file_select_row(self, label_text, line_edit):
        row = QWidget()
        h = QHBoxLayout()
        row.setLayout(h)
        h.addWidget(QLabel(label_text))
        h.addWidget(line_edit)
        btn = QPushButton("Browse")
        h.addWidget(btn)
        return row, btn

    # ---------- PDF tab (stub) ----------
    def _create_pdf_tab(self):
        tab = QWidget()
        v = QVBoxLayout()
        tab.setLayout(v)

        self.pdf_carrier = QLineEdit()
        row, btn = self._file_select_row("Carrier PDF:", self.pdf_carrier)
        btn.clicked.connect(lambda: self._browse_file(self.pdf_carrier, "PDF Files (*.pdf)"))
        v.addWidget(row)

        self.pdf_secret = QLineEdit()
        row, btn = self._file_select_row("Text to hide (.txt):", self.pdf_secret)
        btn.clicked.connect(lambda: self._browse_file(self.pdf_secret, "Text Files (*.txt)"))
        v.addWidget(row)

        self.pdf_output = QLineEdit()
        row, btn = self._file_select_row("Output PDF:", self.pdf_output)
        btn.clicked.connect(lambda: self._save_file(self.pdf_output, "PDF Files (*.pdf)"))
        v.addWidget(row)

        self.pdf_encrypt_cb = QCheckBox("Encrypt payload with password")
        v.addWidget(self.pdf_encrypt_cb)
        self.pdf_password = QLineEdit()
        self.pdf_password.setPlaceholderText("Password (only used if encryption checked)")
        self.pdf_password.setEchoMode(QLineEdit.EchoMode.Password)
        v.addWidget(self.pdf_password)

        btns = QHBoxLayout()
        hide_btn = QPushButton("Hide into PDF")
        extract_btn = QPushButton("Extract from PDF")
        hide_btn.clicked.connect(self._pdf_hide)
        extract_btn.clicked.connect(self._pdf_extract)
        btns.addWidget(hide_btn)
        btns.addWidget(extract_btn)
        v.addLayout(btns)

        v.addStretch()
        return tab

    # ---------- JPG tab (stub) ----------
    def _create_jpg_tab(self):
        tab = QWidget()
        v = QVBoxLayout()
        tab.setLayout(v)

        self.jpg_carrier = QLineEdit()
        row, btn = self._file_select_row("Carrier JPG:", self.jpg_carrier)
        btn.clicked.connect(lambda: self._browse_file(self.jpg_carrier, "Images (*.png *.jpg *.jpeg)"))
        v.addWidget(row)

        self.jpg_secret = QLineEdit()
        row, btn = self._file_select_row("Text to hide (.txt):", self.jpg_secret)
        btn.clicked.connect(lambda: self._browse_file(self.jpg_secret, "Text Files (*.txt)"))
        v.addWidget(row)

        self.jpg_output = QLineEdit()
        row, btn = self._file_select_row("Output JPG:", self.jpg_output)
        btn.clicked.connect(lambda: self._save_file(self.jpg_output, "Images (*.jpg *.png)"))
        v.addWidget(row)

        self.jpg_encrypt_cb = QCheckBox("Encrypt payload with password")
        v.addWidget(self.jpg_encrypt_cb)
        self.jpg_password = QLineEdit()
        self.jpg_password.setEchoMode(QLineEdit.EchoMode.Password)
        v.addWidget(self.jpg_password)

        btns = QHBoxLayout()
        hide_btn = QPushButton("Hide into JPG")
        extract_btn = QPushButton("Extract from JPG")
        hide_btn.clicked.connect(self._jpg_hide)
        extract_btn.clicked.connect(self._jpg_extract)
        btns.addWidget(hide_btn)
        btns.addWidget(extract_btn)
        v.addLayout(btns)

        v.addStretch()
        return tab

    # ---------- EXE tab (implemented using your module) ----------
    def _create_exe_tab(self):
        tab = QWidget()
        v = QVBoxLayout()
        tab.setLayout(v)

        self.exe_carrier = QLineEdit()
        row, btn = self._file_select_row("Carrier EXE:", self.exe_carrier)
        btn.clicked.connect(lambda: self._browse_file(self.exe_carrier, "Executables (*.exe)"))
        v.addWidget(row)

        self.exe_secret = QLineEdit()
        row, btn = self._file_select_row("Text to hide (.txt):", self.exe_secret)
        btn.clicked.connect(lambda: self._browse_file(self.exe_secret, "Text Files (*.txt)"))
        v.addWidget(row)

        self.exe_output = QLineEdit()
        row, btn = self._file_select_row("Output EXE:", self.exe_output)
        btn.clicked.connect(lambda: self._save_file(self.exe_output, "Executables (*.exe)"))
        v.addWidget(row)

        self.exe_encrypt_cb = QCheckBox("Encrypt payload with password")
        v.addWidget(self.exe_encrypt_cb)
        self.exe_password = QLineEdit()
        self.exe_password.setEchoMode(QLineEdit.EchoMode.Password)
        v.addWidget(self.exe_password)

        btns = QHBoxLayout()
        hide_btn = QPushButton("Hide into EXE")
        extract_btn = QPushButton("Extract from EXE")
        hide_btn.clicked.connect(self._exe_hide)
        extract_btn.clicked.connect(self._exe_extract)
        btns.addWidget(hide_btn)
        btns.addWidget(extract_btn)
        v.addLayout(btns)

        v.addStretch()
        return tab

    # ---------- MP3 tab (stub) ----------
    def _create_mp3_tab(self):
        tab = QWidget()
        v = QVBoxLayout()
        tab.setLayout(v)

        self.mp3_carrier = QLineEdit()
        row, btn = self._file_select_row("Carrier MP3:", self.mp3_carrier)
        btn.clicked.connect(lambda: self._browse_file(self.mp3_carrier, "Audio Files (*.mp3)"))
        v.addWidget(row)

        self.mp3_secret = QLineEdit()
        row, btn = self._file_select_row("Text to hide (.txt):", self.mp3_secret)
        btn.clicked.connect(lambda: self._browse_file(self.mp3_secret, "Text Files (*.txt)"))
        v.addWidget(row)

        self.mp3_output = QLineEdit()
        row, btn = self._file_select_row("Output MP3:", self.mp3_output)
        btn.clicked.connect(lambda: self._save_file(self.mp3_output, "Audio Files (*.mp3)"))
        v.addWidget(row)

        self.mp3_encrypt_cb = QCheckBox("Encrypt payload with password")
        v.addWidget(self.mp3_encrypt_cb)
        self.mp3_password = QLineEdit()
        self.mp3_password.setEchoMode(QLineEdit.EchoMode.Password)
        v.addWidget(self.mp3_password)

        btns = QHBoxLayout()
        hide_btn = QPushButton("Hide into MP3")
        extract_btn = QPushButton("Extract from MP3")
        hide_btn.clicked.connect(self._mp3_hide)
        extract_btn.clicked.connect(self._mp3_extract)
        btns.addWidget(hide_btn)
        btns.addWidget(extract_btn)
        v.addLayout(btns)

        v.addStretch()
        return tab

    # ---------- ADS tab (Windows-only) ----------
    def _create_ads_tab(self):
        tab = QWidget()
        v = QVBoxLayout()
        tab.setLayout(v)

        self.ads_host = QLineEdit()
        row, btn = self._file_select_row("Host file (will store ADS):", self.ads_host)
        btn.clicked.connect(lambda: self._browse_file(self.ads_host, "All Files (*)"))
        v.addWidget(row)

        self.ads_secret = QLineEdit()
        row, btn = self._file_select_row("Text to hide (.txt):", self.ads_secret)
        btn.clicked.connect(lambda: self._browse_file(self.ads_secret, "Text Files (*.txt)"))
        v.addWidget(row)

        self.ads_stream_name = QLineEdit("secret_stream")
        row = QWidget()
        h = QHBoxLayout()
        row.setLayout(h)
        h.addWidget(QLabel("ADS stream name:"))
        h.addWidget(self.ads_stream_name)
        v.addWidget(row)

        self.ads_encrypt_cb = QCheckBox("Encrypt payload with password")
        v.addWidget(self.ads_encrypt_cb)
        self.ads_password = QLineEdit()
        self.ads_password.setEchoMode(QLineEdit.EchoMode.Password)
        v.addWidget(self.ads_password)

        btns = QHBoxLayout()
        hide_btn = QPushButton("Hide into ADS")
        extract_btn = QPushButton("Extract from ADS")
        hide_btn.clicked.connect(self._ads_hide)
        extract_btn.clicked.connect(self._ads_extract)
        btns.addWidget(hide_btn)
        btns.addWidget(extract_btn)
        v.addLayout(btns)

        v.addStretch()
        return tab

    # ---------- File dialog helpers ----------
    def _browse_file(self, line_edit: QLineEdit, filter_str: str):
        path, _ = QFileDialog.getOpenFileName(self, "Select file", str(Path.home()), filter_str)
        if path:
            line_edit.setText(path)

    def _save_file(self, line_edit: QLineEdit, filter_str: str):
        path, _ = QFileDialog.getSaveFileName(self, "Save file", str(Path.home()), filter_str)
        if path:
            line_edit.setText(path)

    # ---------- EXE handlers (call into SteganoEXE) ----------
    def _exe_hide(self):
        carrier = self.exe_carrier.text().strip()
        secret = self.exe_secret.text().strip()
        output = self.exe_output.text().strip()
        pwd = self.exe_password.text().strip() if self.exe_encrypt_cb.isChecked() else None

        if not (carrier and secret and output):
            QMessageBox.warning(self, "Missing input", "Please specify carrier, secret and output files.")
            return

        steg = SteganoEXE()
        success = steg.hide_file(carrier, secret, output, password=pwd)
        if success:
            QMessageBox.information(self, "Done", "Hidden file successfully into EXE.")
        else:
            QMessageBox.critical(self, "Failed", "Failed to hide file. See console for details.")

    def _exe_extract(self):
        stego = self.exe_carrier.text().strip()
        out = self.exe_output.text().strip() or QFileDialog.getSaveFileName(self, "Save secret as", str(Path.home()), "All Files (*)")[0]
        pwd = self.exe_password.text().strip() if self.exe_encrypt_cb.isChecked() else None

        if not stego:
            QMessageBox.warning(self, "Missing input", "Please specify the stego executable in 'Carrier EXE' field.")
            return
        if not out:
            QMessageBox.warning(self, "Missing output", "Please provide an output filename for the extracted secret.")
            return

        steg = SteganoEXE()
        success = steg.extract_file(stego, out, password=pwd)
        if success:
            QMessageBox.information(self, "Done", f"Extracted secret to: {out}")
        else:
            QMessageBox.critical(self, "Failed", "Failed to extract file. See console for details.")










    # fun parts below
    # ---------- PDF / JPG / MP3 / ADS handlers (stubs for now) ----------
    def _pdf_hide(self):
        carrier = self.pdf_carrier.text().strip()
        secret = self.pdf_secret.text().strip()
        output = self.pdf_output.text().strip()
        password = self.pdf_password.text().strip() if self.pdf_encrypt_cb.isChecked() else None

        if not (carrier and secret and output):
            QMessageBox.warning(self, "Missing input", "Please provide carrier PDF, secret text, and output PDF.")
            return

        steg = PDFStego()
        success = steg.hide(carrier, secret, output, password)

        if success:
            QMessageBox.information(self, "Success", "Text hidden inside PDF successfully.")
        else:
            QMessageBox.critical(self, "Error", "Failed to hide data inside PDF.")

    
    def _pdf_extract(self):
        carrier = self.pdf_carrier.text().strip()
        output = self.pdf_output.text().strip()
        password = self.pdf_password.text().strip() if self.pdf_encrypt_cb.isChecked() else None

        if not (carrier and output):
            QMessageBox.warning(self, "Missing input", "Please provide the stego PDF and output text file.")
            return

        steg = PDFStego()
        success = steg.extract(carrier, output, password)

        if success:
            QMessageBox.information(self, "Success", f"Extracted text saved to: {output}")
        else:
            QMessageBox.critical(self, "Error", "Extraction failed. Wrong password or no data found.")

        #hehehehehhehehehe it works :)
    










    # ---------- JPG handlers ----------
    # LSB-based stego for JPG images
    
    def _jpg_hide(self):
        carrier = self.jpg_carrier.text().strip()
        secret = self.jpg_secret.text().strip()
        output = self.jpg_output.text().strip()
        password = self.jpg_password.text().strip() if self.jpg_encrypt_cb.isChecked() else None

        if not (carrier and secret and output):
            QMessageBox.warning(self, "Missing input", "Please provide carrier JPG, secret file, and output JPG.")
            return

        steg = JPGStego()
        success = steg.hide(carrier, secret, output, password)

        if success:
            QMessageBox.information(self, "Success", "Text hidden inside JPG successfully.")
        else:
            QMessageBox.critical(self, "Error", "Failed to hide text inside JPG. Image may be too small.")


    def _jpg_extract(self):
        carrier = self.jpg_carrier.text().strip()
        output = self.jpg_output.text().strip()
        password = self.jpg_password.text().strip() if self.jpg_encrypt_cb.isChecked() else None

        if not (carrier and output):
            QMessageBox.warning(self, "Missing input", "Please provide stego JPG and output text file.")
            return

        steg = JPGStego()
        success = steg.extract(carrier, output, password)

        if success:
            QMessageBox.information(self, "Success", f"Extracted text saved to: {output}")
        else:
            QMessageBox.critical(self, "Error", "Failed to extract data from JPG.")









    # ---------- MP3 handlers (ID3v2 GEOB stego) ----------
    # LSB-based stego for MP3 files using ID3v2 GEOB frames
    
    def _mp3_hide(self):
        carrier = self.mp3_carrier.text().strip()
        secret = self.mp3_secret.text().strip()
        output = self.mp3_output.text().strip()
        password = self.mp3_password.text().strip() if self.mp3_encrypt_cb.isChecked() else None

        if not (carrier and secret and output):
            QMessageBox.warning(self, "Missing input", "Please provide carrier MP3, secret file, and output MP3.")
            return

        steg = MP3Stego()
        success = steg.hide(carrier, secret, output, password)

        if success:
            QMessageBox.information(self, "Success", "Text hidden inside MP3 successfully (ID3v2 GEOB).")
        else:
            QMessageBox.critical(self, "Error", "Failed to hide text inside MP3.")


    
    def _mp3_extract(self):
        carrier = self.mp3_carrier.text().strip()
        output = self.mp3_output.text().strip()
        password = self.mp3_password.text().strip() if self.mp3_encrypt_cb.isChecked() else None

        if not (carrier and output):
            QMessageBox.warning(self, "Missing input", "Please provide stego MP3 and output text file.")
            return

        steg = MP3Stego()
        success = steg.extract(carrier, output, password)

        if success:
            QMessageBox.information(self, "Success", f"Extracted text saved to: {output}")
        else:
            QMessageBox.critical(self, "Error", "Failed to extract data from MP3.")










    def _ads_hide(self):
        host = self.ads_host.text().strip()
        secret = self.ads_secret.text().strip()
        stream = self.ads_stream_name.text().strip() or "secret_stream"
        pwd = self.ads_password.text().strip() if self.ads_encrypt_cb.isChecked() else None

        if not (host and secret):
            QMessageBox.warning(self, "Missing input", "Please specify host file and secret .txt file.")
            return

        stego = ADSStego()
        # Basic OS check - give a friendly message to user
        if os.name != "nt":
            QMessageBox.critical(self, "Not supported", "ADS is only supported on Windows NTFS.")
            return

        success = stego.hide(host, secret, stream, password=pwd)
        if success:
            QMessageBox.information(self, "Done", f"Written ADS to {host}:{stream}\n(Works only on NTFS/Windows)")
        else:
            QMessageBox.critical(self, "Error", "ADS write failed. See console for details.")

    def _ads_extract(self):
        host = self.ads_host.text().strip()
        stream = self.ads_stream_name.text().strip() or "secret_stream"
        out, _ = QFileDialog.getSaveFileName(self, "Save extracted secret", str(Path.home()), "All Files (*)")
        pwd = self.ads_password.text().strip() if self.ads_encrypt_cb.isChecked() else None

        if not (host and stream and out):
            QMessageBox.warning(self, "Missing input", "Please specify host, stream name and output file.")
            return

        if os.name != "nt":
            QMessageBox.critical(self, "Not supported", "ADS extraction is only supported on Windows NTFS.")
            return

        stego = ADSStego()
        success = stego.extract(host, stream, out, password=pwd)
        if success:
            QMessageBox.information(self, "Done", f"Extracted ADS stream saved to: {out}")
        else:
            QMessageBox.critical(self, "Error", "ADS extract failed. See console for details.")
