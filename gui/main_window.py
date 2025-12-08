import os
from pathlib import Path

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QTabWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QFileDialog, QCheckBox, QMessageBox, QComboBox, QTextEdit
)
from PyQt6.QtCore import Qt

from stego_modules.exe_stego import SteganoEXE
from stego_modules.pdf_stego import PDFStego
from stego_modules.jpg_stego import JPGStego
from stego_modules.mp3_stego import MP3Stego
from stego_modules.ads_stego import ADSStego


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Stegano - PyQt6")
        self.setMinimumSize(880, 560)
        self._init_ui()

    def _init_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout()
        central.setLayout(layout)

        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)

        # Create tabs (smart mode switching inside each)
        self.tabs.addTab(self._create_pdf_tab(), "PDF")
        self.tabs.addTab(self._create_jpg_tab(), "JPG")
        self.tabs.addTab(self._create_exe_tab(), "EXE")
        self.tabs.addTab(self._create_mp3_tab(), "MP3")
        self.tabs.addTab(self._create_ads_tab(), "ADS (Windows)")

    # ---------------- Generic helpers ----------------
    def _file_select_row(self, label_text, line_edit):
        row = QWidget()
        h = QHBoxLayout()
        row.setLayout(h)
        h.addWidget(QLabel(label_text))
        h.addWidget(line_edit)
        btn = QPushButton("Browse")
        h.addWidget(btn)
        return row, btn

    def _clear_layout(self, layout):
        # remove widgets from a layout
        while layout.count():
            item = layout.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()

    def _browse_file(self, line_edit: QLineEdit, filter_str: str):
        path, _ = QFileDialog.getOpenFileName(self, "Select file", str(Path.home()), filter_str)
        if path:
            line_edit.setText(path)

    def _save_file(self, line_edit: QLineEdit, filter_str: str):
        path, _ = QFileDialog.getSaveFileName(self, "Save file", str(Path.home()), filter_str)
        if path:
            line_edit.setText(path)

    # ---------------- PDF tab (dynamic) ----------------
    def _create_pdf_tab(self):
        tab = QWidget()
        v = QVBoxLayout(tab)

        # Mode selector
        top = QWidget(); top_l = QHBoxLayout(top)
        top.setLayout(top_l)
        top_l.addWidget(QLabel("Mode:"))
        self.pdf_mode = QComboBox()
        self.pdf_mode.addItems(["Hide", "Extract"])
        self.pdf_mode.currentTextChanged.connect(self._update_pdf_ui)
        top_l.addWidget(self.pdf_mode)
        top_l.addStretch()
        v.addWidget(top)

        # Dynamic area
        self.pdf_dynamic = QWidget()
        self.pdf_dyn_layout = QVBoxLayout(self.pdf_dynamic)
        self.pdf_dynamic.setLayout(self.pdf_dyn_layout)
        v.addWidget(self.pdf_dynamic)

        # Initial build
        self._build_pdf_hide_ui()
        return tab

    def _build_pdf_hide_ui(self):
        self._clear_layout(self.pdf_dyn_layout)

        # Carrier
        self.pdf_carrier = QLineEdit()
        row, btn = self._file_select_row("Carrier PDF:", self.pdf_carrier)
        btn.clicked.connect(lambda: self._browse_file(self.pdf_carrier, "PDF Files (*.pdf)"))
        self.pdf_dyn_layout.addWidget(row)

        # Secret
        self.pdf_secret = QLineEdit()
        row, btn = self._file_select_row("Secret TXT:", self.pdf_secret)
        btn.clicked.connect(lambda: self._browse_file(self.pdf_secret, "Text Files (*.txt)"))
        self.pdf_dyn_layout.addWidget(row)

        # Output
        self.pdf_output = QLineEdit()
        row, btn = self._file_select_row("Output PDF:", self.pdf_output)
        btn.clicked.connect(lambda: self._save_file(self.pdf_output, "PDF Files (*.pdf)"))
        self.pdf_dyn_layout.addWidget(row)

        # Encryption
        self.pdf_encrypt_cb = QCheckBox("Encrypt payload")
        self.pdf_password = QLineEdit()
        self.pdf_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.pdf_password.setPlaceholderText("Password (optional)")
        self.pdf_dyn_layout.addWidget(self.pdf_encrypt_cb)
        self.pdf_dyn_layout.addWidget(self.pdf_password)

        # Action button
        hide_btn = QPushButton("Hide into PDF")
        hide_btn.clicked.connect(self._pdf_hide)
        self.pdf_dyn_layout.addWidget(hide_btn)
        self.pdf_dyn_layout.addStretch()

    def _build_pdf_extract_ui(self):
        self._clear_layout(self.pdf_dyn_layout)

        # Stego PDF
        self.pdf_stego = QLineEdit()
        row, btn = self._file_select_row("Stego PDF:", self.pdf_stego)
        btn.clicked.connect(lambda: self._browse_file(self.pdf_stego, "PDF Files (*.pdf)"))
        self.pdf_dyn_layout.addWidget(row)

        # Output TXT
        self.pdf_output_extract = QLineEdit()
        row, btn = self._file_select_row("Extract to TXT:", self.pdf_output_extract)
        btn.clicked.connect(lambda: self._save_file(self.pdf_output_extract, "Text Files (*.txt)"))
        self.pdf_dyn_layout.addWidget(row)

        # Decrypt
        self.pdf_decrypt_cb = QCheckBox("Encrypted payload")
        self.pdf_decrypt_pass = QLineEdit()
        self.pdf_decrypt_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self.pdf_decrypt_pass.setPlaceholderText("Password")
        self.pdf_dyn_layout.addWidget(self.pdf_decrypt_cb)
        self.pdf_dyn_layout.addWidget(self.pdf_decrypt_pass)

        extract_btn = QPushButton("Extract from PDF")
        extract_btn.clicked.connect(self._pdf_extract)
        self.pdf_dyn_layout.addWidget(extract_btn)
        self.pdf_dyn_layout.addStretch()

    def _update_pdf_ui(self, _=None):
        if self.pdf_mode.currentText() == "Hide":
            self._build_pdf_hide_ui()
        else:
            self._build_pdf_extract_ui()

    # ---------------- JPG tab (dynamic) ----------------
    def _create_jpg_tab(self):
        tab = QWidget()
        v = QVBoxLayout(tab)

        top = QWidget(); top_l = QHBoxLayout(top)
        top.setLayout(top_l)
        top_l.addWidget(QLabel("Mode:"))
        self.jpg_mode = QComboBox()
        self.jpg_mode.addItems(["Hide", "Extract"])
        self.jpg_mode.currentTextChanged.connect(self._update_jpg_ui)
        top_l.addWidget(self.jpg_mode)
        top_l.addStretch()
        v.addWidget(top)

        self.jpg_dynamic = QWidget()
        self.jpg_dyn_layout = QVBoxLayout(self.jpg_dynamic)
        self.jpg_dynamic.setLayout(self.jpg_dyn_layout)
        v.addWidget(self.jpg_dynamic)

        self._build_jpg_hide_ui()
        return tab

    def _build_jpg_hide_ui(self):
        self._clear_layout(self.jpg_dyn_layout)

        self.jpg_carrier = QLineEdit()
        row, btn = self._file_select_row("Carrier JPG:", self.jpg_carrier)
        btn.clicked.connect(lambda: self._browse_file(self.jpg_carrier, "Images (*.png *.jpg *.jpeg)"))
        self.jpg_dyn_layout.addWidget(row)

        self.jpg_secret = QLineEdit()
        row, btn = self._file_select_row("Secret TXT:", self.jpg_secret)
        btn.clicked.connect(lambda: self._browse_file(self.jpg_secret, "Text Files (*.txt)"))
        self.jpg_dyn_layout.addWidget(row)

        self.jpg_output = QLineEdit()
        row, btn = self._file_select_row("Output JPG:", self.jpg_output)
        btn.clicked.connect(lambda: self._save_file(self.jpg_output, "Images (*.jpg *.png)"))
        self.jpg_dyn_layout.addWidget(row)

        self.jpg_encrypt_cb = QCheckBox("Encrypt payload")
        self.jpg_password = QLineEdit()
        self.jpg_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.jpg_password.setPlaceholderText("Password (optional)")
        self.jpg_dyn_layout.addWidget(self.jpg_encrypt_cb)
        self.jpg_dyn_layout.addWidget(self.jpg_password)

        hide_btn = QPushButton("Hide into JPG")
        hide_btn.clicked.connect(self._jpg_hide)
        self.jpg_dyn_layout.addWidget(hide_btn)
        self.jpg_dyn_layout.addStretch()

    def _build_jpg_extract_ui(self):
        self._clear_layout(self.jpg_dyn_layout)

        self.jpg_stego = QLineEdit()
        row, btn = self._file_select_row("Stego JPG:", self.jpg_stego)
        btn.clicked.connect(lambda: self._browse_file(self.jpg_stego, "Images (*.png *.jpg *.jpeg)"))
        self.jpg_dyn_layout.addWidget(row)

        self.jpg_output_extract = QLineEdit()
        row, btn = self._file_select_row("Extract to TXT:", self.jpg_output_extract)
        btn.clicked.connect(lambda: self._save_file(self.jpg_output_extract, "Text Files (*.txt)"))
        self.jpg_dyn_layout.addWidget(row)

        self.jpg_decrypt_cb = QCheckBox("Encrypted payload")
        self.jpg_decrypt_pass = QLineEdit()
        self.jpg_decrypt_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self.jpg_decrypt_pass.setPlaceholderText("Password")
        self.jpg_dyn_layout.addWidget(self.jpg_decrypt_cb)
        self.jpg_dyn_layout.addWidget(self.jpg_decrypt_pass)

        extract_btn = QPushButton("Extract from JPG")
        extract_btn.clicked.connect(self._jpg_extract)
        self.jpg_dyn_layout.addWidget(extract_btn)
        self.jpg_dyn_layout.addStretch()

    def _update_jpg_ui(self, _=None):
        if self.jpg_mode.currentText() == "Hide":
            self._build_jpg_hide_ui()
        else:
            self._build_jpg_extract_ui()

    # ---------------- EXE tab (dynamic) ----------------
    def _create_exe_tab(self):
        tab = QWidget()
        v = QVBoxLayout(tab)

        top = QWidget(); top_l = QHBoxLayout(top)
        top.setLayout(top_l)
        top_l.addWidget(QLabel("Mode:"))
        self.exe_mode = QComboBox()
        self.exe_mode.addItems(["Hide", "Extract"])
        self.exe_mode.currentTextChanged.connect(self._update_exe_ui)
        top_l.addWidget(self.exe_mode)
        top_l.addStretch()
        v.addWidget(top)

        self.exe_dynamic = QWidget()
        self.exe_dyn_layout = QVBoxLayout(self.exe_dynamic)
        self.exe_dynamic.setLayout(self.exe_dyn_layout)
        v.addWidget(self.exe_dynamic)

        self._build_exe_hide_ui()
        return tab

    def _build_exe_hide_ui(self):
        self._clear_layout(self.exe_dyn_layout)

        self.exe_carrier = QLineEdit()
        row, btn = self._file_select_row("Carrier EXE:", self.exe_carrier)
        btn.clicked.connect(lambda: self._browse_file(self.exe_carrier, "Executables (*.exe)"))
        self.exe_dyn_layout.addWidget(row)

        self.exe_secret = QLineEdit()
        row, btn = self._file_select_row("Secret TXT:", self.exe_secret)
        btn.clicked.connect(lambda: self._browse_file(self.exe_secret, "Text Files (*.txt)"))
        self.exe_dyn_layout.addWidget(row)

        self.exe_output = QLineEdit()
        row, btn = self._file_select_row("Output EXE:", self.exe_output)
        btn.clicked.connect(lambda: self._save_file(self.exe_output, "Executables (*.exe)"))
        self.exe_dyn_layout.addWidget(row)

        self.exe_encrypt_cb = QCheckBox("Encrypt payload")
        self.exe_password = QLineEdit()
        self.exe_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.exe_password.setPlaceholderText("Password (optional)")
        self.exe_dyn_layout.addWidget(self.exe_encrypt_cb)
        self.exe_dyn_layout.addWidget(self.exe_password)

        hide_btn = QPushButton("Hide into EXE")
        hide_btn.clicked.connect(self._exe_hide)
        self.exe_dyn_layout.addWidget(hide_btn)
        self.exe_dyn_layout.addStretch()

    def _build_exe_extract_ui(self):
        self._clear_layout(self.exe_dyn_layout)

        self.exe_stego = QLineEdit()
        row, btn = self._file_select_row("Stego EXE:", self.exe_stego)
        btn.clicked.connect(lambda: self._browse_file(self.exe_stego, "Executables (*.exe)"))
        self.exe_dyn_layout.addWidget(row)

        self.exe_output_extract = QLineEdit()
        row, btn = self._file_select_row("Extract to TXT:", self.exe_output_extract)
        btn.clicked.connect(lambda: self._save_file(self.exe_output_extract, "Text Files (*.txt)"))
        self.exe_dyn_layout.addWidget(row)

        self.exe_decrypt_cb = QCheckBox("Encrypted payload")
        self.exe_decrypt_pass = QLineEdit()
        self.exe_decrypt_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self.exe_decrypt_pass.setPlaceholderText("Password")
        self.exe_dyn_layout.addWidget(self.exe_decrypt_cb)
        self.exe_dyn_layout.addWidget(self.exe_decrypt_pass)

        extract_btn = QPushButton("Extract from EXE")
        extract_btn.clicked.connect(self._exe_extract)
        self.exe_dyn_layout.addWidget(extract_btn)
        self.exe_dyn_layout.addStretch()

    def _update_exe_ui(self, _=None):
        if self.exe_mode.currentText() == "Hide":
            self._build_exe_hide_ui()
        else:
            self._build_exe_extract_ui()

    # ---------------- MP3 tab (dynamic) ----------------
    def _create_mp3_tab(self):
        tab = QWidget()
        v = QVBoxLayout(tab)

        top = QWidget(); top_l = QHBoxLayout(top)
        top.setLayout(top_l)
        top_l.addWidget(QLabel("Mode:"))
        self.mp3_mode = QComboBox()
        self.mp3_mode.addItems(["Hide", "Extract"])
        self.mp3_mode.currentTextChanged.connect(self._update_mp3_ui)
        top_l.addWidget(self.mp3_mode)
        top_l.addStretch()
        v.addWidget(top)

        self.mp3_dynamic = QWidget()
        self.mp3_dyn_layout = QVBoxLayout(self.mp3_dynamic)
        self.mp3_dynamic.setLayout(self.mp3_dyn_layout)
        v.addWidget(self.mp3_dynamic)

        self._build_mp3_hide_ui()
        return tab

    def _build_mp3_hide_ui(self):
        self._clear_layout(self.mp3_dyn_layout)

        self.mp3_carrier = QLineEdit()
        row, btn = self._file_select_row("Carrier MP3:", self.mp3_carrier)
        btn.clicked.connect(lambda: self._browse_file(self.mp3_carrier, "Audio Files (*.mp3)"))
        self.mp3_dyn_layout.addWidget(row)

        self.mp3_secret = QLineEdit()
        row, btn = self._file_select_row("Secret TXT:", self.mp3_secret)
        btn.clicked.connect(lambda: self._browse_file(self.mp3_secret, "Text Files (*.txt)"))
        self.mp3_dyn_layout.addWidget(row)

        self.mp3_output = QLineEdit()
        row, btn = self._file_select_row("Output MP3:", self.mp3_output)
        btn.clicked.connect(lambda: self._save_file(self.mp3_output, "Audio Files (*.mp3)"))
        self.mp3_dyn_layout.addWidget(row)

        self.mp3_encrypt_cb = QCheckBox("Encrypt payload")
        self.mp3_password = QLineEdit()
        self.mp3_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.mp3_password.setPlaceholderText("Password (optional)")
        self.mp3_dyn_layout.addWidget(self.mp3_encrypt_cb)
        self.mp3_dyn_layout.addWidget(self.mp3_password)

        hide_btn = QPushButton("Hide into MP3")
        hide_btn.clicked.connect(self._mp3_hide)
        self.mp3_dyn_layout.addWidget(hide_btn)
        self.mp3_dyn_layout.addStretch()

    def _build_mp3_extract_ui(self):
        self._clear_layout(self.mp3_dyn_layout)

        self.mp3_stego = QLineEdit()
        row, btn = self._file_select_row("Stego MP3:", self.mp3_stego)
        btn.clicked.connect(lambda: self._browse_file(self.mp3_stego, "Audio Files (*.mp3)"))
        self.mp3_dyn_layout.addWidget(row)

        self.mp3_output_extract = QLineEdit()
        row, btn = self._file_select_row("Extract to TXT:", self.mp3_output_extract)
        btn.clicked.connect(lambda: self._save_file(self.mp3_output_extract, "Text Files (*.txt)"))
        self.mp3_dyn_layout.addWidget(row)

        self.mp3_decrypt_cb = QCheckBox("Encrypted payload")
        self.mp3_decrypt_pass = QLineEdit()
        self.mp3_decrypt_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self.mp3_decrypt_pass.setPlaceholderText("Password")
        self.mp3_dyn_layout.addWidget(self.mp3_decrypt_cb)
        self.mp3_dyn_layout.addWidget(self.mp3_decrypt_pass)

        extract_btn = QPushButton("Extract from MP3")
        extract_btn.clicked.connect(self._mp3_extract)
        self.mp3_dyn_layout.addWidget(extract_btn)
        self.mp3_dyn_layout.addStretch()

    def _update_mp3_ui(self, _=None):
        if self.mp3_mode.currentText() == "Hide":
            self._build_mp3_hide_ui()
        else:
            self._build_mp3_extract_ui()

    # ---------------- ADS tab (dynamic) ----------------
    def _create_ads_tab(self):
        tab = QWidget()
        v = QVBoxLayout(tab)

        top = QWidget(); top_l = QHBoxLayout(top)
        top.setLayout(top_l)
        top_l.addWidget(QLabel("Mode:"))
        self.ads_mode = QComboBox()
        self.ads_mode.addItems(["Hide", "Extract"])
        self.ads_mode.currentTextChanged.connect(self._update_ads_ui)
        top_l.addWidget(self.ads_mode)
        top_l.addStretch()
        v.addWidget(top)

        self.ads_dynamic = QWidget()
        self.ads_dyn_layout = QVBoxLayout(self.ads_dynamic)
        self.ads_dynamic.setLayout(self.ads_dyn_layout)
        v.addWidget(self.ads_dynamic)

        self._build_ads_hide_ui()
        return tab

    def _build_ads_hide_ui(self):
        self._clear_layout(self.ads_dyn_layout)

        self.ads_host = QLineEdit()
        row, btn = self._file_select_row("Host file (will store ADS):", self.ads_host)
        btn.clicked.connect(lambda: self._browse_file(self.ads_host, "All Files (*)"))
        self.ads_dyn_layout.addWidget(row)

        self.ads_secret = QLineEdit()
        row, btn = self._file_select_row("Secret TXT:", self.ads_secret)
        btn.clicked.connect(lambda: self._browse_file(self.ads_secret, "Text Files (*.txt)"))
        self.ads_dyn_layout.addWidget(row)

        self.ads_stream_name = QLineEdit("secret_stream")
        row2 = QWidget()
        h2 = QHBoxLayout()
        row2.setLayout(h2)
        h2.addWidget(QLabel("ADS stream name:"))
        h2.addWidget(self.ads_stream_name)
        self.ads_dyn_layout.addWidget(row2)

        self.ads_encrypt_cb = QCheckBox("Encrypt payload")
        self.ads_password = QLineEdit()
        self.ads_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.ads_password.setPlaceholderText("Password (optional)")
        self.ads_dyn_layout.addWidget(self.ads_encrypt_cb)
        self.ads_dyn_layout.addWidget(self.ads_password)

        hide_btn = QPushButton("Hide into ADS")
        hide_btn.clicked.connect(self._ads_hide)
        self.ads_dyn_layout.addWidget(hide_btn)
        self.ads_dyn_layout.addStretch()

    def _build_ads_extract_ui(self):
        self._clear_layout(self.ads_dyn_layout)

        self.ads_host_extract = QLineEdit()
        row, btn = self._file_select_row("Host file (with ADS):", self.ads_host_extract)
        btn.clicked.connect(lambda: self._browse_file(self.ads_host_extract, "All Files (*)"))
        self.ads_dyn_layout.addWidget(row)

        self.ads_stream_name_extract = QLineEdit("secret_stream")
        row2 = QWidget()
        h2 = QHBoxLayout()
        row2.setLayout(h2)
        h2.addWidget(QLabel("ADS stream name:"))
        h2.addWidget(self.ads_stream_name_extract)
        self.ads_dyn_layout.addWidget(row2)

        self.ads_decrypt_cb = QCheckBox("Encrypted payload")
        self.ads_decrypt_pass = QLineEdit()
        self.ads_decrypt_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self.ads_decrypt_pass.setPlaceholderText("Password")
        self.ads_dyn_layout.addWidget(self.ads_decrypt_cb)
        self.ads_dyn_layout.addWidget(self.ads_decrypt_pass)

        extract_btn = QPushButton("Extract from ADS")
        extract_btn.clicked.connect(self._ads_extract)
        self.ads_dyn_layout.addWidget(extract_btn)
        self.ads_dyn_layout.addStretch()

    def _update_ads_ui(self, _=None):
        if self.ads_mode.currentText() == "Hide":
            self._build_ads_hide_ui()
        else:
            self._build_ads_extract_ui()

    # ---------------- Action handlers (use new dynamic fields) ----------------

    # EXE hide/extract (uses SteganoEXE)
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
        stego = self.exe_stego.text().strip()
        out = self.exe_output_extract.text().strip() or QFileDialog.getSaveFileName(self, "Save secret as", str(Path.home()), "All Files (*)")[0]
        pwd = self.exe_decrypt_pass.text().strip() if self.exe_decrypt_cb.isChecked() else None

        if not stego:
            QMessageBox.warning(self, "Missing input", "Please specify the stego executable in 'Stego EXE' field.")
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

    # PDF handlers
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
        carrier = self.pdf_stego.text().strip()
        output = self.pdf_output_extract.text().strip()
        password = self.pdf_decrypt_pass.text().strip() if self.pdf_decrypt_cb.isChecked() else None

        if not (carrier and output):
            QMessageBox.warning(self, "Missing input", "Please provide the stego PDF and output text file.")
            return

        steg = PDFStego()
        success = steg.extract(carrier, output, password)

        if success:
            QMessageBox.information(self, "Success", f"Extracted text saved to: {output}")
        else:
            QMessageBox.critical(self, "Error", "Extraction failed. Wrong password or no data found.")

    # JPG handlers
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
        carrier = self.jpg_stego.text().strip()
        output = self.jpg_output_extract.text().strip()
        password = self.jpg_decrypt_pass.text().strip() if self.jpg_decrypt_cb.isChecked() else None

        if not (carrier and output):
            QMessageBox.warning(self, "Missing input", "Please provide stego JPG and output text file.")
            return

        steg = JPGStego()
        success = steg.extract(carrier, output, password)

        if success:
            QMessageBox.information(self, "Success", f"Extracted text saved to: {output}")
        else:
            QMessageBox.critical(self, "Error", "Failed to extract data from JPG.")

    # MP3 handlers
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
        carrier = self.mp3_stego.text().strip()
        output = self.mp3_output_extract.text().strip()
        password = self.mp3_decrypt_pass.text().strip() if self.mp3_decrypt_cb.isChecked() else None

        if not (carrier and output):
            QMessageBox.warning(self, "Missing input", "Please provide stego MP3 and output text file.")
            return

        steg = MP3Stego()
        success = steg.extract(carrier, output, password)

        if success:
            QMessageBox.information(self, "Success", f"Extracted text saved to: {output}")
        else:
            QMessageBox.critical(self, "Error", "Failed to extract data from MP3.")

    # ADS handlers
    def _ads_hide(self):
        host = self.ads_host.text().strip()
        secret = self.ads_secret.text().strip()
        stream = self.ads_stream_name.text().strip() or "secret_stream"
        pwd = self.ads_password.text().strip() if self.ads_encrypt_cb.isChecked() else None

        if not (host and secret):
            QMessageBox.warning(self, "Missing input", "Please specify host file and secret .txt file.")
            return

        stego = ADSStego()
        if os.name != "nt":
            QMessageBox.critical(self, "Not supported", "ADS is only supported on Windows NTFS.")
            return

        success = stego.hide(host, secret, stream, password=pwd)
        if success:
            QMessageBox.information(self, "Done", f"Written ADS to {host}:{stream}\n(Works only on NTFS/Windows)")
        else:
            QMessageBox.critical(self, "Error", "ADS write failed. See console for details.")

    def _ads_extract(self):
        host = self.ads_host_extract.text().strip()
        stream = self.ads_stream_name_extract.text().strip() or "secret_stream"
        out, _ = QFileDialog.getSaveFileName(self, "Save extracted secret", str(Path.home()), "All Files (*)")
        pwd = self.ads_decrypt_pass.text().strip() if self.ads_decrypt_cb.isChecked() else None

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
