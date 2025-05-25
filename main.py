import sys
import os
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QPushButton, QLabel, QComboBox, 
                            QTextEdit, QFileDialog, QMessageBox, QTabWidget)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QPalette, QColor
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import base64

class DigitalSignatureApp(QMainWindow):
  
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Digital Signature and ECDH Tool")
        self.setMinimumSize(800, 600)
        self.setup_ui()
        self.setup_dark_theme()
        
        # Initialize key pairs
        self.rsa_private_key = None
        self.rsa_public_key = None
        self.ecc_private_key = None
        self.ecc_public_key = None
        self.ecdh_private_key = None
        self.ecdh_public_key = None

    def setup_dark_theme(self):
        """
        Apply a dark theme to the application using Qt stylesheets.
        """
        self.setStyleSheet("""
            QMainWindow { background-color: #2b2b2b; }
            QWidget { background-color: #2b2b2b; color: #ffffff; }
            QPushButton {
                background-color: #0d47a1; color: white; border: none;
                padding: 8px 16px; border-radius: 4px;
            }
            QPushButton:hover { background-color: #1565c0; }
            QTextEdit {
                background-color: #1e1e1e; color: #ffffff;
                border: 1px solid #3d3d3d; border-radius: 4px;
            }
            QComboBox {
                background-color: #1e1e1e; color: #ffffff;
                border: 1px solid #3d3d3d; border-radius: 4px; padding: 5px;
            }
            QLabel { color: #ffffff; }
            QTabBar::tab { color: #ffffff; background: #2b2b2b; }
            QTabBar::tab:selected { background: #222222; color: #ffffff; }
            QTabWidget::pane { border: 1px solid #3d3d3d; }
        """)

    def setup_ui(self):
        """
        Set up the GUI with tabs for Key Generation, Sign/Verify, and ECDH Key Exchange.
        """
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        # Create tab widget
        tabs = QTabWidget()
        layout.addWidget(tabs)

        # --- Key Generation Tab ---
        key_gen_tab = QWidget()
        key_gen_layout = QVBoxLayout(key_gen_tab)
        
        algo_layout = QHBoxLayout()
        algo_label = QLabel("Select Algorithm:")
        self.algo_combo = QComboBox()
        self.algo_combo.addItems(["RSA", "ECC"])
        algo_layout.addWidget(algo_label)
        algo_layout.addWidget(self.algo_combo)
        key_gen_layout.addLayout(algo_layout)

        generate_btn = QPushButton("Generate New Keys")
        generate_btn.clicked.connect(self.generate_keys)
        key_gen_layout.addWidget(generate_btn)

        self.key_display = QTextEdit()
        self.key_display.setReadOnly(True)
        key_gen_layout.addWidget(self.key_display)

        key_btn_layout = QHBoxLayout()
        load_keys_btn = QPushButton("Load Keys")
        load_keys_btn.clicked.connect(self.load_keys)
        save_keys_btn = QPushButton("Save Keys")
        save_keys_btn.clicked.connect(self.save_keys)
        copy_keys_btn = QPushButton("Copy Keys")
        copy_keys_btn.clicked.connect(self.copy_keys_to_clipboard)
        key_btn_layout.addWidget(load_keys_btn)
        key_btn_layout.addWidget(save_keys_btn)
        key_btn_layout.addWidget(copy_keys_btn)
        key_gen_layout.addLayout(key_btn_layout)

        # --- Sign/Verify Tab ---
        sign_verify_tab = QWidget()
        sign_verify_layout = QVBoxLayout(sign_verify_tab)

        message_label = QLabel("Message/File:")
        sign_verify_layout.addWidget(message_label)
        
        self.message_input = QTextEdit()
        sign_verify_layout.addWidget(self.message_input)

        file_btn = QPushButton("Select File")
        file_btn.clicked.connect(self.select_file)
        sign_verify_layout.addWidget(file_btn)

        btn_layout = QHBoxLayout()
        sign_btn = QPushButton("Sign")
        verify_btn = QPushButton("Verify")
        sign_btn.clicked.connect(self.sign_message)
        verify_btn.clicked.connect(self.verify_signature)
        btn_layout.addWidget(sign_btn)
        btn_layout.addWidget(verify_btn)
        sign_verify_layout.addLayout(btn_layout)

        signature_label = QLabel("Signature:")
        sign_verify_layout.addWidget(signature_label)
        self.signature_display = QTextEdit()
        sign_verify_layout.addWidget(self.signature_display)

        sig_btn_layout = QHBoxLayout()
        load_signature_btn = QPushButton("Load Signature")
        load_signature_btn.clicked.connect(self.load_signature)
        save_signature_btn = QPushButton("Save Signature")
        save_signature_btn.clicked.connect(self.save_signature)
        sig_btn_layout.addWidget(load_signature_btn)
        sig_btn_layout.addWidget(save_signature_btn)
        sign_verify_layout.addLayout(sig_btn_layout)

        # --- ECDH Key Exchange Tab ---
        ecdh_tab = QWidget()
        ecdh_layout = QVBoxLayout(ecdh_tab)

        ecdh_generate_btn = QPushButton("Generate ECDH Key Pair")
        ecdh_generate_btn.clicked.connect(self.generate_ecdh_keys)
        ecdh_layout.addWidget(ecdh_generate_btn)

        self.ecdh_key_display = QTextEdit()
        self.ecdh_key_display.setReadOnly(True)
        ecdh_layout.addWidget(self.ecdh_key_display)

        load_ecdh_public_btn = QPushButton("Load Other Party's Public Key")
        load_ecdh_public_btn.clicked.connect(self.load_ecdh_public_key)
        ecdh_layout.addWidget(load_ecdh_public_btn)

        compute_secret_btn = QPushButton("Compute Shared Secret")
        compute_secret_btn.clicked.connect(self.compute_shared_secret)
        ecdh_layout.addWidget(compute_secret_btn)

        shared_secret_label = QLabel("Shared Secret (Base64):")
        ecdh_layout.addWidget(shared_secret_label)
        self.shared_secret_display = QTextEdit()
        self.shared_secret_display.setReadOnly(True)
        ecdh_layout.addWidget(self.shared_secret_display)

        tabs.addTab(key_gen_tab, "Key Generation")
        tabs.addTab(sign_verify_tab, "Sign/Verify")
        tabs.addTab(ecdh_tab, "ECDH Key Exchange")

    def generate_keys(self):
        """
        Generate RSA or ECC key pair and display in PEM format.
        """
        try:
            algorithm = self.algo_combo.currentText()
            if algorithm == "RSA":
                self.rsa_private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048,
                    backend=default_backend()
                )
                self.rsa_public_key = self.rsa_private_key.public_key()

                private_pem = self.rsa_private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                public_pem = self.rsa_public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )

                self.key_display.setText(
                    "Private Key:\n" + private_pem.decode() + "\n\n" +
                    "Public Key:\n" + public_pem.decode()
                )

            else:  # ECC
                self.ecc_private_key = ec.generate_private_key(
                    ec.SECP256K1(),
                    default_backend()
                )
                self.ecc_public_key = self.ecc_private_key.public_key()

                private_pem = self.ecc_private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                public_pem = self.ecc_public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )

                self.key_display.setText(
                    "Private Key:\n" + private_pem.decode() + "\n\n" +
                    "Public Key:\n" + public_pem.decode()
                )

            QMessageBox.information(self, "Success", "Keys generated successfully!")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to generate keys: {str(e)}")

    def load_keys(self):
        """
        Load private and public keys from PEM files for the selected algorithm.
        """
        try:
            algorithm = self.algo_combo.currentText()
            private_file, _ = QFileDialog.getOpenFileName(self, f"Load {algorithm} Private Key", "", "PEM Files (*.pem);;All Files (*)")
            if not private_file:
                return
            public_file, _ = QFileDialog.getOpenFileName(self, f"Load {algorithm} Public Key", "", "PEM Files (*.pem);;All Files (*)")
            if not public_file:
                return

            with open(private_file, 'rb') as f:
                private_pem = f.read()
            with open(public_file, 'rb') as f:
                public_pem = f.read()

            if algorithm == "RSA":
                self.rsa_private_key = serialization.load_pem_private_key(
                    private_pem,
                    password=None,
                    backend=default_backend()
                )
                self.rsa_public_key = serialization.load_pem_public_key(
                    public_pem,
                    backend=default_backend()
                )
            else:  # ECC
                self.ecc_private_key = serialization.load_pem_private_key(
                    private_pem,
                    password=None,
                    backend=default_backend()
                )
                self.ecc_public_key = serialization.load_pem_public_key(
                    public_pem,
                    backend=default_backend()
                )

            self.key_display.setText(
                "Private Key:\n" + private_pem.decode('utf-8', errors='ignore') + "\n\n" +
                "Public Key:\n" + public_pem.decode('utf-8', errors='ignore')
            )
            QMessageBox.information(self, "Success", f"{algorithm} keys loaded successfully!")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load keys: {str(e)}")

    def save_keys(self):
        """
        Save private and public keys to separate PEM files.
        """
        try:
            algorithm = self.algo_combo.currentText()
            file_name, _ = QFileDialog.getSaveFileName(self, "Save Keys", f"{algorithm}_keys")
            if file_name:
                private_file = f"{file_name}_private.pem"
                public_file = f"{file_name}_public.pem"
                private_pem = self.key_display.toPlainText().split("Public Key:")[0].strip()
                public_pem = self.key_display.toPlainText().split("Public Key:")[1].strip()
                
                with open(private_file, 'w') as f:
                    f.write(private_pem)
                with open(public_file, 'w') as f:
                    f.write(public_pem)
                QMessageBox.information(self, "Success", "Keys saved successfully!")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save keys: {str(e)}")

    def select_file(self):
        """
        Load file contents into the message input box.
        """
        file_name, _ = QFileDialog.getOpenFileName(self, "Select File")
        if file_name:
            try:
                with open(file_name, 'rb') as f:
                    content = f.read()
                self.message_input.setText(content.decode('utf-8', errors='ignore'))
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to read file: {str(e)}")

    def load_signature(self):
        """
        Load a base64-encoded signature from a file into the signature display box.
        """
        try:
            file_name, _ = QFileDialog.getOpenFileName(self, "Load Signature", "", "Text Files (*.txt);;All Files (*)")
            if file_name:
                with open(file_name, 'r') as f:
                    signature_b64 = f.read().strip()
                self.signature_display.setText(signature_b64)
                QMessageBox.information(self, "Success", "Signature loaded successfully!")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load signature: {str(e)}")

    def sign_message(self):
        """
        Sign the message using SHA-256 hashing and the selected algorithm's private key.
        """
        try:
            message = self.message_input.toPlainText().encode()
            algorithm = self.algo_combo.currentText()

            if algorithm == "RSA":
                if not self.rsa_private_key:
                    raise ValueError("Please generate or load RSA keys first")
                hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
                hasher.update(message)
                message_hash = hasher.finalize()
                signature = self.rsa_private_key.sign(
                    message_hash,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
            else:  # ECC
                if not self.ecc_private_key:
                    raise ValueError("Please generate or load ECC keys first")
                hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
                hasher.update(message)
                message_hash = hasher.finalize()
                signature = self.ecc_private_key.sign(
                    message_hash,
                    ec.ECDSA(hashes.SHA256())
                )

            signature_b64 = base64.b64encode(signature).decode()
            self.signature_display.setText(signature_b64)
            QMessageBox.information(self, "Success", "Message signed successfully!")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to sign message: {str(e)}")

    def verify_signature(self):
        """
        Verify the signature using the message, public key, and SHA-256 hashing.
        """
        try:
            message = self.message_input.toPlainText().encode()
            signature_b64 = self.signature_display.toPlainText()
            algorithm = self.algo_combo.currentText()

            if not signature_b64:
                raise ValueError("No signature to verify")
            signature = base64.b64decode(signature_b64)

            if algorithm == "RSA":
                if not self.rsa_public_key:
                    raise ValueError("Please generate or load RSA keys first")
                hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
                hasher.update(message)
                message_hash = hasher.finalize()
                self.rsa_public_key.verify(
                    signature,
                    message_hash,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
            else:  # ECC
                if not self.ecc_public_key:
                    raise ValueError("Please generate or load ECC keys first")
                hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
                hasher.update(message)
                message_hash = hasher.finalize()
                self.ecc_public_key.verify(
                    signature,
                    message_hash,
                    ec.ECDSA(hashes.SHA256())
                )

            QMessageBox.information(self, "Success", "Signature is valid!")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Signature verification failed: {str(e)}")

    def save_signature(self):
        """
        Save the signature to a file.
        """
        try:
            signature_b64 = self.signature_display.toPlainText()
            if not signature_b64:
                raise ValueError("No signature to save")
            file_name, _ = QFileDialog.getSaveFileName(self, "Save Signature", "signature.txt")
            if file_name:
                with open(file_name, 'w') as f:
                    f.write(signature_b64)
                QMessageBox.information(self, "Success", "Signature saved successfully!")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save signature: {str(e)}")

    def copy_keys_to_clipboard(self):
        """
        Copy the keys to the clipboard.
        """
        clipboard = QApplication.clipboard()
        clipboard.setText(self.key_display.toPlainText())
        QMessageBox.information(self, "Copied", "Keys copied to clipboard!")

    def generate_ecdh_keys(self):
        """
        Generate ECDH key pair and display in PEM format.
        """
        try:
            self.ecdh_private_key = ec.generate_private_key(
                ec.SECP256K1(),
                default_backend()
            )
            self.ecdh_public_key = self.ecdh_private_key.public_key()

            private_pem = self.ecdh_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            public_pem = self.ecdh_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            self.ecdh_key_display.setText(
                "ECDH Private Key:\n" + private_pem.decode() + "\n\n" +
                "ECDH Public Key:\n" + public_pem.decode()
            )
            QMessageBox.information(self, "Success", "ECDH keys generated successfully!")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to generate ECDH keys: {str(e)}")

    def load_ecdh_public_key(self):
        """
        Load another party's ECDH public key from a PEM file.
        """
        try:
            public_file, _ = QFileDialog.getOpenFileName(self, "Load Other Party's ECDH Public Key", "", "PEM Files (*.pem);;All Files (*)")
            if not public_file:
                return

            with open(public_file, 'rb') as f:
                public_pem = f.read()

            self.ecdh_other_public_key = serialization.load_pem_public_key(
                public_pem,
                backend=default_backend()
            )

            self.ecdh_key_display.setText(
                self.ecdh_key_display.toPlainText() + "\n\n" +
                "Other Party's ECDH Public Key:\n" + public_pem.decode('utf-8', errors='ignore')
            )
            QMessageBox.information(self, "Success", "Other party's ECDH public key loaded successfully!")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load ECDH public key: {str(e)}")

    def compute_shared_secret(self):
        """
        Compute the ECDH shared secret using the private key and other party's public key.
        """
        try:
            if not self.ecdh_private_key:
                raise ValueError("Please generate ECDH keys first")
            if not hasattr(self, 'ecdh_other_public_key') or not self.ecdh_other_public_key:
                raise ValueError("Please load the other party's ECDH public key first")

            shared_secret = self.ecdh_private_key.exchange(ec.ECDH(), self.ecdh_other_public_key)
            # Derive a key from the shared secret using HKDF
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',
                backend=default_backend()
            ).derive(shared_secret)

            shared_secret_b64 = base64.b64encode(derived_key).decode()
            self.shared_secret_display.setText(shared_secret_b64)
            QMessageBox.information(self, "Success", "Shared secret computed successfully!")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to compute shared secret: {str(e)}")

def main():
    """
    Entry point for the application.
    """
    app = QApplication(sys.argv)
    window = DigitalSignatureApp()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
