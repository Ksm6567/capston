import sys
import os

# Add src folder to import paths
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))
from suricata_monitor import SuricataMonitor
from yara_scanner import YaraScanner

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTextEdit, QLabel
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QShortcut, QKeySequence

class SIEMMainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SIEM - Suricata & Yara Integrated Control")
        self.resize(800, 600)

        self.suricata_thread = None
        self.yara_thread = None

        self.init_ui()
        self.init_shortcuts()

    def init_ui(self):
        # Main widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # Title
        title_label = QLabel("Integrated SIEM Dashboard")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setStyleSheet("font-size: 24px; font-weight: bold; margin: 10px;")
        main_layout.addWidget(title_label)

        # Buttons layout
        buttons_layout = QHBoxLayout()

        # Suricata Button
        self.btn_suricata = QPushButton("Suricata Network Detection (F1)")
        self.btn_suricata.setMinimumHeight(60)
        self.btn_suricata.setStyleSheet(
            "font-size: 16px; font-weight: bold; background-color: #2D9CDB; color: white; border-radius: 5px;"
        )
        self.btn_suricata.clicked.connect(self.run_suricata_detection)
        buttons_layout.addWidget(self.btn_suricata)

        # Yara Button
        self.btn_yara = QPushButton("Yara File/Pattern Detection (F2)")
        self.btn_yara.setMinimumHeight(60)
        self.btn_yara.setStyleSheet(
            "font-size: 16px; font-weight: bold; background-color: #27AE60; color: white; border-radius: 5px;"
        )
        self.btn_yara.clicked.connect(self.run_yara_detection)
        buttons_layout.addWidget(self.btn_yara)

        main_layout.addLayout(buttons_layout)

        # Log output area
        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        self.log_area.setStyleSheet(
            "background-color: #1E1E1E; color: #00FF00; font-family: Consolas; font-size: 14px; padding: 10px;"
        )
        main_layout.addWidget(self.log_area)
        
        self.append_log("System Initialized. Waiting for actions...")

    def init_shortcuts(self):
        # F1 Shortcut for Suricata
        self.shortcut_f1 = QShortcut(QKeySequence("F1"), self)
        self.shortcut_f1.activated.connect(self.run_suricata_detection)

        # F2 Shortcut for Yara
        self.shortcut_f2 = QShortcut(QKeySequence("F2"), self)
        self.shortcut_f2.activated.connect(self.run_yara_detection)

    def append_log(self, message: str):
        self.log_area.append(f"[System] {message}")

    def run_suricata_detection(self):
        if self.suricata_thread and self.suricata_thread.isRunning():
            self.append_log(">>> Stopping Suricata Network Detection...")
            self.suricata_thread.stop()
            self.suricata_thread.wait() # Wait for thread to finish parsing line
            self.suricata_thread = None
            
            self.btn_suricata.setText("Suricata Network Detection (F1)")
            self.btn_suricata.setStyleSheet(
                "font-size: 16px; font-weight: bold; background-color: #2D9CDB; color: white; border-radius: 5px;"
            )
        else:
            self.append_log(">>> Starting Suricata Network Detection...")
            # Initialize monitor
            self.suricata_thread = SuricataMonitor(log_path="eve.json")
            self.suricata_thread.new_alert.connect(self.append_log)
            self.suricata_thread.start()
            
            self.btn_suricata.setText("Stop Suricata Network Detection (F1)")
            self.btn_suricata.setStyleSheet(
                "font-size: 16px; font-weight: bold; background-color: #E74C3C; color: white; border-radius: 5px;"
            )

    def run_yara_detection(self):
        if self.yara_thread and self.yara_thread.isRunning():
            self.append_log(">>> Stopping Yara File/Pattern Detection...")
            self.yara_thread.stop()
            self.yara_thread.wait()
            self.yara_thread = None
            
            self.btn_yara.setText("Yara File/Pattern Detection (F2)")
            self.btn_yara.setStyleSheet(
                "font-size: 16px; font-weight: bold; background-color: #27AE60; color: white; border-radius: 5px;"
            )
        else:
            self.append_log(">>> Starting Yara File/Pattern Detection...")
            self.yara_thread = YaraScanner(rules_path="rules/sample.yar", target_path=".")
            self.yara_thread.scan_result.connect(self.append_log)
            self.yara_thread.scan_finished.connect(self.on_yara_finished)
            self.yara_thread.start()
            
            self.btn_yara.setText("Stop Yara File/Pattern Detection (F2)")
            self.btn_yara.setStyleSheet(
                "font-size: 16px; font-weight: bold; background-color: #E74C3C; color: white; border-radius: 5px;"
            )

    def on_yara_finished(self):
        # Reset button state when Yara finishes automatically
        if self.yara_thread:
            self.yara_thread = None
        
        self.btn_yara.setText("Yara File/Pattern Detection (F2)")
        self.btn_yara.setStyleSheet(
            "font-size: 16px; font-weight: bold; background-color: #27AE60; color: white; border-radius: 5px;"
        )

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SIEMMainWindow()
    window.show()
    sys.exit(app.exec())
