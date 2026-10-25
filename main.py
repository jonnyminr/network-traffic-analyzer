import sys
from PySide6.QtWidgets import QApplication
from PySide6.QtGui import QPalette, QColor
from PySide6.QtCore import Qt

from gui.main_window import MainWindow

def setup_dark_theme(app: QApplication):
    app.setStyle("Fusion")
    palette = QPalette()
    
    # Base background and text colors
    palette.setColor(QPalette.Window, QColor(30, 30, 36))
    palette.setColor(QPalette.WindowText, QColor(225, 225, 230))
    palette.setColor(QPalette.Base, QColor(22, 22, 26))
    palette.setColor(QPalette.AlternateBase, QColor(28, 28, 34))
    palette.setColor(QPalette.ToolTipBase, QColor(40, 40, 48))
    palette.setColor(QPalette.ToolTipText, QColor(230, 230, 235))
    palette.setColor(QPalette.Text, QColor(225, 225, 230))
    palette.setColor(QPalette.Button, QColor(38, 38, 46))
    palette.setColor(QPalette.ButtonText, QColor(230, 230, 235))
    palette.setColor(QPalette.BrightText, QColor(255, 82, 82))
    palette.setColor(QPalette.Link, QColor(0, 229, 255))
    palette.setColor(QPalette.Highlight, QColor(0, 160, 220))
    palette.setColor(QPalette.HighlightedText, QColor(255, 255, 255))
    
    # Disabled colors
    palette.setColor(QPalette.Disabled, QPalette.WindowText, QColor(110, 110, 120))
    palette.setColor(QPalette.Disabled, QPalette.Text, QColor(110, 110, 120))
    palette.setColor(QPalette.Disabled, QPalette.ButtonText, QColor(110, 110, 120))
    
    app.setPalette(palette)

def main():
    app = QApplication(sys.argv)
    setup_dark_theme(app)
    
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
