import sys, math

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QFrame



def calculate_cvss_score(attack_vector, attack_complexity, privileges_required, user_interaction, scope,
                         confidentiality, integrity, availability):
    w = {
        "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
        "AC": {"L": 0.77, "H": 0.44},
        "PR": {"N": 0.85, "L": 0.62, "H": 0.27, "Lscope": 0.68, "Hscope": 0.5, "Nscope": 0.85},
        "UI": {"N": 0.85, "R": 0.62},
        "S": {"U": 6.42, "C": 7.52},
        "C": {"N": 0, "L": 0.22, "H": 0.56},
        "I": {"N": 0, "L": 0.22, "H": 0.56},
        "A": {"N": 0, "L": 0.22, "H": 0.56},
    }

    if scope == "U":
        pr = w["PR"][privileges_required]
    elif scope == "C" and (privileges_required in {"L", "H"}):
        pr = w["PR"][privileges_required + "scope"]
    else:
        pr = w["PR"][privileges_required]

    isc_base = 1 - ((1 - w["C"][confidentiality]) * (1 - w["I"][integrity]) * (1 - w["A"][availability]))

    if scope == "U":
        impact = w["S"][scope] * isc_base
    else:
        impact = (w["S"][scope] * (isc_base - 0.029)) - 3.25 * (isc_base - 0.02) ** 15

    exploitability = 8.22 * w["AV"][attack_vector] * w["AC"][attack_complexity] * pr * w["UI"][user_interaction]
    score = 0

    if impact <= 0:
        score = 0
    elif scope == "U":
        score = min(impact + exploitability, 10)
    elif scope == "C":
        score = min(1.08 * (impact + exploitability), 10)

    return round_up(score, 1)


def round_up(n, decimals=0):
    multiplier = 10 ** decimals
    return math.ceil(n * multiplier) / multiplier



class CVSSCalculator(QWidget):
    def __init__(self):
        super().__init__()

        self.initUI()

    def initUI(self):
        self.setWindowTitle('Kalkulator CVSS v3.1')

        self.setStyleSheet("""
            CVSSCalculator {
                background-color: #282c34;
            }
            QLabel {
                color: #abb2bf;
                font-size: 16px;
            }
            QPushButton {
                background-color: #3b4048;
                color: #abb2bf;
                font-size: 12px;
                border: none;
                border-radius: 5px;
                padding: 5px;
            }
            QPushButton:hover {
                background-color: #4b5260;
            }
            QPushButton:checked {
                background-color: #2cbe4e;
                color: #000000;
            }
            QPushButton:!checked {
                color: #abb2bf;
            }
            QFrame QLabel {
                font-size: 14px;
            }
        """)

        vbox = QVBoxLayout()

        # Tworzenie interfejsu użytkownika
        labels = [
            "Attack Vector (AV)", "Attack Complexity (AC)", "Privileges Required (PR)",
            "User Interaction (UI)", "Scope (S)", "Confidentiality (C)",
            "Integrity (I)", "Availability (A)"
        ]

        options = [
            ["Network (N)", "Adjacent (A)", "Local (L)", "Physical (P)"],
            ["Low (L)", "High (H)"],
            ["None (N)", "Low (L)", "High (H)"],
            ["None (N)", "Required (R)"],
            ["Unchanged (U)", "Changed (C)"],
            ["None (N)", "Low (L)", "High (H)"],
            ["None (N)", "Low (L)", "High (H)"],
            ["None (N)", "Low (L)", "High (H)"]
        ]
        options_short = [
            ["N", "A", "L", "P"],
            ["L", "H"],
            ["N", "L", "H"],
            ["N", "R"],
            ["U", "C"],
            ["N", "L", "H"],
            ["N", "L", "H"],
            ["N", "L", "H"]
        ]

        self.button_groups = []

        for i in range(len(labels)):
            hbox = QHBoxLayout()
            label = QLabel(labels[i])
            hbox.addWidget(label)

            button_group = []

            for j, option in enumerate(options[i]):
                button = QPushButton(option, self)
                button.setCheckable(True)
                button.setMaximumWidth(150)
                button.clicked.connect(self.update_score)
                hbox.addWidget(button)
                button_group.append((button, options_short[i][j]))

                if j == 0:
                    button.setChecked(True)

            vbox.addLayout(hbox)
            self.button_groups.append(button_group)

        # Tworzenie etykiety wyniku
        self.score_frame = QFrame()
        self.score_frame.setFixedSize(250, 100)
        self.score_layout = QVBoxLayout()
        self.score_frame.setStyleSheet("background-color: green;border-radius: 8px;border: none;")
        self.score_label = QLabel("Base Score: 0.0")
        self.score_label.setStyleSheet("font-size: 20px; color: white;font-weight: bold;")
        self.score_rating = QLabel("Rating: None")
        self.score_rating.setStyleSheet("font-size: 20px; color: white;font-weight: bold;")
        self.score_layout.addWidget(self.score_label)
        self.score_layout.addWidget(self.score_rating)
        self.score_frame.setLayout(self.score_layout)
        vbox.addWidget(self.score_frame)

        self.setGeometry(300, 300, 800, 500)

        self.setLayout(vbox)

    def handle_button_click(self):
        clicked_button = self.sender()
        for group in self.button_groups:
            if clicked_button in (button for button, short in group):
                for button, _ in group:
                    if button == clicked_button:
                        button.setChecked(True)

                    else:
                        button.setChecked(False)

    def update_score(self):
        self.handle_button_click()
        values = [next(short for button, short in group if button.isChecked()) for group in self.button_groups]
        score = calculate_cvss_score(*values)
        self.score_frame.setStyleSheet("background-color: green;border-radius: 8px;border: none;")
        self.score_label.setText(f"Base Score: {score}")
        if 0.0 <= score <= 3.9:
            self.score_frame.setStyleSheet("background-color: green;border-radius: 8px;border: none;")
            self.score_rating.setText("Rating: Low")
        elif 4.0 <= score <= 6.9:
            self.score_frame.setStyleSheet("background-color: #ffa812 ;border-radius: 8px;border: none;")
            self.score_rating.setText("Rating: Medium")
        elif 7.0 <= score <= 8.9:
            self.score_frame.setStyleSheet("background-color: #c4342d; border-radius: 8px;border: none;")
            self.score_rating.setText("Rating: High")
        else:
            self.score_frame.setStyleSheet("background-color: crimson;border-radius: 8px;border: none;")
            self.score_rating.setText("Rating: Critical")

def main():
    app = QApplication(sys.argv)
    calculator = CVSSCalculator()
    calculator.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
