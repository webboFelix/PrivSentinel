"""Administrator credential confirmation for identity removal and re-enrollment."""

from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QVBoxLayout,
    QWidget,
)


class AdministratorConfirmationDialog(QDialog):
    def __init__(
        self,
        title: str,
        message: str,
        confirm_text: str,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(True)
        layout = QVBoxLayout(self)
        explanation = QLabel(message)
        explanation.setWordWrap(True)
        layout.addWidget(explanation)

        form = QFormLayout()
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("COMPUTER\\admin or DOMAIN\\admin")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText("Administrator password")
        form.addRow("Administrator account", self.username_input)
        form.addRow("Password", self.password_input)
        layout.addLayout(form)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok
            | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText(confirm_text)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def credentials(self) -> tuple[str, str]:
        return self.username_input.text(), self.password_input.text()

    def clear_password(self) -> None:
        self.password_input.clear()
