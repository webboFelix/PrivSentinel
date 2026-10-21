"""Administrator credential confirmation for identity removal and re-enrollment."""

from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QVBoxLayout,
    QWidget,
)

from src.security.windows_auth import authenticate_windows_administrator


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


def confirm_windows_administrator(
    parent: QWidget,
    title: str,
    message: str,
    confirm_text: str = "Verify and continue",
) -> bool:
    dialog = AdministratorConfirmationDialog(
        title,
        message,
        confirm_text,
        parent,
    )
    if dialog.exec() != QDialog.DialogCode.Accepted:
        dialog.clear_password()
        return False

    username, password = dialog.credentials()
    try:
        authorized = authenticate_windows_administrator(username, password)
    except OSError as exc:
        QMessageBox.critical(
            parent,
            "Could not verify administrator credentials",
            str(exc),
        )
        return False
    finally:
        dialog.clear_password()

    if not authorized:
        QMessageBox.warning(
            parent,
            "Administrator verification failed",
            "The credentials are invalid or the account is not a Windows "
            "administrator. No changes were made.",
        )
        return False
    return True
