from unittest.mock import Mock

from src.app.application import _qt_exception_hook


def test_keyboard_interrupt_in_qt_callback_requests_clean_shutdown():
    app = Mock()
    previous = Mock()
    hook = _qt_exception_hook(app, previous)

    hook(KeyboardInterrupt, KeyboardInterrupt(), None)

    app.quit.assert_called_once_with()
    previous.assert_not_called()


def test_non_interrupt_qt_exception_uses_previous_exception_hook():
    app = Mock()
    previous = Mock()
    hook = _qt_exception_hook(app, previous)
    error = ValueError("callback failed")

    hook(ValueError, error, None)

    previous.assert_called_once_with(ValueError, error, None)
    app.quit.assert_not_called()
