# PrivSentinel

A privacy-first Windows endpoint security application.

## Development

Create a virtual environment and install the project dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

Run the desktop UI from the repository root:

```powershell
.\.venv\Scripts\python.exe -m src
```

The script entry point also works when the current directory is `src\app`:

```powershell
..\..\.venv\Scripts\python.exe application.py
```

The dark-blue PySide6 shell includes a responsive dashboard and 13 linked
sections, global page search (`Ctrl+K`), filtered local-record tables, and
explicit empty/error states. Its dashboard charts use pyqtgraph and OpenGL for
rotating 3D event, alert, file-integrity, and identity views. They display only
locally persisted records and remain explicitly empty until real events exist;
the bundled icon set is used throughout the navigation and dashboard.
Monitoring, scans, exports, biometric enrollment, and remote intelligence
remain inactive until their real local providers are configured.

On Windows, the application creates `%LOCALAPPDATA%\PrivSentinel\` and its
`data`, `logs`, `backups`, `secrets`, `exports`, and `quarantine` directories
on first launch. Validated, versioned settings and window state are stored in
`settings.json` with atomic replacement and schema migrations. The Settings
page can reset, back up, and restore configuration; log level and retention
changes are applied to the local rotating file logger. Sensitive key material
belongs in the separate Windows DPAPI-protected secret store and is never
serialized to `settings.json`.

Run UI tests with:

```powershell
.\.venv\Scripts\python.exe -m pytest src\tests\ui
```
