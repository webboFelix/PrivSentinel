param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path,
    [string]$PythonExe = ""
)

$ErrorActionPreference = "Stop"

if (-not $PythonExe) {
    $venvPython = Join-Path $RepoRoot ".venv\Scripts\python.exe"
    if (Test-Path $venvPython) {
        $PythonExe = $venvPython
    } else {
        $pythonCommand = Get-Command python.exe -ErrorAction SilentlyContinue
        if ($pythonCommand) {
            $PythonExe = $pythonCommand.Source
        }
    }
}

if (-not $PythonExe -or -not (Test-Path $PythonExe)) {
    throw "Pass -PythonExe with a real python.exe path; Windows app-execution aliases are not supported."
}

$mainScript = Join-Path $RepoRoot "src\app\application.py"
if (-not (Test-Path $mainScript)) {
    throw "Could not find the PrivSentinel source entry point at $mainScript."
}

function Read-ExtensionId([string]$Browser) {
    while ($true) {
        $value = Read-Host "Load src\browser\extension in $Browser, then enter its 32-character extension ID"
        $value = $value.Trim()
        if ($value -match "^[a-p]{32}$") {
            return $value
        }
        Write-Host "The extension ID must contain exactly 32 characters in the range a-p." -ForegroundColor Yellow
    }
}

$chromeId = Read-ExtensionId "Chrome"
$edgeId = Read-ExtensionId "Edge"
$braveId = Read-ExtensionId "Brave"
$firefoxId = "privsentinel-web-protection@privsentinel.local"
$localBrowserPath = Join-Path $env:LOCALAPPDATA "PrivSentinel\browser"
New-Item -ItemType Directory -Path $localBrowserPath -Force | Out-Null
$hostManifestPath = Join-Path $localBrowserPath "com.privsentinel.browser.json"

$manifest = @{
    name = "com.privsentinel.browser"
    description = "PrivSentinel local browser reputation connector"
    path = $PythonExe
    type = "stdio"
    args = @($mainScript, "--privsentinel-browser-host")
    allowed_origins = @(
        "chrome-extension://$chromeId/",
        "chrome-extension://$edgeId/",
        "chrome-extension://$braveId/"
    )
    allowed_extensions = @($firefoxId)
}

$manifest | ConvertTo-Json -Depth 5 | Set-Content -Path $hostManifestPath -Encoding utf8
$registrations = @(
    "Software\Google\Chrome\NativeMessagingHosts\com.privsentinel.browser",
    "Software\Microsoft\Edge\NativeMessagingHosts\com.privsentinel.browser",
    "Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\com.privsentinel.browser",
    "Software\Mozilla\NativeMessagingHosts\com.privsentinel.browser"
)

foreach ($registration in $registrations) {
    $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($registration)
    try {
        $key.SetValue("", $hostManifestPath, [Microsoft.Win32.RegistryValueKind]::String)
    } finally {
        $key.Dispose()
    }
}

Write-Host "PrivSentinel native messaging host registered for Chrome, Edge, Brave, and Firefox."
Write-Host "Restart each browser after loading the extension."
