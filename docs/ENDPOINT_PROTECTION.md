# Endpoint scanning, reputation, and browser protection

## Malware scans

- **Microsoft Defender**: Malware Protection can request a Windows Defender full
  scan. Defender manages its own progress, definitions, quarantine, and remediation;
  PrivSentinel records that the scan was requested but does not claim a Defender
  file count or final verdict. Windows Defender cmdlets and a healthy Defender
  service are required.
- **YARA**: Select **Update YARA rules** before the first scan. This downloads and
  validates the current `Yara-Rules/rules` GitHub archive on demand. The upstream
  rule set is GPL-2.0; consult its license before distributing the downloaded
  rules. PrivSentinel does not bundle those rules.
- **Coverage**: The YARA full scan walks mounted local volumes and scans accessible
  regular files. Permission failures, locked/encrypted files, reparse points, and
  special device areas may be skipped and are counted as errors where reported.
  A YARA match is a rule hit that needs review, not proof of malware. YARA
  quarantine is user-confirmed, hash-verified, and reversible. It never silently
  deletes a file.

## External reputation providers

- **URLhaus**: An Auth-Key is required by the current community export API. Create
  one through the abuse.ch authentication portal, then save it on the Threat
  Intelligence page. Feed synchronization downloads active/recent URL records to
  local storage. Browser visits are compared to that local feed; the visited URL
  is not submitted to URLhaus. Synchronize no more frequently than the provider's
  documented limits.
- **VirusTotal**: Save an API key on the Threat Intelligence page. Lookups are
  user-triggered for one selected IP, domain, or SHA-256 hash and cached locally
  for 24 hours. PrivSentinel does not upload files or send full URL paths. The
  selected indicator is sent to VirusTotal; review its terms and quota limits.
  “No record” and “no detections” are not safety guarantees.
- Provider keys are encrypted with Windows DPAPI for the current Windows user.
  They are not written to the settings JSON or application logs.

## Chrome, Edge, Brave, and Firefox

1. Open the Browser Protection page and choose **Browser setup…**.
2. Load `src/browser/extension` as an unpacked/developer extension in Chrome,
   Edge, and Brave. Firefox can test it from `about:debugging` as a temporary
   extension; temporary add-ons are removed when Firefox closes. Persistent
   Firefox installation needs an appropriately signed package or enterprise
   deployment.
3. Run `src/scripts/install_browser_native_host.ps1` in PowerShell from the
   repository root. The script registers a per-user native-messaging host and
   asks for the Chromium extension IDs; no administrator rights are required.
4. Restart each browser and use the extension popup to refresh its local rules.

The extension applies browser navigation rules for URLhaus, cached malicious
VirusTotal domains, and analyst indicators. It records locally evaluated site
visits with query strings and fragments removed. A known match redirects to a
PrivSentinel warning page where the user can allow the domain. Unknown domains
default to allow and are explicitly not treated as safe. This is URL/domain
reputation filtering: it does not inspect page contents, encrypted traffic,
downloads in the browser, or third-party scripts embedded in an otherwise
allowed page. Browser policies, extension permissions, or a stopped native host
can prevent enforcement; verify the extension status after installation.

## Dashboard inventory

The dashboard topology shows one local IPv4 address, an IPv4 default gateway,
up to three private IPv4 peers observed in current local sockets, aggregate
public-peer activity, and a grouped removable-storage node. IPv6 addresses and
the local hostname are omitted from the topology display. It does not probe the
LAN, discover idle devices, enumerate every USB peripheral, or determine Windows
Firewall state. Endpoint IPs and process/user metadata are local observations,
not external reputation verdicts.

The Network Monitor reports aggregate upload/download rates from operating-system
interface byte counters. A sustained rate spike above the rolling adaptive
baseline raises an in-app prompt to review recorded connections. Interface rates
are not attributed to individual processes and do not inspect packet contents.
Any IP block remains a separate, explicitly confirmed firewall action.

File-integrity activity is grouped into the selected 24-hour, 7-day, or 30-day
period when a configured baseline scan observes a change. A rename is inferred
only when a missing path and a newly observed path have a unique matching hash;
the monitor cannot distinguish a move from a copy followed by deletion.
