"""Local host, live socket, gateway, and removable-storage inventory."""

from __future__ import annotations

import base64
import ipaddress
import json
import os
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

import psutil


@dataclass(frozen=True, slots=True)
class ActiveEndpoint:
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    protocol: str
    state: str
    pid: int | None
    process_name: str
    username: str


@dataclass(frozen=True, slots=True)
class RemovableStorage:
    mount_point: str
    label: str


@dataclass(frozen=True, slots=True)
class AttachedDevice:
    instance_id: str
    label: str
    kind: str
    detail: str


@dataclass(frozen=True, slots=True)
class HostTopology:
    hostname: str
    local_addresses: tuple[str, ...]
    gateways: tuple[str, ...]
    endpoints: tuple[ActiveEndpoint, ...]
    removable_storage: tuple[RemovableStorage, ...]
    warnings: tuple[str, ...]
    attached_devices: tuple[AttachedDevice, ...] = ()


class HostTopologyCollector:
    """Collect only locally available host facts; no network probes are sent."""

    def __init__(self) -> None:
        self._attached_device_cache: dict[str, dict[str, object]] = {}

    def collect(self) -> HostTopology:
        warnings: list[str] = []
        route_warnings: list[str] = []
        device_warnings: list[str] = []
        with ThreadPoolExecutor(max_workers=2, thread_name_prefix="host-topology") as pool:
            gateway_task = pool.submit(self._default_gateways, route_warnings)
            device_task = pool.submit(
                self._attached_devices,
                device_warnings,
                self._attached_device_cache,
            )
            addresses = self._local_addresses(warnings)
            endpoints = self._active_endpoints(warnings)
            removable = self._removable_storage(warnings)
            gateways = gateway_task.result()
            devices = device_task.result()
        warnings.extend(route_warnings)
        warnings.extend(device_warnings)
        return HostTopology(
            hostname=socket.gethostname(),
            local_addresses=addresses,
            gateways=gateways,
            endpoints=endpoints,
            removable_storage=removable,
            warnings=tuple(warnings),
            attached_devices=devices,
        )

    @staticmethod
    def _attached_devices(
        warnings: list[str],
        property_cache: dict[str, dict[str, object]] | None = None,
    ) -> tuple[AttachedDevice, ...]:
        if os.name != "nt":
            return ()
        cache_payload = base64.b64encode(
            json.dumps(
                [
                    {"InstanceId": instance_id, **properties}
                    for instance_id, properties in (property_cache or {}).items()
                ]
            ).encode("utf-8")
        ).decode("ascii")
        command = (
            "$ErrorActionPreference = 'Stop'; "
            "$cacheJson = [Text.Encoding]::UTF8.GetString("
            f"[Convert]::FromBase64String('{cache_payload}')); "
            "$propertyCache = @($cacheJson | ConvertFrom-Json); "
            "$devices = @(Get-PnpDevice -PresentOnly | "
            "Where-Object { ($_.Class -eq 'USB' -and "
            "$_.InstanceId -match '^USB\\\\VID_' -and "
            "$_.InstanceId -notmatch '&MI_') -or $_.Class -eq 'WPD' -or "
            "($_.Class -eq 'Ports' -and $_.InstanceId -match '^USB\\\\' -and "
            "$_.FriendlyName -match '\\(COM\\d+\\)') -or "
            "$_.Class -eq 'Monitor' } | "
            "ForEach-Object { "
            "$device = $_; "
            "$cached = $propertyCache | Where-Object "
            "{ $_.InstanceId -eq $device.InstanceId } | Select-Object -First 1; "
            "$registryKey = 'HKLM:\\SYSTEM\\CurrentControlSet\\Enum\\' + "
            "$device.InstanceId; "
            "$registry = Get-ItemProperty -LiteralPath $registryKey "
            "-ErrorAction SilentlyContinue; "
            "$removable = $null -ne $registry -and "
            "(($registry.Capabilities -band 4) -ne 0); "
            "$descriptionQueried = $removable -and "
            "$device.Class -in @('USB', 'WPD') -and "
            "$device.FriendlyName -match '^(USB Composite Device|MTP USB Device|USB Device)$'; "
            "$descriptionValue = if ($cached) { $cached.BusDescription } "
            "elseif ($descriptionQueried) "
            "{ (Get-PnpDeviceProperty -InstanceId $device.InstanceId "
            "-KeyName 'DEVPKEY_Device_BusReportedDeviceDesc' "
            "-ErrorAction SilentlyContinue | Select-Object -First 1).Data } "
            "else { $null }; "
            "$removalValue = if ($removable) { 3 } else { 1 }; "
            "[pscustomobject]@{ Class = $device.Class; "
            "FriendlyName = $device.FriendlyName; InstanceId = $device.InstanceId; "
            "Status = $device.Status; "
            "Parent = $null; ContainerId = $registry.ContainerID; "
            "RemovalPolicy = $removalValue; BusDescription = $descriptionValue; "
            "BusDescriptionQueried = $descriptionQueried "
            "} } ); "
            "$displays = @(); "
            "try { $displays = @(Get-CimInstance "
            "-Namespace root\\wmi -ClassName WmiMonitorConnectionParams | "
            "Where-Object { $_.VideoOutputTechnology -ne 11 } | "
            "Select-Object InstanceName, VideoOutputTechnology) } catch { }; "
            "[pscustomobject]@{ devices = $devices; displays = $displays } | "
            "ConvertTo-Json -Compress -Depth 3"
        )
        try:
            result = subprocess.run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    command,
                ],
                capture_output=True,
                check=True,
                encoding="utf-8",
                timeout=10,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            inventory = json.loads(result.stdout or "{}")
        except (
            FileNotFoundError,
            subprocess.SubprocessError,
            OSError,
            json.JSONDecodeError,
        ) as exc:
            detail = (
                str(exc.stderr or exc.stdout or exc).strip()
                if isinstance(exc, subprocess.CalledProcessError)
                else str(exc)
            )
            warnings.append(f"Attached-device inventory unavailable: {detail}")
            return ()

        if not isinstance(inventory, dict):
            warnings.append("Attached-device inventory returned an invalid response.")
            return ()

        display_types = {
            0: "VGA",
            4: "DVI",
            5: "HDMI",
            10: "DisplayPort",
            11: "Embedded DisplayPort",
        }
        displays = inventory.get("displays", [])
        display_rows = displays if isinstance(displays, list) else [displays]
        display_connections = {
            str(item.get("InstanceName", "")).casefold(): display_types.get(
                item.get("VideoOutputTechnology")
            )
            for item in display_rows
            if isinstance(item, dict) and item.get("InstanceName")
        }
        rows = inventory.get("devices", [])
        device_rows = rows if isinstance(rows, list) else [rows]
        if property_cache is not None:
            present_ids = {
                str(item.get("InstanceId", "")).strip()
                for item in device_rows
                if isinstance(item, dict)
            }
            for instance_id in set(property_cache) - present_ids:
                property_cache.pop(instance_id, None)
            for item in device_rows:
                if not isinstance(item, dict):
                    continue
                instance_id = str(item.get("InstanceId", "")).strip()
                if instance_id and item.get("BusDescriptionQueried"):
                    property_cache[instance_id] = {
                        "BusDescription": item.get("BusDescription"),
                    }
        devices: dict[str, tuple[int, AttachedDevice]] = {}
        serial_ports: dict[str, set[str]] = {}
        for item in device_rows:
            if not isinstance(item, dict):
                continue
            if str(item.get("Class", "")).casefold() != "ports":
                continue
            port_match = re.search(
                r"\((COM\d+)\)",
                str(item.get("FriendlyName") or ""),
                re.IGNORECASE,
            )
            product_match = re.match(
                r"^(USB\\VID_[^&\\]+&PID_[^&\\]+)",
                str(item.get("InstanceId") or ""),
                re.IGNORECASE,
            )
            if port_match and product_match:
                serial_ports.setdefault(
                    product_match.group(1).casefold(),
                    set(),
                ).add(port_match.group(1).upper())
        removable_product_counts: dict[str, int] = {}
        for item in device_rows:
            if (
                isinstance(item, dict)
                and str(item.get("Class", "")).casefold() in {"usb", "wpd"}
                and item.get("RemovalPolicy") == 3
                and "&MI_" not in str(item.get("InstanceId") or "").upper()
            ):
                product_match = re.match(
                    r"^(USB\\VID_[^&\\]+&PID_[^&\\]+)",
                    str(item.get("InstanceId") or ""),
                    re.IGNORECASE,
                )
                if product_match:
                    product_key = product_match.group(1).casefold()
                    removable_product_counts[product_key] = (
                        removable_product_counts.get(product_key, 0) + 1
                    )
        active_displays = tuple(display_connections)
        for item in device_rows:
            if not isinstance(item, dict):
                continue
            instance_id = str(item.get("InstanceId", "")).strip()
            if not instance_id:
                continue
            device_class = str(item.get("Class", "")).casefold()
            friendly_name = str(item.get("FriendlyName") or "").strip()
            status = str(item.get("Status") or "Unknown")
            if device_class == "monitor":
                if "integrated" in friendly_name.casefold():
                    continue
                normalized_instance = instance_id.casefold()
                active_instance = next(
                    (
                        display_instance
                        for display_instance in active_displays
                        if display_instance.startswith(normalized_instance)
                        or normalized_instance.startswith(display_instance)
                    ),
                    None,
                )
                if active_instance is None:
                    continue
                kind = "display"
                label = display_connections[active_instance] or "Monitor"
                detail = f"Connected · {status}"
            elif device_class == "wpd":
                if (
                    not instance_id.upper().startswith("USB\\VID_")
                    or item.get("RemovalPolicy") != 3
                ):
                    continue
                kind = "usb"
                label = str(item.get("BusDescription") or friendly_name).strip()
                if not label or label.casefold() == "mtp usb device":
                    label = "USB phone"
                detail = f"Connected · {status}"
            elif instance_id.upper().startswith("USB\\VID_"):
                if (
                    "&MI_" in instance_id.upper()
                    or item.get("RemovalPolicy") != 3
                ):
                    continue
                kind = "usb"
                label = str(item.get("BusDescription") or friendly_name).strip()
                if not label or label.casefold() == "usb composite device":
                    label = "USB device"
                detail = f"Connected · {status}"
                product_match = re.match(
                    r"^(USB\\VID_[^&\\]+&PID_[^&\\]+)",
                    instance_id,
                    re.IGNORECASE,
                )
                if product_match:
                    product_key = product_match.group(1).casefold()
                    ports = (
                        serial_ports.get(product_key, set())
                        if removable_product_counts.get(product_key) == 1
                        else set()
                    )
                    if ports:
                        detail += f" · serial {', '.join(sorted(ports))}"
            else:
                continue
            container_id = str(item.get("ContainerId") or "").strip("{}").casefold()
            if not container_id or container_id == "00000000-0000-0000-ffff-ffffffffffff":
                container_id = re.sub(
                    r"&MI_\d+",
                    "",
                    instance_id,
                    flags=re.IGNORECASE,
                ).casefold()
            key = container_id
            candidate = AttachedDevice(
                instance_id=instance_id,
                label=label,
                kind=kind,
                detail=detail,
            )
            current = devices.get(key)
            rank = 2 if device_class == "wpd" else 1
            if current is None or rank > current[0]:
                devices[key] = (rank, candidate)
        return tuple(devices[key][1] for key in sorted(devices))

    @staticmethod
    def _local_addresses(warnings: list[str]) -> tuple[str, ...]:
        try:
            interfaces = psutil.net_if_addrs()
            interface_status = psutil.net_if_stats()
        except OSError as exc:
            warnings.append(f"Local interface addresses unavailable: {exc}")
            return ()
        values: set[str] = set()
        for interface, interface_addresses in interfaces.items():
            status = interface_status.get(interface)
            if status is None or not status.isup:
                continue
            for item in interface_addresses:
                if item.family not in (socket.AF_INET, socket.AF_INET6):
                    continue
                address = str(item.address).split("%", 1)[0]
                try:
                    parsed = ipaddress.ip_address(address)
                except ValueError:
                    continue
                if (
                    not parsed.is_loopback
                    and not parsed.is_unspecified
                    and not parsed.is_link_local
                ):
                    values.add(str(parsed))
        return tuple(sorted(values, key=lambda value: (":" in value, value)))

    @staticmethod
    def _active_endpoints(warnings: list[str]) -> tuple[ActiveEndpoint, ...]:
        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError) as exc:
            warnings.append(f"Live socket inventory unavailable: {exc}")
            return ()
        process_details: dict[int, tuple[str, str]] = {}
        endpoints: dict[tuple[str, str, int, int], ActiveEndpoint] = {}
        for connection in connections:
            local = connection.laddr
            remote = connection.raddr
            if not remote:
                continue
            try:
                remote_address = str(ipaddress.ip_address(remote.ip.split("%", 1)[0]))
            except ValueError:
                continue
            local_address = ""
            local_port = 0
            if local:
                try:
                    local_address = str(
                        ipaddress.ip_address(local.ip.split("%", 1)[0])
                    )
                except ValueError:
                    local_address = str(local.ip)
                local_port = int(local.port)
            pid = connection.pid
            process_name = username = "Unavailable"
            if pid is not None:
                if pid not in process_details:
                    try:
                        process = psutil.Process(pid)
                        process_details[pid] = (process.name(), process.username())
                    except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                        process_details[pid] = ("Unavailable", "Unavailable")
                process_name, username = process_details[pid]
            protocol = "TCP" if connection.type == socket.SOCK_STREAM else "UDP"
            endpoint = ActiveEndpoint(
                local_address=local_address,
                local_port=local_port,
                remote_address=remote_address,
                remote_port=int(remote.port),
                protocol=protocol,
                state=str(connection.status or "—"),
                pid=pid,
                process_name=process_name,
                username=username,
            )
            key = (
                remote_address,
                local_address,
                int(remote.port),
                int(pid or 0),
            )
            endpoints[key] = endpoint
        return tuple(
            sorted(
                endpoints.values(),
                key=lambda item: (
                    not ipaddress.ip_address(item.remote_address).is_global,
                    item.remote_address,
                    item.remote_port,
                ),
            )
        )

    @staticmethod
    def _default_gateways(warnings: list[str]) -> tuple[str, ...]:
        if os.name != "nt":
            return ()
        try:
            result = subprocess.run(
                ["route.exe", "print", "-4"],
                capture_output=True,
                check=True,
                encoding="utf-8",
                errors="replace",
                timeout=4,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except OSError as exc:
            warnings.append(f"Active default route unavailable: {exc}")
            return ()
        except subprocess.SubprocessError as exc:
            warnings.append(f"Active default route unavailable: {exc}")
            return ()

        active_interfaces = set(HostTopologyCollector._local_addresses(warnings))
        candidates: list[tuple[int, str]] = []
        for line in result.stdout.splitlines():
            if "persistent routes" in line.casefold():
                break
            columns = line.split()
            if len(columns) < 5 or columns[:2] != ["0.0.0.0", "0.0.0.0"]:
                continue
            gateway, interface = columns[2:4]
            try:
                gateway_address = ipaddress.ip_address(gateway)
                metric = int(columns[4])
            except ValueError:
                continue
            if (
                gateway_address.version == 4
                and not gateway_address.is_unspecified
                and not gateway_address.is_loopback
                and interface in active_interfaces
            ):
                candidates.append((metric, str(gateway_address)))
        if not candidates:
            return ()
        return (min(candidates)[1],)

    @staticmethod
    def _removable_storage(warnings: list[str]) -> tuple[RemovableStorage, ...]:
        if os.name != "nt":
            return ()
        import ctypes

        try:
            partitions = psutil.disk_partitions(all=True)
        except (psutil.AccessDenied, OSError) as exc:
            warnings.append(f"Removable-storage inventory unavailable: {exc}")
            return ()
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        get_drive_type = kernel32.GetDriveTypeW
        get_drive_type.argtypes = [ctypes.c_wchar_p]
        get_drive_type.restype = ctypes.c_uint
        get_volume_information = kernel32.GetVolumeInformationW
        get_volume_information.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_uint,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_wchar_p,
            ctypes.c_uint,
        ]
        get_volume_information.restype = ctypes.c_int
        found: dict[str, RemovableStorage] = {}
        for partition in partitions:
            drive, _ = os.path.splitdrive(partition.mountpoint)
            if not drive:
                continue
            mount_point = drive + "\\"
            if get_drive_type(mount_point) != 2:
                continue
            volume_name = ctypes.create_unicode_buffer(261)
            filesystem_name = ctypes.create_unicode_buffer(261)
            has_label = get_volume_information(
                mount_point,
                volume_name,
                len(volume_name),
                None,
                None,
                None,
                filesystem_name,
                len(filesystem_name),
            )
            label = volume_name.value if has_label else ""
            found[mount_point.casefold()] = RemovableStorage(
                mount_point=mount_point,
                label=label or "Removable USB storage",
            )
        return tuple(found[key] for key in sorted(found))
