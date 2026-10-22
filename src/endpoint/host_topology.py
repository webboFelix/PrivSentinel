"""Local host, live socket, gateway, and removable-storage inventory."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import subprocess
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

    def collect(self) -> HostTopology:
        warnings: list[str] = []
        addresses = self._local_addresses(warnings)
        gateways = self._default_gateways(warnings)
        endpoints = self._active_endpoints(warnings)
        removable = self._removable_storage(warnings)
        devices = self._attached_devices(warnings)
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
    def _attached_devices(warnings: list[str]) -> tuple[AttachedDevice, ...]:
        if os.name != "nt":
            return ()
        command = (
            "$ErrorActionPreference = 'Stop'; "
            "$devices = @(Get-PnpDevice -PresentOnly | "
            "Where-Object { ($_.InstanceId -match '^USB\\\\VID_' -and "
            "$_.InstanceId -notmatch '&MI_') -or "
            "$_.Class -in @('Ports', 'Monitor') } | "
            "Select-Object Class, FriendlyName, InstanceId); "
            "$displays = @(); "
            "try { $displays = @(Get-CimInstance "
            "-Namespace root\\wmi -ClassName WmiMonitorConnectionParams | "
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
                timeout=6,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            inventory = json.loads(result.stdout or "{}")
        except (
            FileNotFoundError,
            subprocess.SubprocessError,
            OSError,
            json.JSONDecodeError,
        ) as exc:
            warnings.append(f"Attached-device inventory unavailable: {exc}")
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
        devices: dict[str, AttachedDevice] = {}
        active_displays = tuple(display_connections)
        for item in device_rows:
            if not isinstance(item, dict):
                continue
            instance_id = str(item.get("InstanceId", "")).strip()
            if not instance_id:
                continue
            device_class = str(item.get("Class", "")).casefold()
            friendly_name = str(item.get("FriendlyName") or "").strip()
            if device_class == "ports":
                if not instance_id.upper().startswith("USB\\VID_"):
                    continue
                kind = "serial"
                port = re.search(r"\((COM\d+)\)", friendly_name, re.IGNORECASE)
                label = port.group(1).upper() if port else "Serial port"
            elif device_class == "monitor":
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
            elif instance_id.upper().startswith("USB\\VID_"):
                kind = "usb"
                if not friendly_name:
                    continue
                label = friendly_name
            else:
                continue
            physical_id = re.sub(r"&MI_\d+", "", instance_id, flags=re.IGNORECASE)
            key = physical_id.casefold()
            candidate = AttachedDevice(
                instance_id=instance_id,
                label=label,
                kind=kind,
                detail="Connected",
            )
            current = devices.get(key)
            if current is None or (kind == "serial" and current.kind != "serial"):
                devices[key] = candidate
        return tuple(devices[key] for key in sorted(devices))

    @staticmethod
    def _local_addresses(warnings: list[str]) -> tuple[str, ...]:
        try:
            interfaces = psutil.net_if_addrs()
        except OSError as exc:
            warnings.append(f"Local interface addresses unavailable: {exc}")
            return ()
        values: set[str] = set()
        for interface_addresses in interfaces.values():
            for item in interface_addresses:
                if item.family not in (socket.AF_INET, socket.AF_INET6):
                    continue
                address = str(item.address).split("%", 1)[0]
                try:
                    parsed = ipaddress.ip_address(address)
                except ValueError:
                    continue
                if not parsed.is_loopback and not parsed.is_unspecified:
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
        import winreg

        gateways: set[str] = set()
        interface_key_path = (
            r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
        )
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, interface_key_path) as key:
                index = 0
                while True:
                    try:
                        interface = winreg.EnumKey(key, index)
                    except OSError:
                        break
                    index += 1
                    try:
                        with winreg.OpenKey(key, interface) as interface_key:
                            for value_name in ("DefaultGateway", "DhcpDefaultGateway"):
                                try:
                                    value, _ = winreg.QueryValueEx(
                                        interface_key, value_name
                                    )
                                except FileNotFoundError:
                                    continue
                                candidates = (
                                    value if isinstance(value, (tuple, list)) else (value,)
                                )
                                for candidate in candidates:
                                    try:
                                        address = ipaddress.ip_address(str(candidate))
                                    except ValueError:
                                        continue
                                    if not address.is_unspecified:
                                        gateways.add(str(address))
                    except OSError:
                        continue
        except OSError as exc:
            warnings.append(f"Default gateway inventory unavailable: {exc}")
        return tuple(sorted(gateways))

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
