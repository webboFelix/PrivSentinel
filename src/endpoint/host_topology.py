"""Local host, live socket, gateway, and removable-storage inventory."""

from __future__ import annotations

import ipaddress
import os
import socket
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
class HostTopology:
    hostname: str
    local_addresses: tuple[str, ...]
    gateways: tuple[str, ...]
    endpoints: tuple[ActiveEndpoint, ...]
    removable_storage: tuple[RemovableStorage, ...]
    warnings: tuple[str, ...]


class HostTopologyCollector:
    """Collect only locally available host facts; no network probes are sent."""

    def collect(self) -> HostTopology:
        warnings: list[str] = []
        addresses = self._local_addresses(warnings)
        gateways = self._default_gateways(warnings)
        endpoints = self._active_endpoints(warnings)
        removable = self._removable_storage(warnings)
        return HostTopology(
            hostname=socket.gethostname(),
            local_addresses=addresses,
            gateways=gateways,
            endpoints=endpoints,
            removable_storage=removable,
            warnings=tuple(warnings),
        )

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
