#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# LinSpectacles - Linux Inspection Suite
# Copyright (C) 2026 brunonlinespace
# GPL-3.0-or-later

"""Read-only Linux TPM collectors for TPM Inspector 0.0.4."""

from __future__ import annotations

import re
import stat
from datetime import datetime
from pathlib import Path


TPM_CLASS_ROOT = Path("/sys/class/tpm")
SECURITYFS_ROOT = Path("/sys/kernel/security")
DEV_ROOT = Path("/dev")
_TPM_NAME_RE = re.compile(r"^tpm(\d+)$")
_PCR_NUMBER_RE = re.compile(r"^\d+$")


def _now_local():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _read_text(path):
    path = Path(path)
    try:
        return "observed", path.read_text(encoding="utf-8", errors="replace").strip()
    except PermissionError:
        return "restricted", ""
    except FileNotFoundError:
        return "unavailable", ""
    except OSError as exc:
        return "error", str(exc)


def _exists_state(path):
    try:
        Path(path).stat()
    except FileNotFoundError:
        return "absent"
    except PermissionError:
        return "restricted"
    except OSError:
        return "error"
    return "present"


def discover_tpm_roots():
    """Return (discovery state, explanation, numeric TPM sysfs entries).

    An empty successful listing is different from a missing, restricted, or
    failed sysfs listing. Never infer 'no TPM' after a failed acquisition.
    """
    try:
        entries = list(TPM_CLASS_ROOT.iterdir())
    except FileNotFoundError:
        return "unavailable", f"TPM sysfs source unavailable: {TPM_CLASS_ROOT}", []
    except PermissionError:
        return "restricted", f"Ordinary access to TPM sysfs source is restricted: {TPM_CLASS_ROOT}", []
    except OSError as exc:
        return "error", f"Could not enumerate TPM sysfs source {TPM_CLASS_ROOT}: {exc}", []

    result = []
    for entry in entries:
        match = _TPM_NAME_RE.fullmatch(entry.name)
        if match:
            result.append((int(match.group(1)), entry))
    return "observed", "TPM sysfs class enumerated normally.", sorted(result, key=lambda item: item[0])


def _tpm_roots():
    return discover_tpm_roots()[2]


def _driver_name(root):
    candidates = [root / "device" / "driver", root / "driver"]
    access_problem = None
    for candidate in candidates:
        try:
            if candidate.is_symlink() or candidate.exists():
                resolved = candidate.resolve(strict=False)
                return resolved.name or str(resolved), str(candidate), "observed"
        except PermissionError:
            access_problem = ("Restricted", str(candidate), "restricted")
        except OSError:
            if access_problem is None:
                access_problem = ("Error", str(candidate), "error")
    return access_problem or ("Not exposed", "Not exposed", "unavailable")


def _pcr_banks(root):
    banks = []
    try:
        entries = list(root.iterdir())
    except PermissionError:
        return "restricted", banks
    except FileNotFoundError:
        return "unavailable", banks
    except OSError:
        return "error", banks
    for entry in entries:
        try:
            is_dir = entry.is_dir()
        except OSError:
            is_dir = False
        if is_dir and entry.name.startswith("pcr-") and len(entry.name) > 4:
            banks.append(entry.name[4:])
    return "observed", sorted(set(banks), key=str.lower)


def _tpm_version(root):
    candidates = [root / "tpm_version_major", root / "device" / "tpm_version_major"]
    for path in candidates:
        state, value = _read_text(path)
        if state != "unavailable":
            return state, value, str(path)
    return "unavailable", "", str(candidates[0])


def _legacy_state_attributes(root):
    """Return only explicitly whitelisted legacy read-only state attributes."""
    rows = []
    for base in (root, root / "device"):
        for name in ("enabled", "active", "owned", "temp_deactivated"):
            path = base / name
            state, value = _read_text(path)
            if state == "unavailable":
                continue
            rows.append({
                "name": name,
                "value": value if state == "observed" else state.capitalize(),
                "source": str(path),
                "state": state,
            })
    unique = []
    seen = set()
    for row in rows:
        key = row["source"]
        if key not in seen:
            seen.add(key)
            unique.append(row)
    return unique


def collect_devices(roots=None):
    acquired = _now_local()
    rows = []
    for index, root in (roots if roots is not None else _tpm_roots()):
        tpm = f"tpm{index}"
        driver, driver_source, driver_state = _driver_name(root)
        version_state, version, version_source = _tpm_version(root)
        if version_state == "observed":
            shown_version = version or "Not reported"
        elif version_state == "restricted":
            shown_version = "Restricted"
        elif version_state == "error":
            shown_version = "Error"
        else:
            shown_version = "Not exposed"

        raw_node = DEV_ROOT / tpm
        rm_node = DEV_ROOT / f"tpmrm{index}"
        banks_state, banks = _pcr_banks(root)
        if banks_state == "observed":
            banks_text = ", ".join(banks) if banks else "None exposed"
        elif banks_state == "restricted":
            banks_text = "Restricted"
        elif banks_state == "error":
            banks_text = "Error"
        else:
            banks_text = "Not exposed"
        raw_state = _exists_state(raw_node)
        rm_state = _exists_state(rm_node)
        rows.append({
            "_view": "TPM Devices",
            "tpm": tpm,
            "version": shown_version,
            "device_node": str(raw_node) if raw_state == "present" else (
                "Restricted" if raw_state == "restricted" else
                "Error" if raw_state == "error" else "Not present"
            ),
            "driver": driver,
            "driver_source": driver_source,
            "driver_state": driver_state,
            "state": "Sysfs Exposed",
            "pcr_banks": banks_text,
            "pcr_banks_state": banks_state,
            "sysfs_path": str(root),
            "raw_node": str(raw_node),
            "raw_node_state": raw_state,
            "rm_node": str(rm_node),
            "rm_node_state": rm_state,
            "version_state": version_state,
            "version_source": version_source,
            "legacy_state": _legacy_state_attributes(root),
            "acquired": acquired,
        })
    return rows


def collect_pcrs_with_status(roots=None):
    """Collect only actual exposed PCR file records; report scan issues apart."""
    acquired = _now_local()
    rows = []
    issues = []
    for index, root in (roots if roots is not None else _tpm_roots()):
        tpm = f"tpm{index}"
        banks_state, banks = _pcr_banks(root)
        if banks_state != "observed":
            issues.append(f"{tpm}: PCR bank discovery {banks_state} at {root}")
            continue
        for bank in banks:
            bank_path = root / f"pcr-{bank}"
            try:
                entries = list(bank_path.iterdir())
            except PermissionError:
                issues.append(f"{tpm}: ordinary access to PCR bank {bank} is restricted")
                continue
            except FileNotFoundError:
                issues.append(f"{tpm}: PCR bank {bank} disappeared during acquisition")
                continue
            except OSError as exc:
                issues.append(f"{tpm}: PCR bank {bank} could not be read: {exc}")
                continue

            numbered = []
            for entry in entries:
                if _PCR_NUMBER_RE.match(entry.name):
                    numbered.append((int(entry.name), entry))
            for pcr_number, entry in sorted(numbered, key=lambda item: item[0]):
                state, value = _read_text(entry)
                if state == "observed":
                    shown = " ".join(value.splitlines()) if value else "(empty)"
                elif state == "restricted":
                    shown = "Restricted"
                elif state == "error":
                    shown = "Error"
                else:
                    shown = "Unavailable"
                rows.append({
                    "_view": "PCRs",
                    "tpm": tpm,
                    "bank": bank,
                    "pcr": pcr_number,
                    "value": shown,
                    "acquired": acquired,
                    "source": str(entry),
                    "read_state": state,
                })
    return rows, issues


def collect_pcrs(roots=None):
    return collect_pcrs_with_status(roots)[0]


def _event_log_candidates():
    """Find source paths and keep discovery failures distinct from absence."""
    try:
        children = list(SECURITYFS_ROOT.iterdir())
    except FileNotFoundError:
        return "unavailable", [], f"Securityfs location is unavailable: {SECURITYFS_ROOT}"
    except PermissionError:
        return "restricted", [], f"Securityfs location cannot be enumerated with ordinary access: {SECURITYFS_ROOT}"
    except OSError as exc:
        return "error", [], f"Securityfs enumeration failed: {exc}"

    candidates = []
    problems = []
    for directory in sorted(children, key=lambda item: item.name.lower()):
        if not _TPM_NAME_RE.fullmatch(directory.name):
            continue
        try:
            if not stat.S_ISDIR(directory.stat().st_mode):
                continue
            path = directory / "binary_bios_measurements"
            path.stat()
            candidates.append(path)
        except FileNotFoundError:
            continue
        except PermissionError:
            problems.append(f"Access restricted while checking {directory / 'binary_bios_measurements'}")
        except OSError as exc:
            problems.append(f"Cannot inspect {directory / 'binary_bios_measurements'}: {exc}")

    if problems:
        state = "partial" if candidates else "restricted"
        return state, candidates, "; ".join(problems)
    if not candidates:
        return "unavailable", [], "No firmware TPM binary_bios_measurements source is exposed under securityfs."
    return "observed", candidates, f"Discovered {len(candidates)} firmware TPM event-log source(s)."


def _probe_binary_source(path):
    try:
        stat_result = path.stat()
    except PermissionError:
        return "restricted", None, None, "Permission denied while inspecting event-log metadata."
    except FileNotFoundError:
        return "unavailable", None, None, "Event-log source disappeared during refresh."
    except OSError as exc:
        return "error", None, None, str(exc)

    try:
        with path.open("rb") as handle:
            first = handle.read(1)
    except PermissionError:
        return "restricted", stat_result.st_size, None, "Permission denied reading the binary event log."
    except FileNotFoundError:
        return "unavailable", stat_result.st_size, None, "Source disappeared before the first read."
    except OSError as exc:
        return "error", stat_result.st_size, None, str(exc)

    return "observed", stat_result.st_size, bool(first), ""


def collect_measured_boot_with_status():
    """Inventory verified event-log sources, never fabricate parsed events.

    Empty / restricted / unavailable discovery is represented through a separate
    status result, *not* a synthetic event row or event sequence number.
    """
    acquired = _now_local()
    discovery_state, candidates, discovery_message = _event_log_candidates()
    rows = []

    for path in candidates:
        state, size, has_data, error_text = _probe_binary_source(path)
        if state == "observed":
            access = "Ordinary"
            evidence = "Binary event log; records not decoded"
        elif state == "restricted":
            access = "Restricted"
            evidence = "Binary event log could not be read with ordinary access"
        elif state == "error":
            access = "Error"
            evidence = "Binary event log could not be read normally"
        else:
            access = "Unavailable"
            evidence = "Source disappeared during refresh"

        rows.append({
            "_view": "Measured Boot",
            "tpm": path.parent.name,
            "source": str(path),
            "access": access,
            "size": f"{size:,} bytes" if isinstance(size, int) else "Not available",
            "evidence": evidence,
            "acquired": acquired,
            "read_state": state,
            "has_data": has_data,
            "error": error_text,
        })

    return rows, discovery_state, discovery_message


def collect_measured_boot():
    return collect_measured_boot_with_status()[0]


def collect_capabilities(devices=None, measured_boot=None):
    devices = list(devices if devices is not None else collect_devices())
    measured_boot = list(measured_boot if measured_boot is not None else collect_measured_boot())
    rows = []

    event_by_tpm = {}
    for row in measured_boot:
        tpm = row.get("tpm")
        if isinstance(tpm, str) and _TPM_NAME_RE.match(tpm):
            event_by_tpm[tpm] = row

    for device in devices:
        tpm = device["tpm"]
        base_source = device["sysfs_path"]
        rows.extend([
            {
                "_view": "Capabilities",
                "tpm": tpm,
                "capability": "TPM Version Major",
                "value": device["version"],
                "source": device.get("version_source", str(Path(base_source) / "tpm_version_major")),
            },
            {
                "_view": "Capabilities",
                "tpm": tpm,
                "capability": "Kernel Driver",
                "value": device["driver"],
                "source": device.get("driver_source", "Not exposed"),
            },
            {
                "_view": "Capabilities",
                "tpm": tpm,
                "capability": "Raw TPM Device Node",
                "value": {
                    "present": "Present", "absent": "Not present",
                    "restricted": "Restricted", "error": "Error",
                }.get(device["raw_node_state"], "Unknown"),
                "source": device["raw_node"],
            },
            {
                "_view": "Capabilities",
                "tpm": tpm,
                "capability": "TPM Resource Manager Device Node",
                "value": {
                    "present": "Present", "absent": "Not present",
                    "restricted": "Restricted", "error": "Error",
                }.get(device["rm_node_state"], "Unknown"),
                "source": device["rm_node"],
            },
        ])
        banks = [
            bank.strip()
            for bank in device.get("pcr_banks", "").split(",")
            if bank.strip() and bank.strip() not in {"None exposed", "Not exposed", "Restricted", "Error"}
        ]
        if banks:
            for bank in banks:
                rows.append({
                    "_view": "Capabilities",
                    "tpm": tpm,
                    "capability": f"PCR Bank: {bank}",
                    "value": "Exposed by sysfs",
                    "source": str(Path(base_source) / f"pcr-{bank}"),
                })
        else:
            bank_state = device.get("pcr_banks_state", "observed")
            if bank_state == "restricted":
                bank_value = "Restricted"
            elif bank_state == "error":
                bank_value = "Error"
            elif bank_state == "unavailable":
                bank_value = "Not exposed"
            else:
                bank_value = "None exposed by modern sysfs bank directories"
            rows.append({
                "_view": "Capabilities",
                "tpm": tpm,
                "capability": "PCR Banks",
                "value": bank_value,
                "source": base_source,
            })

        event = event_by_tpm.get(tpm)
        rows.append({
            "_view": "Capabilities",
            "tpm": tpm,
            "capability": "Measured Boot Event Log",
            "value": event.get("access", "Not exposed") if event else "Not exposed",
            "source": event.get("source", "/sys/kernel/security/tpm*/binary_bios_measurements") if event else "/sys/kernel/security/tpm*/binary_bios_measurements",
        })

    return rows
