# TPM Inspector

**Expose. Explore. Explain.**

TPM Inspector is a read-only Linux inspector for TPM devices, exposed PCR snapshots, measured-boot event-log availability, and kernel-exposed TPM capability evidence.

Current release: **0.0.4**

Repository: <https://github.com/linspectacles/tpm-inspector>


<p align="center">
  <a href="https://github.com/brunonlinespace/brunonlinespace/blob/main/linspectacles/tpm-inspector.png">
    <img
      src="https://raw.githubusercontent.com/brunonlinespace/brunonlinespace/main/linspectacles/tpm-inspector.png"
      alt="TPM Inspector screenshot"
      width="900"
    >
  </a>
</p>
## What TPM Inspector is

TPM Inspector answers a focused question: **what Trusted Platform Module state and measured-boot evidence does the running Linux kernel expose?**

PCR values are presented as snapshots. Measured-boot event logs are treated as evidence sources, not turned into a synthetic system-trust verdict.

## Highlights

- Four views: **TPM Devices**, **PCRs**, **Measured Boot**, and **Capabilities**.
- TPM identity and stable exported attributes from sysfs.
- Raw TPM and resource-manager node presence.
- Modern sysfs PCR bank/value snapshots where exposed.
- Measured-boot event-log source availability, access and size reporting.
- Kernel-exposed capability evidence.
- No `tpm2-tools` dependency in 0.0.4.
- No privilege escalation or mutating TPM commands.

## Data sources and acquisition

- `/sys/class/tpm/`
- `/sys/class/tpm/tpmN/tpm_version_major`
- `/dev/tpmN`
- `/dev/tpmrmN`
- `/sys/class/tpm/tpmN/pcr-<hash>/<number>`
- `/sys/kernel/security/tpm*/binary_bios_measurements`

Measured Boot inventories event-log **sources**, not decoded events. Missing securityfs/event-log sources are reported as unavailable rather than as application failures.

## Interface

The View selector provides **TPM Devices**, **PCRs**, **Measured Boot**, and **Capabilities**.

The four views can also be selected with `Ctrl+1` through `Ctrl+4`. Metadata Details preserves source/read-state context for the selected record.

## Read-only and scope boundaries

TPM Inspector does not provision/clear a TPM, create/delete keys, seal/unseal secrets, quote or extend PCRs, change NV state, perform attestation, or elevate privileges.

PCR values are snapshots, not static configuration. Event-log availability does not prove validity or trust.

## Useful keyboard shortcuts

| Command | Shortcut |
| --- | --- |
| TPM Devices | `Ctrl+1` |
| PCRs | `Ctrl+2` |
| Measured Boot | `Ctrl+3` |
| Capabilities | `Ctrl+4` |
| Toggle Metadata Details | `F3` |
| Toggle Metadata Details layout | `Ctrl+L` |
| Refresh inventory | `Shift+F5` |
| Options | `Ctrl+/` |

## Running from source

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install PyQt6
python3 -m linspectacles_tpm_inspector.standalone
```

No TPM management tool is required for the implemented 0.0.4 acquisition paths.

No RPM installation instructions are included in this README.

## LinSpectacles Hub

This applet can run independently, but it can also be installed and used inside **[LinSpectacles Hub](https://github.com/linspectacles/linspectacles-hub)**.

LinSpectacles Hub is the optional workbench for the LinSpectacles applet family. It provides shared applet discovery, navigation and management while each inspector remains independently runnable.

To install a portable or user applet through the Hub, open **Configuration... → Applets** and add the applet ZIP. Once discovered, the applet can be enabled and opened from the Hub navigation.

System-installed applets are discovered by the Hub from its system applet store and remain managed by the system package manager.

## Source layout and LinSpectacles integration

```text
linspectacles_tpm_inspector/
├── __init__.py
├── standalone.py
├── LICENSE
├── applet.json
├── README.md
└── tpm_inspector/
    ├── __init__.py
    ├── applet.py
    ├── _collectors.py
    ├── _support.py
    └── icon.png
```

## Configuration

TPM Inspector persists only implemented presentation settings. Those settings do not modify TPM state or grant extra access.

## Scope

TPM Inspector owns **TPM device, PCR snapshot, measured-boot event-log availability and kernel-exposed capability evidence**. Broader platform firmware remains with **Firmware Inspector**.

## License

GNU General Public License v3.0 or later. See [`LICENSE`](LICENSE).

## Links

- LinSpectacles organisation: <https://github.com/linspectacles/>
- LinSpectacles Hub: <https://github.com/linspectacles/linspectacles-hub>
- Repository: <https://github.com/linspectacles/tpm-inspector>
- Issues: <https://github.com/linspectacles/tpm-inspector/issues>

<p align="center">
  <a href="https://github.com/linspectacles/tpm-inspector">
    <img
      src="tpm_inspector/icon.png"
      alt="TPM Inspector"
      width="256"
    >
  </a>
</p>
