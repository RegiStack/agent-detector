# Registack AIR Agent Detector

Public preview repository for the `Registack AIR Agent Detector` CLI tool.

This repository is published as a **public preview without reuse rights**.

What that means:
- the source is visible for evaluation, trust review, and pilot preparation
- the tool may be downloaded and tested for evaluation purposes
- the repository is **not** open source
- no reuse, redistribution, derivative work, or production commercialization rights are granted

See:
- [LICENSE.txt](./LICENSE.txt)
- [NOTICE.md](./NOTICE.md)
- [SECURITY.md](./SECURITY.md)

The detector:
- scans local filesystems for AI-agent candidates and runtime artifacts
- optionally inspects the local Docker runtime
- optionally inspects Kubernetes manifests in scanned paths
- probes common local AI endpoints on `127.0.0.1`
- emits AIR-compatible JSON

Important properties:
- no telemetry
- no internet calls from the detector itself
- only local endpoint probes on `127.0.0.1`
- Docker inspection stays on the local Docker daemon
- Kubernetes inspection is manifest-based from local scanned files

This repository is intended to support:
- technical review
- pilot evaluation
- security review
- controlled CLI installation from `registack.eu`

It is not positioned as:
- a full AIR platform repository
- an enterprise support portal
- an open contribution project

During installation, you can now define the **default detection path** that
the tool will scan when no `--scan-dir` argument is provided later.

The detection path is selected from a predefined list during installation.
It is no longer entered as a free-form path string.

## Hosted Layout Assumption

This directory is intended to be deployed under:

```text
https://registack.eu/cli/registack-agent-detector/
```

Install commands below assume that path.

The published web directory should contain:
- `index.html`
- `LICENSE.txt`
- `NOTICE.md`
- `SECURITY.md`
- all install and uninstall scripts
- the Python detector
- the PowerShell wrapper
- this `README.md`

## Assemble Publish Tree

Build a ready-to-upload website tree locally:

```bash
bash assemble-publish-tree.sh
```

This creates:

```text
dist/cli/registack-agent-detector/
```

You can then sync that directory to the web host path for:

```text
https://registack.eu/cli/registack-agent-detector/
```

## Install

### macOS

```bash
curl -fsSL https://registack.eu/cli/registack-agent-detector/install-macos.sh | bash
```

The installer presents a numbered list of valid detection paths.
This list may include the filesystem root `/` for full-machine scans.

For automated use, select by number:

```bash
curl -fsSL https://registack.eu/cli/registack-agent-detector/install-macos.sh | bash -s -- --scan-choice 1
```

### Linux

```bash
curl -fsSL https://registack.eu/cli/registack-agent-detector/install-linux.sh | bash
```

The installer presents a numbered list of valid detection paths.
This list may include the filesystem root `/` for full-machine scans.

For automated use, select by number:

```bash
curl -fsSL https://registack.eu/cli/registack-agent-detector/install-linux.sh | bash -s -- --scan-choice 1
```

### Windows

```powershell
powershell -ExecutionPolicy Bypass -c "irm https://registack.eu/cli/registack-agent-detector/install-windows.ps1 | iex"
```

The installer presents a numbered list of valid detection paths.

For automated use, select by number:

```powershell
& ([scriptblock]::Create((irm https://registack.eu/cli/registack-agent-detector/install-windows.ps1))) -ScanChoice 1
```

## Verify

### macOS / Linux

```bash
registack-agent-detector --version
registack-agent-detector --scan-default --output text
```

### Windows

```powershell
registack-agent-detector.cmd --version
registack-agent-detector.cmd --scan-default --output text
```

## Run Examples

Scan one or more paths:

```bash
registack-agent-detector --scan-dir /Applications --scan-dir ~/.registack --output json
```

If no `--scan-dir` is passed, the detector uses the default detection path
saved during installation.

To force the saved installation-time path explicitly:

```bash
registack-agent-detector --scan-default --output json
```

If the install target directory is not writable, the installer may request
elevated permissions to place the binary or its config pointer in the target
location.

Deep scan:

```bash
registack-agent-detector --scan-dir . --deep --output json
```

Docker scan:

```bash
registack-agent-detector --scan-dir . --scan-docker --output json
```

Kubernetes manifest scan:

```bash
registack-agent-detector --scan-dir ./deploy --scan-kubernetes --deep --output json
```

Quiet JSON:

```bash
registack-agent-detector --scan-dir . --scan-docker --output json --quiet
```

## CLI Flags

- `--scan-dir <path>` repeatable
- `--scan-default`
- `--scan-docker`
- `--scan-kubernetes`
- `--deep`
- `--output {json,text}`
- `--quiet`
- `--version`

## JSON Output Shape

```json
{
  "detections": [],
  "scan_metadata": {
    "timestamp": "2026-05-18T00:00:00+00:00",
    "scanner_version": "0.1.0",
    "output_format": "air-compatible"
  }
}
```

Detections include:
- `detection_type`
- `title`
- `path`
- `detail`
- `source`
- `confidence_score`
- `operational_criticality`
- `evidence`
- `air_record_type`
- `air_payload`

## Exit Codes

- `0` no detections, successful scan
- `1` detections found
- `2` error

## Uninstall

### macOS

```bash
curl -fsSL https://registack.eu/cli/registack-agent-detector/uninstall-macos.sh | bash
```

### Linux

```bash
curl -fsSL https://registack.eu/cli/registack-agent-detector/uninstall-linux.sh | bash
```

### Windows

```powershell
powershell -ExecutionPolicy Bypass -c "irm https://registack.eu/cli/registack-agent-detector/uninstall-windows.ps1 | iex"
```

## Local Development

Run directly:

```bash
python3 registack-agent-detector.py --scan-dir . --output json
```

PowerShell wrapper:

```powershell
.\registack-agent-detector.ps1 --scan-dir . --output json
```

## Public Preview Boundaries

If you publish this repository publicly, keep these boundaries explicit:
- canonical install commands should point to `registack.eu`, not raw GitHub URLs
- GitHub should act as source, release-note, and transparency surface
- production rollout, managed enterprise deployment, and AIR control-plane governance remain outside this repository
