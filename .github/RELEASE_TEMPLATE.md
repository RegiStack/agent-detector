# Release Title

`Registack AIR Agent Detector vX.Y.Z`

## Release Status

- Preview stage:
- Public preview date:
- Canonical install base URL:

## Summary

Short paragraph describing what changed and why an evaluator should care.

## Included Artifacts

- `registack-agent-detector.py`
- `registack-agent-detector.ps1`
- `install-macos.sh`
- `install-linux.sh`
- `install-windows.ps1`
- `uninstall-macos.sh`
- `uninstall-linux.sh`
- `uninstall-windows.ps1`
- `README.md`
- `LICENSE.txt`
- `NOTICE.md`
- `SECURITY.md`

## Install Commands

### macOS

```bash
curl -fsSL https://registack.eu/cli/registack-agent-detector/install-macos.sh | bash
```

### Linux

```bash
curl -fsSL https://registack.eu/cli/registack-agent-detector/install-linux.sh | bash
```

### Windows

```powershell
powershell -ExecutionPolicy Bypass -c "irm https://registack.eu/cli/registack-agent-detector/install-windows.ps1 | iex"
```

## Verification

```bash
registack-agent-detector --version
registack-agent-detector --scan-default --output json
```

## Highlights

- Detection-path selection flow:
- Runtime or detection logic changes:
- Output schema changes:
- Install or uninstall changes:
- Documentation changes:

## Known Limitations

- 
- 
- 

## Security Notes

- Any security-relevant install-flow change:
- Any changed local probing behavior:
- Any known issue requiring operator caution:

## Compatibility Notes

- macOS:
- Linux:
- Windows:

## Publication Checklist

- [ ] Install commands verified against live `registack.eu`
- [ ] `index.html` updated if needed
- [ ] Checksums or provenance artifacts published if applicable
- [ ] Website copy still matches actual CLI behavior
- [ ] `--scan-default` and path-selection behavior verified
- [ ] No unsupported claims added

## Rights Reminder

This repository is published as a public preview without reuse rights.
See:
- `LICENSE.txt`
- `NOTICE.md`
