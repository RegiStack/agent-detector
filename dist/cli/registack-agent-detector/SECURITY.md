# Security Policy

## Scope

This repository covers the public preview of the `Registack AIR Agent Detector`
CLI and its published installer artifacts.

In scope:
- `registack-agent-detector.py`
- `registack-agent-detector.ps1`
- installer and uninstaller scripts
- website-published preview files under the detector CLI path

Out of scope for this repository:
- the broader Registack AIR control plane
- internal Registack services
- customer-specific deployments
- unpublished enterprise infrastructure

## Preview support expectation

This is a public preview. Security issues will be triaged, but this repository
does not imply a formal SLA, production support contract, or guaranteed response
time.

## How to report a vulnerability

Do not open a public issue for a suspected vulnerability first.

Report privately through official Registack contact channels and include:
- affected file or script
- exact version or commit reference
- platform and shell used
- reproduction steps
- observed impact
- whether the issue affects only preview install flow or runtime scanning

If you do not have a dedicated security contact yet, use the primary official
Registack contact route and mark the report as:

```text
Security Report — Registack AIR Agent Detector
```

## What helps triage

Useful report details:
- whether the issue requires local access
- whether it depends on `curl | bash` installation flow
- whether it affects `macOS`, `Linux`, or `Windows`
- whether it involves path handling, script execution, config persistence, or
  JSON output
- minimal proof-of-concept

## Disclosure preference

Please allow Registack reasonable time to:
- confirm the issue
- assess impact
- prepare a fix or mitigation
- update install instructions if needed

Coordinated disclosure is strongly preferred.

## Current security properties

Current intended properties of the preview detector:
- no telemetry
- no outbound network calls except optional local endpoint probes on `127.0.0.1`
- local Docker inspection only when explicitly requested
- local Kubernetes manifest inspection only when explicitly requested
- detection-path selection during installation by numbered choice rather than
  manual free-form typing

These properties should not be interpreted as a certification statement or
formal security guarantee.
