#!/usr/bin/env python3
# Registack AIR — Internal Pre-Release. © Registack.
"""
Tenant and device binding helper for Registack AIR.

The detector remains a free client-side scanner. Central tenant registration,
device enrollment, profile binding, and governed runtime verification stay in
the licensed Registack AIR Control Plane.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import platform
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

VERSION = "0.1.0"
ENV_BASE_URL = "REGISTACK_AIR_BASE_URL"
ENV_TOKEN = "REGISTACK_AIR_TOKEN"
ENV_CONFIG_PATH = "REGISTACK_AGENT_DETECTOR_CONFIG"
CONFIG_POINTER_FILENAME = ".registack-agent-detector-config"
AIR_BINDING_KEY = "air_binding"


class LinkError(Exception):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Register and bind a local detector to Registack AIR tenants.")
    parser.add_argument("--output", choices=["text", "json"], default="text", help="Output format.")
    parser.add_argument("--version", action="version", version=f"registack-air-link {VERSION}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("status", help="Show the locally saved AIR tenant/device binding.")

    customers = subparsers.add_parser("list-customers", help="List AIR customers.")
    add_api_args(customers)

    tenants = subparsers.add_parser("list-tenants", help="List tenants for one AIR customer.")
    add_api_args(tenants)
    tenants.add_argument("--customer-id", required=True, help="AIR customer ID.")

    create_customer = subparsers.add_parser("register-customer", help="Register a customer in the AIR control plane.")
    add_api_args(create_customer)
    create_customer.add_argument("--name", required=True, help="Customer name.")
    create_customer.add_argument("--external-ref", default="", help="Optional external reference.")
    create_customer.add_argument("--status", default="ACTIVE", help="Customer status.")
    create_customer.add_argument("--metadata", action="append", default=[], metavar="KEY=VALUE", help="Customer metadata entry.")

    create_tenant = subparsers.add_parser("register-tenant", help="Register a tenant under an existing AIR customer.")
    add_api_args(create_tenant)
    create_tenant.add_argument("--customer-id", required=True, help="Existing AIR customer ID.")
    create_tenant.add_argument("--name", required=True, help="Tenant name.")
    create_tenant.add_argument("--slug", default="", help="Tenant slug. Defaults to AIR-side slugification.")
    create_tenant.add_argument("--status", default="ACTIVE", help="Tenant status.")
    create_tenant.add_argument("--metadata", action="append", default=[], metavar="KEY=VALUE", help="Tenant metadata entry.")
    create_tenant.add_argument("--bind", action="store_true", help="Save the created tenant as the local detector AIR binding.")
    create_tenant.add_argument("--store-token", action="store_true", help="Persist the bearer token in the local config.")

    bind_tenant = subparsers.add_parser("bind-tenant", help="Bind the local detector to an existing AIR tenant.")
    add_api_args(bind_tenant)
    bind_tenant.add_argument("--tenant-id", required=True, help="Existing AIR tenant ID.")
    bind_tenant.add_argument("--store-token", action="store_true", help="Persist the bearer token in the local config.")

    register_device = subparsers.add_parser("register-device", help="Register or reuse the local machine as a managed device for the bound tenant.")
    add_api_args(register_device)
    register_device.add_argument("--tenant-id", default="", help="AIR tenant ID. Defaults to the locally bound tenant.")
    register_device.add_argument("--hostname", default=socket.gethostname(), help="Device hostname.")
    register_device.add_argument("--device-label", default="", help="Human-friendly device label.")
    register_device.add_argument("--os-family", default=local_os_family(), help="Operating system family.")
    register_device.add_argument("--os-version", default=platform.release(), help="Operating system version.")
    register_device.add_argument("--architecture", default=platform.machine(), help="CPU architecture.")
    register_device.add_argument("--serial-number", default="", help="Optional serial number.")
    register_device.add_argument("--primary-user", default=getpass.getuser(), help="Primary user.")
    register_device.add_argument("--ownership-model", default="CORPORATE", help="Ownership model.")
    register_device.add_argument("--mdm-provider", default="", help="Optional MDM provider.")
    register_device.add_argument("--enrollment-channel", default="LOCAL_DETECTOR", help="Enrollment channel.")
    register_device.add_argument("--device-status", default="ACTIVE", help="Managed device status.")
    register_device.add_argument("--enrollment-status", default="ENROLLED", help="Enrollment record status.")
    register_device.add_argument("--bootstrap-source", default="registack-air-link", help="Enrollment bootstrap source.")
    register_device.add_argument("--bootstrap-reference", default="local-detector-binding", help="Enrollment bootstrap reference.")
    register_device.add_argument("--runtime-version", default="", help="Optional runtime or detector version string.")
    register_device.add_argument("--runtime-integrity-state", default="", help="Optional runtime integrity state.")
    register_device.add_argument("--metadata", action="append", default=[], metavar="KEY=VALUE", help="Managed device metadata entry.")
    register_device.add_argument("--notes", default="Bound from local Registack AIR Agent Detector.", help="Enrollment notes.")
    register_device.add_argument("--store-token", action="store_true", help="Persist the bearer token in the local config.")

    return parser.parse_args()


def add_api_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--base-url", default="", help="AIR admin installer base URL.")
    parser.add_argument("--token", default=os.environ.get(ENV_TOKEN, ""), help="AIR bearer token.")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def local_os_family() -> str:
    value = platform.system().strip().upper()
    if value == "DARWIN":
        return "MACOS"
    if value == "WINDOWS":
        return "WINDOWS_11"
    return value or "UNKNOWN"


def first_non_empty(*values: object) -> str:
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return ""


def pointer_config_path() -> Path | None:
    candidates = []
    argv0 = Path(sys.argv[0]).expanduser()
    if argv0.name:
        candidates.append(argv0.parent / CONFIG_POINTER_FILENAME)
    script_path = Path(__file__).resolve()
    candidates.append(script_path.parent / CONFIG_POINTER_FILENAME)
    for candidate in candidates:
        try:
            if candidate.exists():
                value = candidate.read_text(encoding="utf-8").strip()
                if value:
                    return Path(value).expanduser()
        except OSError:
            continue
    return None


def default_config_path() -> Path:
    override = os.environ.get(ENV_CONFIG_PATH)
    if override:
        return Path(override).expanduser()
    pointer = pointer_config_path()
    if pointer is not None:
        return pointer
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        return base / "Registack" / "agent-detector" / "config.json"
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        return Path(xdg).expanduser() / "registack-agent-detector" / "config.json"
    return Path.home() / ".config" / "registack-agent-detector" / "config.json"


def load_config() -> dict:
    path = default_config_path()
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def save_config(payload: dict) -> None:
    path = default_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def load_binding(config: dict) -> dict:
    binding = config.get(AIR_BINDING_KEY, {})
    return binding if isinstance(binding, dict) else {}


def save_binding(config: dict, binding: dict) -> None:
    config[AIR_BINDING_KEY] = binding
    save_config(config)


def redact_binding(binding: dict) -> dict:
    result = dict(binding)
    token = first_non_empty(result.pop("token", ""))
    result["stored_token"] = bool(token)
    return result


def parse_metadata(items: list[str]) -> dict[str, str]:
    metadata: dict[str, str] = {}
    for item in items:
        raw = str(item).strip()
        if not raw:
            continue
        if "=" not in raw:
            raise LinkError(f"metadata entry must be KEY=VALUE: {raw}")
        key, value = raw.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            raise LinkError(f"metadata key must not be empty: {raw}")
        metadata[key] = value
    return metadata


def normalize_base_url(value: str) -> str:
    normalized = str(value).strip().rstrip("/")
    if not normalized:
        raise LinkError(f"--base-url is required or set {ENV_BASE_URL}")
    parsed = urllib.parse.urlparse(normalized)
    if not parsed.scheme or not parsed.netloc:
        raise LinkError("base URL must be an absolute http(s) URL")
    return normalized


def resolve_base_url(args: argparse.Namespace, config: dict) -> str:
    binding = load_binding(config)
    return normalize_base_url(first_non_empty(getattr(args, "base_url", ""), os.environ.get(ENV_BASE_URL, ""), binding.get("base_url", "")))


def resolve_token(args: argparse.Namespace, config: dict) -> str:
    binding = load_binding(config)
    token = first_non_empty(getattr(args, "token", ""), os.environ.get(ENV_TOKEN, ""), binding.get("token", ""))
    if not token:
        raise LinkError(f"bearer token is required via --token, {ENV_TOKEN}, or a stored AIR binding")
    return token


def resolve_tenant_id(args: argparse.Namespace, config: dict) -> str:
    binding = load_binding(config)
    tenant_id = first_non_empty(getattr(args, "tenant_id", ""), binding.get("tenant_id", ""))
    if not tenant_id:
        raise LinkError("tenant ID is required or bind the detector to a tenant first")
    return tenant_id


def http_request(method: str, url: str, token: str, payload: dict | None = None) -> dict:
    headers = {"Authorization": f"Bearer {token}"}
    data = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=20.0) as response:
            body = response.read().decode("utf-8", errors="replace").strip()
            if not body:
                return {}
            parsed = json.loads(body)
            if isinstance(parsed, dict):
                return parsed
            raise LinkError(f"unexpected AIR response shape from {url}")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace").strip()
        message = body or exc.reason
        raise LinkError(f"AIR request failed ({exc.code}) for {url}: {message}") from exc
    except urllib.error.URLError as exc:
        raise LinkError(f"AIR request failed for {url}: {exc.reason}") from exc
    except json.JSONDecodeError as exc:
        raise LinkError(f"AIR response was not valid JSON for {url}: {exc}") from exc


def api_get(base_url: str, token: str, path: str) -> dict:
    return http_request("GET", f"{base_url}{path}", token)


def api_post(base_url: str, token: str, path: str, payload: dict) -> dict:
    return http_request("POST", f"{base_url}{path}", token, payload)


def list_items(payload: dict) -> list[dict]:
    items = payload.get("items", [])
    return items if isinstance(items, list) else []


def render_table(items: list[dict], fields: list[str]) -> str:
    if not items:
        return "No records found."
    lines = []
    for item in items:
        parts = []
        for field in fields:
            value = first_non_empty(item.get(field, ""))
            if value:
                parts.append(f"{field}={value}")
        lines.append(" - " + ", ".join(parts))
    return "\n".join(lines)


def update_binding_from_tenant(config: dict, base_url: str, tenant: dict, customer: dict | None, token: str, store_token: bool) -> dict:
    binding = load_binding(config)
    binding.update(
        {
            "base_url": base_url,
            "customer_id": first_non_empty(tenant.get("customer_id", ""), binding.get("customer_id", "")),
            "customer_name": first_non_empty((customer or {}).get("name", ""), binding.get("customer_name", "")),
            "tenant_id": first_non_empty(tenant.get("id", ""), binding.get("tenant_id", "")),
            "tenant_name": first_non_empty(tenant.get("name", ""), binding.get("tenant_name", "")),
            "tenant_slug": first_non_empty(tenant.get("slug", ""), binding.get("tenant_slug", "")),
            "tenant_status": first_non_empty(tenant.get("status", ""), binding.get("tenant_status", "")),
            "bound_at": now_iso(),
        }
    )
    if store_token and token:
        binding["token"] = token
    save_binding(config, binding)
    return binding


def command_status(args: argparse.Namespace) -> int:
    config = load_config()
    binding = load_binding(config)
    payload = {"config_path": str(default_config_path()), "air_binding": redact_binding(binding)}
    if args.output == "json":
        print(json.dumps(payload, indent=2))
        return 0
    if not binding:
        print(f"No AIR tenant binding configured in {default_config_path()}.")
        return 0
    print(f"Config: {default_config_path()}")
    print(f"Base URL: {first_non_empty(binding.get('base_url', '')) or '(not set)'}")
    print(f"Customer: {first_non_empty(binding.get('customer_name', ''), binding.get('customer_id', '')) or '(not set)'}")
    print(f"Tenant: {first_non_empty(binding.get('tenant_name', ''), binding.get('tenant_id', '')) or '(not set)'}")
    print(f"Device: {first_non_empty(binding.get('device_label', ''), binding.get('device_id', ''), binding.get('device_hostname', '')) or '(not set)'}")
    print(f"Stored token: {'yes' if binding.get('token') else 'no'}")
    return 0


def command_list_customers(args: argparse.Namespace) -> int:
    config = load_config()
    base_url = resolve_base_url(args, config)
    token = resolve_token(args, config)
    customers = list_items(api_get(base_url, token, "/customers"))
    if args.output == "json":
        print(json.dumps({"items": customers}, indent=2))
    else:
        print(render_table(customers, ["id", "name", "status", "external_ref"]))
    return 0


def command_list_tenants(args: argparse.Namespace) -> int:
    config = load_config()
    base_url = resolve_base_url(args, config)
    token = resolve_token(args, config)
    tenants = list_items(api_get(base_url, token, f"/customers/{args.customer_id}/tenants"))
    if args.output == "json":
        print(json.dumps({"customer_id": args.customer_id, "items": tenants}, indent=2))
    else:
        print(render_table(tenants, ["id", "name", "slug", "status"]))
    return 0


def command_register_customer(args: argparse.Namespace) -> int:
    config = load_config()
    base_url = resolve_base_url(args, config)
    token = resolve_token(args, config)
    customer = api_post(
        base_url,
        token,
        "/customers",
        {
            "name": args.name,
            "external_ref": args.external_ref,
            "status": args.status,
            "metadata": parse_metadata(args.metadata),
        },
    )
    if args.output == "json":
        print(json.dumps(customer, indent=2))
    else:
        print(f"Customer created: {customer.get('id')} · {customer.get('name')}")
    return 0


def command_register_tenant(args: argparse.Namespace) -> int:
    config = load_config()
    base_url = resolve_base_url(args, config)
    token = resolve_token(args, config)
    tenant = api_post(
        base_url,
        token,
        f"/customers/{args.customer_id}/tenants",
        {
            "name": args.name,
            "slug": args.slug,
            "status": args.status,
            "metadata": parse_metadata(args.metadata),
        },
    )
    customer = None
    binding = None
    if args.bind:
        customer = api_get(base_url, token, f"/customers/{args.customer_id}")
        binding = update_binding_from_tenant(config, base_url, tenant, customer, token, args.store_token)
    payload = {"tenant": tenant}
    if customer:
        payload["customer"] = customer
    if binding:
        payload["air_binding"] = redact_binding(binding)
    if args.output == "json":
        print(json.dumps(payload, indent=2))
    else:
        print(f"Tenant created: {tenant.get('id')} · {tenant.get('name')}")
        if args.bind:
            print(f"Local detector bound to tenant {tenant.get('id')}.")
    return 0


def command_bind_tenant(args: argparse.Namespace) -> int:
    config = load_config()
    base_url = resolve_base_url(args, config)
    token = resolve_token(args, config)
    tenant = api_get(base_url, token, f"/tenants/{args.tenant_id}")
    customer_id = first_non_empty(tenant.get("customer_id", ""))
    customer = api_get(base_url, token, f"/customers/{customer_id}") if customer_id else None
    binding = update_binding_from_tenant(config, base_url, tenant, customer, token, args.store_token)
    payload = {"tenant": tenant, "customer": customer or {}, "air_binding": redact_binding(binding)}
    if args.output == "json":
        print(json.dumps(payload, indent=2))
    else:
        print(f"Bound local detector to tenant {tenant.get('id')} · {tenant.get('name')}")
    return 0


def find_existing_device(devices: list[dict], hostname: str) -> dict | None:
    for device in devices:
        if first_non_empty(device.get("hostname", "")).lower() == hostname.lower():
            return device
    return None


def command_register_device(args: argparse.Namespace) -> int:
    config = load_config()
    base_url = resolve_base_url(args, config)
    token = resolve_token(args, config)
    tenant_id = resolve_tenant_id(args, config)
    tenant = api_get(base_url, token, f"/tenants/{tenant_id}")
    customer_id = first_non_empty(tenant.get("customer_id", ""))
    customer = api_get(base_url, token, f"/customers/{customer_id}") if customer_id else None

    devices = list_items(api_get(base_url, token, f"/tenants/{tenant_id}/managed-devices"))
    device = find_existing_device(devices, args.hostname)
    reused = device is not None
    if device is None:
        device = api_post(
            base_url,
            token,
            f"/tenants/{tenant_id}/managed-devices",
            {
                "hostname": args.hostname,
                "device_label": args.device_label,
                "os_family": args.os_family,
                "os_version": args.os_version,
                "architecture": args.architecture,
                "serial_number": args.serial_number,
                "primary_user": args.primary_user,
                "ownership_model": args.ownership_model,
                "mdm_provider": args.mdm_provider,
                "enrollment_channel": args.enrollment_channel,
                "status": args.device_status,
                "metadata": parse_metadata(args.metadata),
            },
        )

    enrollment = api_post(
        base_url,
        token,
        f"/managed-devices/{device['id']}/enrollment-records",
        {
            "status": args.enrollment_status,
            "enrollment_channel": args.enrollment_channel,
            "bootstrap_source": args.bootstrap_source,
            "bootstrap_reference": args.bootstrap_reference,
            "runtime_version": args.runtime_version,
            "runtime_integrity_state": args.runtime_integrity_state,
            "notes": args.notes,
        },
    )

    binding = update_binding_from_tenant(config, base_url, tenant, customer, token, args.store_token)
    binding.update(
        {
            "device_id": first_non_empty(device.get("id", "")),
            "device_hostname": first_non_empty(device.get("hostname", "")),
            "device_label": first_non_empty(device.get("device_label", "")),
            "device_status": first_non_empty(device.get("status", "")),
            "device_registered_at": now_iso(),
            "device_reused": reused,
            "enrollment_record_id": first_non_empty(enrollment.get("id", "")),
            "enrollment_status": first_non_empty(enrollment.get("status", "")),
            "enrollment_channel": first_non_empty(enrollment.get("enrollment_channel", "")),
        }
    )
    save_binding(config, binding)

    payload = {
        "device": device,
        "device_reused": reused,
        "enrollment_record": enrollment,
        "air_binding": redact_binding(binding),
    }
    if args.output == "json":
        print(json.dumps(payload, indent=2))
    else:
        action = "reused" if reused else "registered"
        print(f"Managed device {action}: {device.get('id')} · {device.get('hostname')}")
        print(f"Enrollment record: {enrollment.get('id')} · {enrollment.get('status')}")
    return 0


def main() -> int:
    args = parse_args()
    try:
        if args.command == "status":
            return command_status(args)
        if args.command == "list-customers":
            return command_list_customers(args)
        if args.command == "list-tenants":
            return command_list_tenants(args)
        if args.command == "register-customer":
            return command_register_customer(args)
        if args.command == "register-tenant":
            return command_register_tenant(args)
        if args.command == "bind-tenant":
            return command_bind_tenant(args)
        if args.command == "register-device":
            return command_register_device(args)
        raise LinkError(f"unsupported command: {args.command}")
    except LinkError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
