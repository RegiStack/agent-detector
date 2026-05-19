#!/usr/bin/env python3
# Registack AIR — Internal Pre-Release. © Registack.
"""
Thin importer for Registack AIR detector JSON.

The detector remains a free client-side scanner. Central registry transfer and
governed agent registration stay in the licensed Registack AIR Control Plane.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

VERSION = "0.2.0"
ENV_BASE_URL = "REGISTACK_AIR_BASE_URL"
ENV_TOKEN = "REGISTACK_AIR_TOKEN"
ENV_CONFIG_PATH = "REGISTACK_AGENT_DETECTOR_CONFIG"
ENV_STATE_PATH = "REGISTACK_AGENT_DETECTOR_STATE"
CONFIG_POINTER_FILENAME = ".registack-agent-detector-config"

REVIEW_STATE_PENDING = "pending"
REVIEW_STATE_REVIEWED = "reviewed"
AIR_SYNC_STATE_NOT_IMPORTED = "not_imported"
AIR_SYNC_STATE_IMPORTED = "imported_detection_record"

ENDPOINT_SUFFIXES = {
    "detection_record": "detections",
    "container_runtime_detection_record": "container-runtime-detections",
    "kubernetes_workload_detection_record": "kubernetes-workload-detections",
}

NON_API_FIELDS = {
    "record_type",
    "import_ready",
    "validation_warnings",
    "detection_signature",
    "discovery_state",
    "review_state",
    "air_sync_state",
    "reviewed_at",
    "air_synced_at",
    "air_detection_record_id",
    "air_source_record_type",
    "air_source_record_id",
    "first_seen_at",
    "last_seen_at",
    "seen_count",
}


class ImporterError(Exception):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Import AIR candidates from Registack detector JSON.")
    parser.add_argument("--input", default="-", help="Path to detector JSON file, or - for stdin.")
    parser.add_argument("--tenant-id", required=True, help="AIR tenant ID to import into.")
    parser.add_argument(
        "--base-url",
        default=os.environ.get(ENV_BASE_URL, ""),
        help="AIR admin installer base URL, for example http://127.0.0.1:8092/admin/installer",
    )
    parser.add_argument("--token", default=os.environ.get(ENV_TOKEN, ""), help="Bearer token for AIR admin API.")
    parser.add_argument("--include-known", action="store_true", help="Import detections marked as known as well as new.")
    parser.add_argument("--dry-run", action="store_true", help="Do not POST; print the resolved import plan only.")
    parser.add_argument("--review", action="store_true", help="Show an interactive review view before optional AIR import.")
    parser.add_argument("--yes", action="store_true", help="Proceed without the interactive import confirmation prompt.")
    parser.add_argument("--timeout", type=float, default=20.0, help="HTTP timeout in seconds.")
    parser.add_argument("--version", action="version", version=f"registack-air-import {VERSION}")
    return parser.parse_args()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


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


def default_state_path() -> Path:
    override = os.environ.get(ENV_STATE_PATH)
    if override:
        return Path(override).expanduser()
    return default_config_path().with_name("state.json")


def load_state() -> dict:
    path = default_state_path()
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def save_state(payload: dict) -> None:
    path = default_state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def normalize_review_state(value: object) -> str:
    return REVIEW_STATE_REVIEWED if str(value).strip().lower() == REVIEW_STATE_REVIEWED else REVIEW_STATE_PENDING


def normalize_air_sync_state(value: object) -> str:
    return AIR_SYNC_STATE_IMPORTED if str(value).strip().lower() == AIR_SYNC_STATE_IMPORTED else AIR_SYNC_STATE_NOT_IMPORTED


def load_detector_json(path_value: str) -> dict:
    if path_value == "-":
        raw = sys.stdin.read()
    else:
        raw = Path(path_value).read_text(encoding="utf-8")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ImporterError(f"invalid detector JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ImporterError("detector JSON root must be an object")
    detections = payload.get("detections")
    if not isinstance(detections, list):
        raise ImporterError("detector JSON must contain a detections array")
    return payload


def normalize_base_url(base_url: str) -> str:
    normalized = str(base_url).strip().rstrip("/")
    if not normalized:
        raise ImporterError(f"--base-url is required or set {ENV_BASE_URL}")
    parsed = urllib.parse.urlparse(normalized)
    if not parsed.scheme or not parsed.netloc:
        raise ImporterError("base URL must be an absolute http(s) URL")
    return normalized


def request_payload(candidate: dict) -> dict:
    payload = {}
    for key, value in candidate.items():
        if key in NON_API_FIELDS:
            continue
        payload[key] = value
    return payload


def build_endpoint(base_url: str, tenant_id: str, record_type: str) -> str:
    suffix = ENDPOINT_SUFFIXES.get(record_type)
    if not suffix:
        raise ImporterError(f"unsupported AIR record_type: {record_type}")
    return f"{base_url}/tenants/{tenant_id}/{suffix}"


def post_json(url: str, token: str, payload: dict, timeout: float) -> dict:
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", errors="replace")
            if not body.strip():
                return {}
            parsed = json.loads(body)
            return parsed if isinstance(parsed, dict) else {"raw_response": parsed}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise ImporterError(f"HTTP {exc.code} from {url}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise ImporterError(f"request to {url} failed: {exc}") from exc


def prompt_yes_no(prompt: str, default: bool = False) -> bool:
    streams = []
    try:
        if os.name == "nt":
            streams = [
                (
                    open("CONIN$", "r", encoding="utf-8", errors="ignore"),
                    open("CONOUT$", "w", encoding="utf-8", errors="ignore"),
                )
            ]
        else:
            streams = [
                (
                    open("/dev/tty", "r", encoding="utf-8", errors="ignore"),
                    open("/dev/tty", "w", encoding="utf-8", errors="ignore"),
                )
            ]
    except OSError:
        streams = []

    if not streams and sys.stdin.isatty():
        streams = [(sys.stdin, sys.stdout)]
    if not streams:
        raise ImporterError("interactive review requires a TTY; re-run with --yes to bypass the import prompt")

    input_stream, output_stream = streams[0]
    suffix = " [Y/n]: " if default else " [y/N]: "
    try:
        output_stream.write(prompt + suffix)
        output_stream.flush()
        response = input_stream.readline()
    finally:
        if input_stream not in {sys.stdin}:
            input_stream.close()
        if output_stream not in {sys.stdout}:
            output_stream.close()
    normalized = response.strip().lower()
    if not normalized:
        return default
    return normalized in {"y", "yes"}


def prepare_actions(detections: list[object], include_known: bool) -> list[dict]:
    specialized_paths: dict[str, set[str]] = {}
    for detection in detections:
        if not isinstance(detection, dict):
            continue
        candidate = detection.get("air_candidate")
        if not isinstance(candidate, dict):
            continue
        record_type = str(candidate.get("record_type", "")).strip()
        path = str(detection.get("path", "")).strip()
        if not path or record_type == "detection_record":
            continue
        specialized_paths.setdefault(path, set()).add(record_type)

    actions: list[dict] = []
    for index, detection in enumerate(detections, start=1):
        action: dict = {
            "index": index,
            "detection": detection if isinstance(detection, dict) else {},
            "status": "planned",
            "reason": "",
            "endpoint": "",
            "payload": {},
        }
        if not isinstance(detection, dict):
            action["status"] = "skipped"
            action["reason"] = "detection entry is not an object"
            actions.append(action)
            continue
        discovery_state = str(detection.get("discovery_state", "")).strip().lower()
        if not include_known and discovery_state == "known":
            action["status"] = "skipped"
            action["reason"] = "known detection excluded by default"
            actions.append(action)
            continue
        candidate = detection.get("air_candidate")
        if not isinstance(candidate, dict):
            action["status"] = "skipped"
            action["reason"] = "missing air_candidate block"
            actions.append(action)
            continue
        path = str(detection.get("path", "")).strip()
        record_type = str(candidate.get("record_type", "")).strip()
        if record_type == "detection_record" and path in specialized_paths:
            action["status"] = "skipped"
            action["reason"] = "generic detection is shadowed by a more specific runtime detection for the same path"
            action["shadowed_by"] = sorted(specialized_paths[path])
            actions.append(action)
            continue
        if not bool(candidate.get("import_ready", True)):
            action["status"] = "skipped"
            action["reason"] = "candidate is not import_ready"
            action["validation_warnings"] = candidate.get("validation_warnings", [])
            actions.append(action)
            continue
        action["candidate"] = candidate
        action["record_type"] = record_type
        action["payload"] = request_payload(candidate)
        actions.append(action)
    return actions


def render_review(actions: list[dict], tenant_id: str, base_url: str, dry_run: bool) -> str:
    actionable = [item for item in actions if item.get("status") == "planned"]
    reviewed = [
        item for item in actions
        if isinstance(item.get("detection"), dict)
        and str(item["detection"].get("review_state", "")).strip().lower() == REVIEW_STATE_REVIEWED
    ]
    pending = [item for item in actions if item not in reviewed]
    lines = [
        "Registack AIR Import Review",
        f"tenant_id: {tenant_id}",
        f"base_url: {base_url}",
        f"planned_imports: {len(actionable)}",
        f"reviewed_locally: {len(reviewed)}",
        f"pending_review: {len(pending)}",
        f"dry_run: {dry_run}",
        "",
    ]
    for heading, items in [("Reviewed Detections", reviewed), ("Pending Review", pending)]:
        if not items:
            continue
        lines.append(heading + ":")
        ordered = sorted(
            items,
            key=lambda item: (
                item.get("status") != "planned",
                str(item.get("detection", {}).get("discovery_state", "")) != "new",
                str(item.get("detection", {}).get("path", "")),
            ),
        )
        for item in ordered:
            detection = item.get("detection", {})
            candidate = item.get("candidate", detection.get("air_candidate", {})) if isinstance(detection, dict) else {}
            lines.append(
                f"  {item.get('index')}. [{detection.get('review_state', REVIEW_STATE_PENDING)}] "
                f"[{detection.get('discovery_state', '')}] {detection.get('title', '')}"
            )
            lines.append(f"     status: {item.get('status')}")
            if item.get("reason"):
                lines.append(f"     reason: {item.get('reason')}")
            lines.append(f"     record_type: {first_non_empty(item.get('record_type'), candidate.get('record_type'), '-')}")
            lines.append(
                "     provider/operator/subject/version: "
                f"{first_non_empty(candidate.get('provider_name'), '-')} / "
                f"{first_non_empty(candidate.get('operator_name'), '-')} / "
                f"{first_non_empty(candidate.get('subject_name'), '-')} / "
                f"{first_non_empty(candidate.get('subject_version'), '-')}"
            )
            lines.append(
                "     metadata/confidence/criticality: "
                f"{first_non_empty(candidate.get('metadata_status'), '-')} / "
                f"{first_non_empty(candidate.get('confidence'), '-')} / "
                f"{first_non_empty(candidate.get('operational_criticality'), '-')}"
            )
            lines.append(f"     path: {detection.get('path', '')}")
            warnings = candidate.get("validation_warnings", [])
            if isinstance(warnings, list) and warnings:
                lines.append(f"     validation_warnings: {', '.join(str(value) for value in warnings)}")
            if detection.get("air_detection_record_id"):
                lines.append(f"     air_detection_record_id: {detection.get('air_detection_record_id')}")
        lines.append("")
    lines.append("Control-plane boundary:")
    lines.append("  This client records local detections and local review state.")
    lines.append("  Central detection intake, agent registration, profile binding, and runtime governance stay in the licensed Registack AIR Control Plane.")
    return "\n".join(lines)


def extract_import_ids(record_type: str, response_body: dict) -> dict[str, str]:
    source_record_id = first_non_empty(response_body.get("id"))
    if record_type == "detection_record":
        return {
            "air_detection_record_id": source_record_id,
            "air_source_record_type": "detection_record",
            "air_source_record_id": source_record_id,
        }
    return {
        "air_detection_record_id": first_non_empty(response_body.get("detection_record_id")),
        "air_source_record_type": record_type,
        "air_source_record_id": source_record_id,
    }


def persist_review_records(actions: list[dict], mark_reviewed: bool) -> None:
    state = load_state()
    review_records = state.get("review_records", {})
    if not isinstance(review_records, dict):
        review_records = {}
    now = now_iso()
    changed = False
    for action in actions:
        detection = action.get("detection", {})
        if not isinstance(detection, dict):
            continue
        signature = first_non_empty(detection.get("detection_signature"))
        if not signature:
            continue
        record = review_records.get(signature, {})
        if not isinstance(record, dict):
            record = {}
        if mark_reviewed:
            record["review_state"] = REVIEW_STATE_REVIEWED
            record["reviewed_at"] = now
        if action.get("status") == "imported":
            import_ids = extract_import_ids(action.get("record_type", ""), action.get("response", {}))
            record["air_sync_state"] = AIR_SYNC_STATE_IMPORTED
            record["air_synced_at"] = now
            record["air_detection_record_id"] = import_ids["air_detection_record_id"]
            record["air_source_record_type"] = import_ids["air_source_record_type"]
            record["air_source_record_id"] = import_ids["air_source_record_id"]
        elif mark_reviewed and not record.get("air_sync_state"):
            record["air_sync_state"] = AIR_SYNC_STATE_NOT_IMPORTED
        review_records[signature] = record
        changed = True
    if not changed:
        return
    state["review_records"] = review_records
    state["updated_at"] = now
    if "scanner_version" not in state:
        state["scanner_version"] = "review-only"
    save_state(state)


def registration_hint(actions: list[dict]) -> str:
    imported = [item for item in actions if item.get("status") == "imported"]
    if not imported:
        return (
            "Registration hint:\n"
            "  No AIR detection records were created in this run.\n"
            "  Agent registration and authorized-profile to functional-profile binding continue in the central Registack AIR Control Plane after detection intake."
        )
    ids = []
    for item in imported:
        import_ids = extract_import_ids(item.get("record_type", ""), item.get("response", {}))
        detection_id = import_ids.get("air_detection_record_id")
        if detection_id and detection_id not in ids:
            ids.append(detection_id)
    joined = ", ".join(ids) if ids else "none"
    return (
        "Registration hint:\n"
        f"  AIR detection record IDs created: {joined}\n"
        "  Continue registration in the licensed Registack AIR Control Plane.\n"
        "  That is the central register where the agent identity is linked to the authorized profile,\n"
        "  converted into a functional profile, and later used for runtime verification."
    )


def import_actions(actions: list[dict], token: str, timeout: float) -> None:
    for action in actions:
        if action.get("status") != "planned":
            continue
        try:
            response_body = post_json(action["endpoint"], token, action["payload"], timeout)
        except ImporterError as exc:
            action["status"] = "error"
            action["error"] = str(exc)
            continue
        action["status"] = "imported"
        action["response"] = response_body


def print_json_summary(summary: dict) -> None:
    print(json.dumps(summary, indent=2))


def build_summary(args: argparse.Namespace, actions: list[dict], base_url: str) -> dict:
    summary = {
        "importer_version": VERSION,
        "tenant_id": args.tenant_id,
        "base_url": base_url,
        "dry_run": args.dry_run,
        "review_mode": args.review,
        "imported_count": len([item for item in actions if item.get("status") == "imported"]),
        "planned_count": len([item for item in actions if item.get("status") == "planned"]),
        "skipped_count": len([item for item in actions if item.get("status") == "skipped"]),
        "error_count": len([item for item in actions if item.get("status") == "error"]),
        "results": [],
    }
    for item in actions:
        detection = item.get("detection", {})
        candidate = item.get("candidate", detection.get("air_candidate", {})) if isinstance(detection, dict) else {}
        summary["results"].append(
            {
                "index": item.get("index"),
                "path": detection.get("path", "") if isinstance(detection, dict) else "",
                "status": item.get("status"),
                "reason": item.get("reason", ""),
                "record_type": first_non_empty(item.get("record_type"), candidate.get("record_type")),
                "endpoint": item.get("endpoint", ""),
                "payload": item.get("payload", {}),
                "error": item.get("error", ""),
                "response": item.get("response", {}),
            }
        )
    return summary


def main() -> int:
    args = parse_args()
    detector_payload = load_detector_json(args.input)
    detections = detector_payload.get("detections", [])

    if not args.dry_run and not args.token:
        raise ImporterError(f"--token is required or set {ENV_TOKEN}")
    base_url = normalize_base_url(args.base_url) if not args.dry_run or args.base_url else args.base_url.strip().rstrip("/")

    actions = prepare_actions(detections, include_known=args.include_known)

    if args.review:
        print(render_review(actions, args.tenant_id, base_url, args.dry_run))
        persist_review_records(actions, mark_reviewed=True)
        actionable = [item for item in actions if item.get("status") == "planned"]
        if not args.dry_run and actionable:
            proceed = args.yes or prompt_yes_no("Proceed to AIR import?", default=False)
            if proceed:
                import_actions(actionable, args.token, args.timeout)
                persist_review_records(actions, mark_reviewed=True)
            else:
                print("AIR import was not executed. Local review state was recorded.")
        print("")
        print(registration_hint(actions))
        return 1 if any(item.get("status") == "error" for item in actions) else 0

    if not args.dry_run:
        import_actions(actions, args.token, args.timeout)
        persist_review_records(actions, mark_reviewed=True)

    summary = build_summary(args, actions, base_url)
    print_json_summary(summary)
    return 1 if summary["error_count"] else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ImporterError as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        raise SystemExit(2)
