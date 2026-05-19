#!/usr/bin/env python3
# Registack AIR — Internal Pre-Release. © Registack.
"""
Registack AIR Agent Detector CLI.

Local-only detector for AI-agent candidates, runtime artifacts, Docker
containers, Kubernetes workload manifests, and local AI endpoints.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

VERSION = "0.1.6"
OUTPUT_FORMAT = "air-compatible"
ENV_CONFIG_PATH = "REGISTACK_AGENT_DETECTOR_CONFIG"
ENV_STATE_PATH = "REGISTACK_AGENT_DETECTOR_STATE"
CONFIG_POINTER_FILENAME = ".registack-agent-detector-config"

METADATA_STATUS_DETECTED = "detected"
METADATA_STATUS_INFERRED = "inferred"
METADATA_STATUS_VERIFIED = "verified"

AIR_RECORD_TYPE_DETECTION = "detection_record"
AIR_RECORD_TYPE_CONTAINER_RUNTIME = "container_runtime_detection_record"
AIR_RECORD_TYPE_KUBERNETES = "kubernetes_workload_detection_record"

REVIEW_STATE_PENDING = "pending"
REVIEW_STATE_REVIEWED = "reviewed"
AIR_SYNC_STATE_NOT_IMPORTED = "not_imported"
AIR_SYNC_STATE_IMPORTED = "imported_detection_record"

MODEL_EXTENSIONS = {
    ".onnx": "ONNX model artifact",
    ".pt": "PyTorch model artifact",
    ".pth": "PyTorch checkpoint artifact",
    ".bin": "Model binary artifact",
    ".safetensors": "SafeTensors model artifact",
    ".gguf": "GGUF model artifact",
    ".ggml": "GGML model artifact",
    ".h5": "Keras or TensorFlow model artifact",
    ".hdf5": "HDF5 model artifact",
    ".pb": "TensorFlow protobuf artifact",
    ".mlmodel": "CoreML model artifact",
    ".mlpackage": "CoreML package artifact",
    ".tflite": "TensorFlow Lite model artifact",
}

RUNTIME_ARTIFACT_NAMES = {
    "modelfile": "Ollama model definition",
    "ollama.yaml": "Ollama runtime config",
    "vllm.json": "vLLM runtime config",
    "litellm.yaml": "LiteLLM runtime config",
    "litellm.yml": "LiteLLM runtime config",
    "serve.yaml": "Model serving config",
    "serve.yml": "Model serving config",
}

REGISTACK_MARKER_FILES = {
    ".registack.yaml": "Registack marker file",
    "identity.json": "Registack identity bundle",
    "actual-profile.json": "Registack actual profile bundle",
    "authorized-profile.json": "Registack authorized profile bundle",
    "functional-profile.json": "Registack functional profile bundle",
}

AGENT_CONFIG_FILES = {
    "agent.yaml": "Generic agent config",
    "agent.yml": "Generic agent config",
    "crew.yaml": "CrewAI crew config",
    "crew.yml": "CrewAI crew config",
    "langgraph.json": "LangGraph graph config",
    "langgraph.yaml": "LangGraph graph config",
    "langgraph.yml": "LangGraph graph config",
    "agents.json": "Agent config bundle",
    "agents.yaml": "Agent config bundle",
    "agents.yml": "Agent config bundle",
}

FRAMEWORK_KEYWORDS = {
    "langchain": "LangChain",
    "llamaindex": "LlamaIndex",
    "llama-index": "LlamaIndex",
    "openai-sdk": "OpenAI SDK",
    "openai": "OpenAI SDK",
    "autogen": "AutoGen",
    "crewai": "CrewAI",
}

FRAMEWORK_FILES = {
    "requirements.txt",
    "pyproject.toml",
    "package.json",
    "poetry.lock",
    "pipfile",
    "pipfile.lock",
    "go.mod",
    "cargo.toml",
}

LOCAL_ENDPOINTS = [
    (11434, "Ollama local API", "/api/tags"),
    (1234, "LM Studio API", "/v1/models"),
    (8000, "OpenAI-compatible API", "/v1/models"),
    (8080, "OpenAI-compatible API", "/v1/models"),
    (7860, "Gradio AI app", "/"),
    (3000, "AI web runtime", "/"),
]

DOCKER_IMAGE_PATTERNS = (
    "ollama",
    "vllm",
    "open-webui",
    "text-generation",
    "langchain",
    "llama",
    "autogen",
    "crewai",
    "anythingllm",
    "n8n",
    "litellm",
    "openai",
    "anthropic",
    "huggingface",
)

KUBERNETES_KIND_PATTERNS = (
    "kind: pod",
    "kind: deployment",
    "kind: cronjob",
    "kind: statefulset",
    "kind: daemonset",
    "kind: job",
)

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    "node_modules",
    "dist",
    "build",
    ".venv",
    "venv",
    "target",
    ".mypy_cache",
    ".pytest_cache",
}

TEXT_EXTENSIONS = {
    ".txt",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".md",
    ".env",
    ".conf",
    ".ini",
}


@dataclass
class Detection:
    detection_type: str
    title: str
    path: str
    detail: str
    source: str
    confidence_score: float
    operational_criticality: str
    metadata_status: str = METADATA_STATUS_DETECTED
    provider_name: str = ""
    operator_name: str = ""
    model_name: str = ""
    model_version: str = ""
    model_release_date: str = ""
    detection_signature: str = ""
    discovery_state: str = "current"
    review_state: str = REVIEW_STATE_PENDING
    air_sync_state: str = AIR_SYNC_STATE_NOT_IMPORTED
    reviewed_at: str = ""
    air_synced_at: str = ""
    air_detection_record_id: str = ""
    air_source_record_type: str = ""
    air_source_record_id: str = ""
    first_seen_at: str = ""
    last_seen_at: str = ""
    seen_count: int = 0
    evidence: list[str] = field(default_factory=list)
    air_record_type: str = AIR_RECORD_TYPE_DETECTION
    air_candidate: dict = field(default_factory=dict)
    air_payload: dict = field(default_factory=dict)


@dataclass
class ParsedMetadata:
    provider_name: str = ""
    operator_name: str = ""
    model_name: str = ""
    model_version: str = ""
    model_release_date: str = ""
    metadata_status: str = METADATA_STATUS_DETECTED
    evidence: list[str] = field(default_factory=list)

    def has_values(self) -> bool:
        return any(
            (
                self.provider_name,
                self.operator_name,
                self.model_name,
                self.model_version,
                self.model_release_date,
            )
        )


class DetectorError(Exception):
    pass


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
    config_path = default_config_path()
    return config_path.with_name("state.json")


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


def load_config() -> dict:
    path = default_config_path()
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def configured_scan_dirs() -> list[str]:
    config = load_config()
    primary = first_non_empty(config.get("selected_primary_scan_dir"))
    if primary:
        primary_path = Path(primary).expanduser()
        if primary_path.exists():
            return [str(primary_path)]
        return []
    scan_dirs = config.get("default_scan_dirs", [])
    if not isinstance(scan_dirs, list):
        return []
    for item in scan_dirs:
        normalized = str(item).strip()
        if not normalized:
            continue
        path = Path(normalized).expanduser()
        if path.exists():
            return [str(path)]
    return []


def load_state() -> dict:
    path = default_state_path()
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if isinstance(payload, dict):
        return payload
    return {}


def save_state(payload: dict) -> None:
    path = default_state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def normalize_metadata_status(value: str) -> str:
    lowered = str(value).strip().lower()
    if lowered in {
        METADATA_STATUS_DETECTED,
        METADATA_STATUS_INFERRED,
        METADATA_STATUS_VERIFIED,
    }:
        return lowered
    return METADATA_STATUS_DETECTED


def stronger_metadata_status(current: str, candidate: str) -> str:
    rank = {
        METADATA_STATUS_DETECTED: 0,
        METADATA_STATUS_INFERRED: 1,
        METADATA_STATUS_VERIFIED: 2,
    }
    current_normalized = normalize_metadata_status(current)
    candidate_normalized = normalize_metadata_status(candidate)
    if rank[candidate_normalized] > rank[current_normalized]:
        return candidate_normalized
    return current_normalized


def first_non_empty(*values: object) -> str:
    for value in values:
        if value is None:
            continue
        if isinstance(value, str):
            normalized = value.strip()
            if normalized:
                return normalized
            continue
        normalized = str(value).strip()
        if normalized:
            return normalized
    return ""


def strip_wrapping_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1].strip()
    return value


def normalize_date_string(value: object) -> str:
    if value is None:
        return ""
    normalized = str(value).strip()
    if not normalized:
        return ""
    try:
        return datetime.fromisoformat(normalized.replace("Z", "+00:00")).isoformat().replace("+00:00", "Z")
    except ValueError:
        pass
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", normalized):
        return normalized
    return normalized


def parse_json_object(sample: str) -> dict:
    try:
        payload = json.loads(sample)
    except json.JSONDecodeError:
        return {}
    if isinstance(payload, dict):
        return payload
    return {}


def flatten_mapping(value: object, prefix: str = "") -> dict[str, str]:
    flattened: dict[str, str] = {}
    if isinstance(value, dict):
        for key, nested in value.items():
            key_text = str(key).strip()
            if not key_text:
                continue
            next_prefix = f"{prefix}.{key_text}" if prefix else key_text
            flattened.update(flatten_mapping(nested, next_prefix))
        return flattened
    if isinstance(value, list):
        return flattened
    leaf = first_non_empty(value)
    if leaf and prefix:
        flattened[prefix.lower()] = leaf
        flattened[prefix.split(".")[-1].lower()] = leaf
    return flattened


def parse_yamlish_mapping(sample: str) -> dict[str, str]:
    values: dict[str, str] = {}
    stack: list[tuple[int, str]] = []
    for line in sample.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line.lstrip().startswith("- "):
            continue
        match = re.match(r"^(\s*)([A-Za-z0-9_.-]+)\s*:\s*(.*?)\s*$", line)
        if not match:
            continue
        indent = len(match.group(1).replace("\t", "    "))
        key = match.group(2).strip().lower()
        raw_value = match.group(3).strip()
        while stack and indent <= stack[-1][0]:
            stack.pop()
        if raw_value in {"", "|", ">"}:
            stack.append((indent, key))
            continue
        normalized = strip_wrapping_quotes(raw_value.split(" #", 1)[0].strip())
        if not normalized:
            continue
        full_key = ".".join([item[1] for item in stack] + [key])
        values[full_key] = normalized
        values.setdefault(key, normalized)
    return values


def parse_toml_like_mapping(sample: str) -> dict[str, str]:
    values: dict[str, str] = {}
    table_prefix = ""
    for line in sample.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        table_match = re.match(r"^\[([^\]]+)\]$", stripped)
        if table_match:
            table_prefix = table_match.group(1).strip().strip('"').strip("'").lower()
            continue
        match = re.match(r"^([A-Za-z0-9_.-]+)\s*=\s*(.+?)\s*$", stripped)
        if not match:
            continue
        key = match.group(1).strip().lower()
        raw_value = match.group(2).split(" #", 1)[0].strip()
        value = strip_wrapping_quotes(raw_value)
        full_key = f"{table_prefix}.{key}" if table_prefix else key
        values[full_key] = value
        values.setdefault(key, value)
    return values


def infer_provider_name(value: str) -> str:
    lowered = value.lower()
    provider_patterns = [
        ("openai", "OpenAI"),
        ("anthropic", "Anthropic"),
        ("mistral", "Mistral"),
        ("huggingface", "Hugging Face"),
        ("nvidia", "NVIDIA"),
        ("nemo", "NVIDIA"),
        ("meta", "Meta"),
        ("llama", "Meta"),
        ("ollama", "Ollama"),
        ("litellm", "LiteLLM"),
        ("vllm", "vLLM"),
        ("crewai", "CrewAI"),
        ("langchain", "LangChain"),
        ("autogen", "AutoGen"),
    ]
    for pattern, label in provider_patterns:
        if pattern in lowered:
            return label
    return ""


def normalize_provider_value(value: object) -> str:
    normalized = first_non_empty(value)
    if not normalized:
        return ""
    inferred = infer_provider_name(normalized)
    if inferred:
        return inferred
    return normalized


def infer_image_metadata(image_ref: str) -> ParsedMetadata:
    normalized_ref = str(image_ref).strip()
    if not normalized_ref:
        return ParsedMetadata()
    without_digest = normalized_ref.split("@", 1)[0]
    image_name = without_digest
    image_tag = ""
    if ":" in without_digest and without_digest.rfind(":") > without_digest.rfind("/"):
        image_name, image_tag = without_digest.rsplit(":", 1)
    basename = image_name.rsplit("/", 1)[-1]
    provider_name = infer_provider_name(without_digest)
    model_version = ""
    if image_tag and image_tag.lower() != "latest":
        model_version = image_tag
    metadata = ParsedMetadata(
        provider_name=provider_name,
        model_name=basename,
        model_version=model_version,
        metadata_status=METADATA_STATUS_INFERRED,
        evidence=[f"image_ref:{normalized_ref}"],
    )
    if not metadata.has_values():
        return ParsedMetadata()
    return metadata


def merge_metadata(*items: ParsedMetadata) -> ParsedMetadata:
    merged = ParsedMetadata()
    for item in items:
        if item is None:
            continue
        if item.provider_name and not merged.provider_name:
            merged.provider_name = item.provider_name
        if item.operator_name and not merged.operator_name:
            merged.operator_name = item.operator_name
        if item.model_name and not merged.model_name:
            merged.model_name = item.model_name
        if item.model_version and not merged.model_version:
            merged.model_version = item.model_version
        if item.model_release_date and not merged.model_release_date:
            merged.model_release_date = item.model_release_date
        merged.metadata_status = stronger_metadata_status(merged.metadata_status, item.metadata_status)
        for evidence_item in item.evidence:
            if evidence_item not in merged.evidence:
                merged.evidence.append(evidence_item)
    if merged.has_values() and merged.metadata_status == METADATA_STATUS_DETECTED:
        merged.metadata_status = METADATA_STATUS_INFERRED
    return merged


def normalize_air_confidence(score: float) -> str:
    if score >= 0.85:
        return "high"
    if score >= 0.55:
        return "medium"
    return "low"


def normalize_string_list(values: Iterable[object]) -> list[str]:
    normalized: list[str] = []
    for item in values:
        text = first_non_empty(item)
        if not text or text in normalized:
            continue
        normalized.append(text)
    return normalized


def as_string_list(value: object) -> list[str]:
    if isinstance(value, list):
        return normalize_string_list(value)
    text = first_non_empty(value)
    if not text:
        return []
    return [text]


def humanize_slug(value: str) -> str:
    text = re.sub(r"[_-]+", " ", str(value).strip())
    text = re.sub(r"\s+", " ", text).strip()
    return text.title() if text else ""


def record_type_for_detection(detection_type: str) -> str:
    if detection_type == "container_runtime_detection":
        return AIR_RECORD_TYPE_CONTAINER_RUNTIME
    if detection_type == "kubernetes_workload_detection":
        return AIR_RECORD_TYPE_KUBERNETES
    return AIR_RECORD_TYPE_DETECTION


def normalize_review_state(value: object) -> str:
    lowered = str(value).strip().lower()
    if lowered == REVIEW_STATE_REVIEWED:
        return REVIEW_STATE_REVIEWED
    return REVIEW_STATE_PENDING


def normalize_air_sync_state(value: object) -> str:
    lowered = str(value).strip().lower()
    if lowered == AIR_SYNC_STATE_IMPORTED:
        return AIR_SYNC_STATE_IMPORTED
    return AIR_SYNC_STATE_NOT_IMPORTED


def family_name_for_detection(detection: Detection) -> str:
    candidate_kind = first_non_empty(detection.air_payload.get("candidate_kind"))
    mapping = {
        "registack-managed-agent": "Registack Managed Agent",
        "agent-config": "Agent Configuration",
        "runtime-artifact": "AI Runtime Artifact",
        "model-artifact": "Model Artifact",
        "framework-indicator": "Framework Indicator",
        "kubernetes-workload-manifest": "Kubernetes Workload",
        "docker-runtime": "Container Runtime",
        "local-endpoint": "Local AI Endpoint",
    }
    if candidate_kind in mapping:
        return mapping[candidate_kind]
    if candidate_kind:
        return humanize_slug(candidate_kind)
    return humanize_slug(detection.detection_type)


def detection_method_for_detection(detection: Detection) -> str:
    mapping = {
        "registack_marker_file": "filesystem marker scan",
        "agent_config_file": "filesystem config scan",
        "runtime_artifact": "filesystem runtime scan",
        "model_artifact": "filesystem model scan",
        "framework_indicator": "framework signature scan",
        "kubernetes_workload_detection": "kubernetes manifest scan",
        "local_endpoint_detection": "local endpoint probe",
        "container_runtime_detection": "container runtime scan",
    }
    return mapping.get(detection.detection_type, humanize_slug(detection.detection_type).lower())


def reference_refs_for_detection(detection: Detection) -> list[str]:
    return [f"{detection.source} | {detection.path}"]


def detection_signals_for_detection(detection: Detection) -> list[str]:
    signals = [detection.detection_type]
    candidate_kind = first_non_empty(detection.air_payload.get("candidate_kind"))
    if candidate_kind:
        signals.append(candidate_kind)
    signals.extend(detection.evidence)
    return normalize_string_list(signals)


def extract_kubernetes_manifest_fields(sample: str) -> dict[str, object]:
    payload = parse_json_object(sample)
    if payload:
        kind = first_non_empty(payload.get("kind"))
        metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
        namespace = first_non_empty(metadata.get("namespace"), "default")
        workload_name = first_non_empty(metadata.get("name"))
        spec = payload.get("spec") if isinstance(payload.get("spec"), dict) else {}
        template = spec.get("template") if isinstance(spec.get("template"), dict) else {}
        pod_spec = template.get("spec") if isinstance(template.get("spec"), dict) else {}
        if str(kind).lower() == "cronjob":
            job_template = spec.get("jobTemplate") if isinstance(spec.get("jobTemplate"), dict) else {}
            job_template_spec = job_template.get("spec") if isinstance(job_template.get("spec"), dict) else {}
            job_pod_template = job_template_spec.get("template") if isinstance(job_template_spec.get("template"), dict) else {}
            pod_spec = job_pod_template.get("spec") if isinstance(job_pod_template.get("spec"), dict) else pod_spec
        container_names = []
        image_refs = []
        containers = pod_spec.get("containers") if isinstance(pod_spec.get("containers"), list) else []
        for container in containers:
            if not isinstance(container, dict):
                continue
            container_names.extend(as_string_list(container.get("name")))
            image_refs.extend(as_string_list(container.get("image")))
        return {
            "workload_kind": kind,
            "workload_name": workload_name,
            "namespace": namespace,
            "service_account_name": first_non_empty(pod_spec.get("serviceAccountName")),
            "container_names": normalize_string_list(container_names),
            "image_refs": normalize_string_list(image_refs),
            "schedule": first_non_empty(spec.get("schedule")),
        }

    flattened = parse_yamlish_mapping(sample)
    if not flattened:
        return {}
    container_names = re.findall(r"^\s*-\s*name:\s*['\"]?([^\s\"'#]+)", sample, flags=re.MULTILINE)
    secret_names = re.findall(r"secretName\s*:\s*['\"]?([^\s\"'#]+)", sample, flags=re.IGNORECASE)
    return {
        "workload_kind": first_non_empty(flattened.get("kind")),
        "workload_name": first_non_empty(flattened.get("metadata.name"), flattened.get("name")),
        "namespace": first_non_empty(flattened.get("metadata.namespace"), flattened.get("namespace"), "default"),
        "service_account_name": first_non_empty(
            flattened.get("spec.template.spec.serviceaccountname"),
            flattened.get("spec.jobtemplate.spec.template.spec.serviceaccountname"),
            flattened.get("serviceaccountname"),
        ),
        "container_names": normalize_string_list(container_names),
        "mounted_secrets": normalize_string_list(secret_names),
        "schedule": first_non_empty(flattened.get("spec.schedule"), flattened.get("schedule")),
    }


def build_air_candidate(detection: Detection) -> dict[str, object]:
    record_type = record_type_for_detection(detection.detection_type)
    payload = detection.air_payload
    name = first_non_empty(
        payload.get("container_name"),
        payload.get("workload_name"),
        payload.get("host"),
        detection.title,
    )
    subject_name = first_non_empty(
        detection.model_name,
        payload.get("container_name"),
        payload.get("workload_name"),
        Path(detection.path).stem,
        detection.title,
    )
    subject_version = first_non_empty(detection.model_version)
    candidate: dict[str, object] = {
        "record_type": record_type,
        "name": name,
        "family_name": family_name_for_detection(detection),
        "display_context": "runtime_registry",
        "provider_name": detection.provider_name,
        "operator_name": detection.operator_name,
        "subject_name": subject_name,
        "subject_version": subject_version,
        "model_release_date": detection.model_release_date,
        "metadata_status": detection.metadata_status,
        "detection_method": detection_method_for_detection(detection),
        "detection_source": detection.source,
        "confidence": normalize_air_confidence(detection.confidence_score),
        "operational_criticality": detection.operational_criticality,
        "detection_signals": detection_signals_for_detection(detection),
        "reference_refs": reference_refs_for_detection(detection),
        "notes": detection.detail,
        "detection_signature": detection.detection_signature,
        "discovery_state": detection.discovery_state,
        "review_state": detection.review_state,
        "air_sync_state": detection.air_sync_state,
        "reviewed_at": detection.reviewed_at,
        "air_synced_at": detection.air_synced_at,
        "air_detection_record_id": detection.air_detection_record_id,
        "air_source_record_type": detection.air_source_record_type,
        "air_source_record_id": detection.air_source_record_id,
        "first_seen_at": detection.first_seen_at,
        "last_seen_at": detection.last_seen_at,
        "seen_count": detection.seen_count,
        "import_ready": True,
        "validation_warnings": [],
    }

    if record_type == AIR_RECORD_TYPE_CONTAINER_RUNTIME:
        candidate.update(
            {
                "runtime_type": first_non_empty(payload.get("runtime_type"), detection.source, "docker"),
                "runtime_host": first_non_empty(payload.get("runtime_host")),
                "runtime_namespace": first_non_empty(payload.get("runtime_namespace")),
                "environment": first_non_empty(payload.get("environment")),
                "container_id": first_non_empty(payload.get("container_id")),
                "container_name": first_non_empty(payload.get("container_name")),
                "image_ref": first_non_empty(payload.get("image_ref"), payload.get("image")),
                "image_digest": first_non_empty(payload.get("image_digest")),
                "image_labels": payload.get("image_labels") if isinstance(payload.get("image_labels"), dict) else {},
                "compose_project": first_non_empty(payload.get("compose_project")),
                "compose_service": first_non_empty(payload.get("compose_service")),
                "command": first_non_empty(payload.get("command")),
                "exposed_ports": as_string_list(payload.get("exposed_ports")),
                "mounted_secrets": as_string_list(payload.get("mounted_secrets")),
                "required_privileges": as_string_list(payload.get("required_privileges")),
            }
        )

    if record_type == AIR_RECORD_TYPE_KUBERNETES:
        image_refs = as_string_list(payload.get("image_refs"))
        if not image_refs:
            image_refs = as_string_list(payload.get("images"))
        candidate.update(
            {
                "cluster_name": first_non_empty(payload.get("cluster_name")),
                "cluster_context": first_non_empty(payload.get("cluster_context")),
                "namespace": first_non_empty(payload.get("namespace"), "default"),
                "workload_kind": first_non_empty(payload.get("workload_kind")),
                "workload_name": first_non_empty(payload.get("workload_name")),
                "controller_name": first_non_empty(payload.get("controller_name")),
                "service_account_name": first_non_empty(payload.get("service_account_name")),
                "container_names": as_string_list(payload.get("container_names")),
                "image_refs": image_refs,
                "exposed_services": as_string_list(payload.get("exposed_services")),
                "mounted_secrets": as_string_list(payload.get("mounted_secrets")),
                "schedule": first_non_empty(payload.get("schedule")),
            }
        )
        missing_fields = []
        if not first_non_empty(candidate.get("workload_kind")):
            missing_fields.append("workload_kind")
        if not first_non_empty(candidate.get("workload_name")):
            missing_fields.append("workload_name")
        if missing_fields:
            candidate["import_ready"] = False
            candidate["validation_warnings"] = [f"missing required Kubernetes fields: {', '.join(missing_fields)}"]

    if not first_non_empty(name):
        candidate["import_ready"] = False
        warnings = list(candidate.get("validation_warnings", []))
        warnings.append("missing candidate name")
        candidate["validation_warnings"] = warnings

    return candidate


class Detector:
    def __init__(self, quiet: bool = False) -> None:
        self.quiet = quiet
        self.detections: list[Detection] = []
        self.warnings: list[str] = []
        self.paths_scanned: list[str] = []
        self.seen_detection_keys: set[tuple[str, str, str, str]] = set()
        self.history_state = load_state()
        self.new_detection_count = 0

    def warn(self, message: str) -> None:
        self.warnings.append(message)
        if not self.quiet:
            print(f"warning: {message}", file=sys.stderr)

    def add_detection(
        self,
        detection_type: str,
        title: str,
        path: str,
        detail: str,
        source: str,
        confidence_score: float,
        operational_criticality: str,
        evidence: Iterable[str] | None = None,
        air_payload: dict | None = None,
        metadata: ParsedMetadata | None = None,
    ) -> None:
        normalized_metadata = metadata or ParsedMetadata()
        payload = dict(air_payload or {})
        if normalized_metadata.has_values():
            payload.update(
                {
                    "provider_name": normalized_metadata.provider_name,
                    "operator_name": normalized_metadata.operator_name,
                    "model_name": normalized_metadata.model_name,
                    "model_version": normalized_metadata.model_version,
                    "model_release_date": normalized_metadata.model_release_date,
                    "metadata_status": normalized_metadata.metadata_status,
                }
            )
        detection_key = (detection_type, title, path, source)
        if detection_key in self.seen_detection_keys:
            return
        detection = Detection(
            detection_type=detection_type,
            title=title,
            path=path,
            detail=detail,
            source=source,
            confidence_score=max(0.0, min(1.0, confidence_score)),
            operational_criticality=normalize_criticality(operational_criticality),
            metadata_status=normalized_metadata.metadata_status,
            provider_name=normalized_metadata.provider_name,
            operator_name=normalized_metadata.operator_name,
            model_name=normalized_metadata.model_name,
            model_version=normalized_metadata.model_version,
            model_release_date=normalized_metadata.model_release_date,
            evidence=list(evidence or []),
            air_payload=payload,
        )
        detection.air_record_type = record_type_for_detection(detection.detection_type)
        detection.air_candidate = build_air_candidate(detection)
        self.detections.append(detection)
        self.seen_detection_keys.add(detection_key)

    def detection_signature(self, detection: Detection) -> str:
        signature_payload = {
            "detection_type": detection.detection_type,
            "path": detection.path,
            "source": detection.source,
            "provider_name": detection.provider_name,
            "operator_name": detection.operator_name,
            "model_name": detection.model_name,
            "model_version": detection.model_version,
        }
        serialized = json.dumps(signature_payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def apply_detection_history(self) -> None:
        now = now_iso()
        known = self.history_state.get("known_detections", {})
        if not isinstance(known, dict):
            known = {}
        review_records = self.history_state.get("review_records", {})
        if not isinstance(review_records, dict):
            review_records = {}
        updated: dict[str, dict] = {}
        for signature, item in known.items():
            if not isinstance(item, dict):
                continue
            carried = dict(item)
            carried["currently_detected"] = False
            updated[signature] = carried
        new_count = 0
        for detection in self.detections:
            signature = self.detection_signature(detection)
            existing = known.get(signature, {})
            if not isinstance(existing, dict):
                existing = {}
            review_record = review_records.get(signature, {})
            if not isinstance(review_record, dict):
                review_record = {}
            first_seen_at = first_non_empty(existing.get("first_seen_at"), now)
            seen_count = int(existing.get("seen_count", 0) or 0) + 1
            is_new = signature not in known
            detection.detection_signature = signature
            detection.discovery_state = "new" if is_new else "known"
            detection.review_state = normalize_review_state(review_record.get("review_state"))
            detection.air_sync_state = normalize_air_sync_state(review_record.get("air_sync_state"))
            detection.reviewed_at = first_non_empty(review_record.get("reviewed_at"))
            detection.air_synced_at = first_non_empty(review_record.get("air_synced_at"))
            detection.air_detection_record_id = first_non_empty(review_record.get("air_detection_record_id"))
            detection.air_source_record_type = first_non_empty(review_record.get("air_source_record_type"))
            detection.air_source_record_id = first_non_empty(review_record.get("air_source_record_id"))
            detection.first_seen_at = first_seen_at
            detection.last_seen_at = now
            detection.seen_count = seen_count
            detection.air_payload.update(
                {
                    "detection_signature": detection.detection_signature,
                    "discovery_state": detection.discovery_state,
                    "review_state": detection.review_state,
                    "air_sync_state": detection.air_sync_state,
                    "reviewed_at": detection.reviewed_at,
                    "air_synced_at": detection.air_synced_at,
                    "air_detection_record_id": detection.air_detection_record_id,
                    "air_source_record_type": detection.air_source_record_type,
                    "air_source_record_id": detection.air_source_record_id,
                    "first_seen_at": detection.first_seen_at,
                    "last_seen_at": detection.last_seen_at,
                    "seen_count": detection.seen_count,
                }
            )
            detection.air_record_type = record_type_for_detection(detection.detection_type)
            detection.air_candidate = build_air_candidate(detection)
            updated[signature] = {
                "detection_type": detection.detection_type,
                "path": detection.path,
                "title": detection.title,
                "source": detection.source,
                "provider_name": detection.provider_name,
                "operator_name": detection.operator_name,
                "model_name": detection.model_name,
                "model_version": detection.model_version,
                "first_seen_at": first_seen_at,
                "last_seen_at": now,
                "seen_count": seen_count,
                "currently_detected": True,
            }
            if is_new:
                new_count += 1
        self.new_detection_count = new_count
        self.history_state = {
            "scanner_version": VERSION,
            "updated_at": now,
            "known_detections": updated,
            "review_records": review_records,
        }
        try:
            save_state(self.history_state)
        except OSError as exc:
            self.warn(f"unable to persist detector state: {exc}")

    def _metadata_from_identity_json(self, sample: str) -> ParsedMetadata:
        payload = parse_json_object(sample)
        if not payload:
            return ParsedMetadata()
        flattened = flatten_mapping(payload)
        metadata = ParsedMetadata(
            provider_name=normalize_provider_value(first_non_empty(
                flattened.get("provider_name"),
                flattened.get("vendor"),
                flattened.get("vendor_name"),
                flattened.get("model_vendor"),
                flattened.get("machine_labels.vendor"),
                flattened.get("machine_labels.provider"),
            )),
            operator_name=first_non_empty(
                flattened.get("operator_name"),
                flattened.get("installing_operator"),
                flattened.get("operator"),
                flattened.get("operator_legal_name"),
                flattened.get("machine_labels.operator"),
            ),
            model_name=first_non_empty(
                flattened.get("model_name"),
                flattened.get("model_family"),
                flattened.get("model"),
                flattened.get("machine_labels.model_name"),
                flattened.get("machine_labels.model_family"),
            ),
            model_version=first_non_empty(
                flattened.get("model_version"),
                flattened.get("machine_labels.model_version"),
            ),
            model_release_date=normalize_date_string(
                first_non_empty(
                    flattened.get("model_release_date"),
                    flattened.get("model_released_at"),
                    flattened.get("agent_release_date"),
                    flattened.get("machine_labels.model_release_date"),
                    flattened.get("machine_labels.model_released_at"),
                    flattened.get("machine_labels.vendor_release_date"),
                )
            ),
            metadata_status=METADATA_STATUS_VERIFIED,
        )
        if metadata.provider_name:
            metadata.evidence.append("identity.json:provider")
        if metadata.operator_name:
            metadata.evidence.append("identity.json:operator")
        if metadata.model_name:
            metadata.evidence.append("identity.json:model_name")
        if metadata.model_version:
            metadata.evidence.append("identity.json:model_version")
        if metadata.model_release_date:
            metadata.evidence.append("identity.json:model_release_date")
        if not metadata.provider_name:
            inferred_provider = infer_provider_name(sample)
            if inferred_provider:
                metadata.provider_name = inferred_provider
                metadata.metadata_status = stronger_metadata_status(metadata.metadata_status, METADATA_STATUS_INFERRED)
                metadata.evidence.append("identity.json:provider_inferred")
        if metadata.has_values():
            return metadata
        return ParsedMetadata()

    def _metadata_from_json_mapping(self, sample: str, source_name: str) -> ParsedMetadata:
        payload = parse_json_object(sample)
        if not payload:
            return ParsedMetadata()
        flattened = flatten_mapping(payload)
        metadata = ParsedMetadata(
            provider_name=normalize_provider_value(first_non_empty(
                flattened.get("provider_name"),
                flattened.get("vendor"),
                flattened.get("vendor_name"),
                flattened.get("model_vendor"),
            )),
            operator_name=first_non_empty(
                flattened.get("operator_name"),
                flattened.get("installing_operator"),
                flattened.get("operator"),
                flattened.get("operator_legal_name"),
            ),
            model_name=first_non_empty(
                flattened.get("model_name"),
                flattened.get("model_family"),
                flattened.get("model"),
                flattened.get("model_id"),
                flattened.get("served_model_name"),
                flattened.get("base_model"),
            ),
            model_version=first_non_empty(
                flattened.get("model_version"),
                flattened.get("served_model_version"),
            ),
            model_release_date=normalize_date_string(
                first_non_empty(
                    flattened.get("model_release_date"),
                    flattened.get("model_released_at"),
                    flattened.get("vendor_release_date"),
                )
            ),
            metadata_status=METADATA_STATUS_VERIFIED,
        )
        explicit_values_present = any(
            (
                metadata.provider_name,
                metadata.operator_name,
                metadata.model_name,
                metadata.model_version,
                metadata.model_release_date,
            )
        )
        if metadata.provider_name:
            metadata.evidence.append(f"{source_name}:provider")
        if metadata.operator_name:
            metadata.evidence.append(f"{source_name}:operator")
        if metadata.model_name:
            metadata.evidence.append(f"{source_name}:model_name")
        if metadata.model_version:
            metadata.evidence.append(f"{source_name}:model_version")
        if metadata.model_release_date:
            metadata.evidence.append(f"{source_name}:model_release_date")
        if not metadata.provider_name:
            inferred_provider = infer_provider_name(sample)
            if inferred_provider:
                metadata.provider_name = inferred_provider
                metadata.metadata_status = METADATA_STATUS_INFERRED
                metadata.evidence.append(f"{source_name}:provider_inferred")
        elif not explicit_values_present:
            metadata.metadata_status = METADATA_STATUS_INFERRED
        if metadata.has_values():
            return metadata
        return ParsedMetadata()

    def _metadata_from_yamlish_text(self, sample: str, source_name: str) -> ParsedMetadata:
        flattened = parse_yamlish_mapping(sample)
        if not flattened:
            return ParsedMetadata()
        return self._metadata_from_flat_mapping(flattened, sample, source_name)

    def _metadata_from_toml_text(self, sample: str, source_name: str) -> ParsedMetadata:
        flattened = parse_toml_like_mapping(sample)
        if not flattened:
            return ParsedMetadata()
        return self._metadata_from_flat_mapping(flattened, sample, source_name)

    def _metadata_from_flat_mapping(self, flattened: dict[str, str], sample: str, source_name: str) -> ParsedMetadata:
        metadata = ParsedMetadata(
            provider_name=normalize_provider_value(first_non_empty(
                flattened.get("provider_name"),
                flattened.get("vendor"),
                flattened.get("vendor_name"),
                flattened.get("model_vendor"),
                flattened.get("machine_labels.vendor"),
                flattened.get("provider"),
                flattened.get("default.provider"),
            )),
            operator_name=first_non_empty(
                flattened.get("operator_name"),
                flattened.get("installing_operator"),
                flattened.get("operator"),
                flattened.get("operator_legal_name"),
            ),
            model_name=first_non_empty(
                flattened.get("model_name"),
                flattened.get("model_family"),
                flattened.get("model"),
                flattened.get("model_id"),
                flattened.get("served_model_name"),
                flattened.get("base_model"),
                flattened.get("slug"),
                flattened.get("display_name"),
                flattened.get("primary"),
            ),
            model_version=first_non_empty(
                flattened.get("model_version"),
                flattened.get("model_tag"),
            ),
            model_release_date=normalize_date_string(
                first_non_empty(
                    flattened.get("model_release_date"),
                    flattened.get("model_released_at"),
                    flattened.get("agent_release_date"),
                    flattened.get("vendor_release_date"),
                )
            ),
            metadata_status=METADATA_STATUS_VERIFIED,
        )
        explicit_values_present = any(
            (
                metadata.provider_name,
                metadata.operator_name,
                metadata.model_name,
                metadata.model_version,
                metadata.model_release_date,
            )
        )
        if metadata.provider_name:
            metadata.evidence.append(f"{source_name}:provider")
        if metadata.operator_name:
            metadata.evidence.append(f"{source_name}:operator")
        if metadata.model_name:
            metadata.evidence.append(f"{source_name}:model_name")
        if metadata.model_version:
            metadata.evidence.append(f"{source_name}:model_version")
        if metadata.model_release_date:
            metadata.evidence.append(f"{source_name}:model_release_date")
        if not metadata.provider_name:
            inferred_provider = infer_provider_name(sample)
            if inferred_provider:
                metadata.provider_name = inferred_provider
                metadata.metadata_status = METADATA_STATUS_INFERRED
                metadata.evidence.append(f"{source_name}:provider_inferred")
        elif not explicit_values_present:
            metadata.metadata_status = METADATA_STATUS_INFERRED
        if metadata.has_values():
            return metadata
        return ParsedMetadata()

    def _metadata_for_file(self, path: Path, sample: str) -> ParsedMetadata:
        lowered_name = path.name.lower()
        if lowered_name == "identity.json":
            return self._metadata_from_identity_json(sample)
        if lowered_name == ".registack.yaml":
            return self._metadata_from_yamlish_text(sample, ".registack.yaml")
        if path.suffix.lower() == ".json":
            return self._metadata_from_json_mapping(sample, path.name)
        if path.suffix.lower() == ".toml":
            return self._metadata_from_toml_text(sample, path.name)
        if lowered_name in RUNTIME_ARTIFACT_NAMES and path.suffix.lower() == ".json":
            return self._metadata_from_json_mapping(sample, lowered_name)
        if lowered_name in RUNTIME_ARTIFACT_NAMES or lowered_name in AGENT_CONFIG_FILES:
            return self._metadata_from_yamlish_text(sample, lowered_name)
        if path.suffix.lower() in {".yaml", ".yml"}:
            return self._metadata_from_yamlish_text(sample, path.name)
        return ParsedMetadata()

    def scan_paths(self, scan_dirs: list[str], deep: bool, scan_kubernetes: bool) -> None:
        for raw_path in scan_dirs:
            path = Path(raw_path).expanduser()
            if not path.exists():
                raise DetectorError(f"scan path does not exist: {raw_path}")
            self.paths_scanned.append(str(path))
            if path.is_file():
                self._inspect_file(path, deep=deep, scan_kubernetes=scan_kubernetes)
                continue
            if deep:
                walker = os.walk(path)
                for root, dirs, files in walker:
                    dirs[:] = [name for name in dirs if name not in SKIP_DIRS]
                    root_path = Path(root)
                    for filename in files:
                        self._inspect_file(root_path / filename, deep=deep, scan_kubernetes=scan_kubernetes)
            else:
                for child in sorted(path.iterdir()):
                    if child.name in SKIP_DIRS:
                        continue
                    if child.is_file():
                        self._inspect_file(child, deep=False, scan_kubernetes=scan_kubernetes)
                    elif child.is_dir():
                        for nested in sorted(child.iterdir()):
                            if nested.is_file():
                                self._inspect_file(nested, deep=False, scan_kubernetes=scan_kubernetes)

    def _inspect_file(self, path: Path, deep: bool, scan_kubernetes: bool) -> None:
        lowered_name = path.name.lower()
        lowered_path = str(path).lower()
        suffix = path.suffix.lower()
        should_read_text = (
            lowered_name in FRAMEWORK_FILES
            or suffix in TEXT_EXTENSIONS
            or scan_kubernetes
            or lowered_name in REGISTACK_MARKER_FILES
            or lowered_name in RUNTIME_ARTIFACT_NAMES
            or lowered_name in AGENT_CONFIG_FILES
        )
        sample = ""
        lowered_text = ""
        parsed_metadata = ParsedMetadata()
        if should_read_text:
            try:
                sample = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                sample = ""
            lowered_text = sample.lower()
            if sample:
                parsed_metadata = self._metadata_for_file(path, sample)

        if lowered_name in REGISTACK_MARKER_FILES:
            self.add_detection(
                detection_type="registack_marker_file",
                title=REGISTACK_MARKER_FILES[lowered_name],
                path=str(path),
                detail="Registack-governed identity or profile artifact detected.",
                source="filesystem",
                confidence_score=0.98,
                operational_criticality="high",
                evidence=[lowered_name, *parsed_metadata.evidence],
                air_payload={
                    "candidate_kind": "registack-managed-agent",
                    "marker_file": lowered_name,
                },
                metadata=parsed_metadata,
            )

        if lowered_name in AGENT_CONFIG_FILES:
            self.add_detection(
                detection_type="agent_config_file",
                title=AGENT_CONFIG_FILES[lowered_name],
                path=str(path),
                detail="Agent-oriented configuration artifact detected.",
                source="filesystem",
                confidence_score=0.92,
                operational_criticality="medium",
                evidence=[lowered_name, *parsed_metadata.evidence],
                air_payload={
                    "candidate_kind": "agent-config",
                    "config_file": lowered_name,
                },
                metadata=parsed_metadata,
            )

        if lowered_name in RUNTIME_ARTIFACT_NAMES:
            self.add_detection(
                detection_type="runtime_artifact",
                title=RUNTIME_ARTIFACT_NAMES[lowered_name],
                path=str(path),
                detail="AI runtime artifact detected.",
                source="filesystem",
                confidence_score=0.78,
                operational_criticality="medium",
                evidence=[lowered_name, *parsed_metadata.evidence],
                air_payload={"candidate_kind": "runtime-artifact"},
                metadata=parsed_metadata,
            )

        if suffix in MODEL_EXTENSIONS:
            criticality = "high" if suffix in {".onnx", ".pt", ".safetensors", ".gguf"} else "medium"
            self.add_detection(
                detection_type="model_artifact",
                title=MODEL_EXTENSIONS[suffix],
                path=str(path),
                detail="Local model or model-adjacent artifact detected.",
                source="filesystem",
                confidence_score=0.84,
                operational_criticality=criticality,
                evidence=[suffix],
                air_payload={"candidate_kind": "model-artifact"},
                metadata=parsed_metadata,
            )

        if not should_read_text:
            return
        self._detect_framework_indicators(path, lowered_text, parsed_metadata)
        if deep:
            self._detect_registack_yaml(path, lowered_text, parsed_metadata)
        if scan_kubernetes:
            self._detect_kubernetes_manifest(path, lowered_text, sample)

    def _detect_framework_indicators(self, path: Path, lowered_text: str, parsed_metadata: ParsedMetadata) -> None:
        if path.name.lower() in REGISTACK_MARKER_FILES:
            return
        if path.suffix.lower() in {".yaml", ".yml", ".json"} and any(
            pattern in lowered_text for pattern in KUBERNETES_KIND_PATTERNS
        ):
            return
        hits = []
        for keyword, label in FRAMEWORK_KEYWORDS.items():
            if keyword in lowered_text:
                hits.append(label)
        if not hits:
            return

        unique_hits = sorted(set(hits))
        framework_metadata = ParsedMetadata()
        if "OpenAI SDK" in unique_hits:
            framework_metadata.provider_name = "OpenAI"
            framework_metadata.metadata_status = METADATA_STATUS_INFERRED
            framework_metadata.evidence.append("framework_indicator:OpenAI")
        elif "AutoGen" in unique_hits:
            framework_metadata.provider_name = "Microsoft"
            framework_metadata.metadata_status = METADATA_STATUS_INFERRED
            framework_metadata.evidence.append("framework_indicator:AutoGen")
        elif "LangChain" in unique_hits:
            framework_metadata.provider_name = "LangChain"
            framework_metadata.metadata_status = METADATA_STATUS_INFERRED
            framework_metadata.evidence.append("framework_indicator:LangChain")
        elif "LlamaIndex" in unique_hits:
            framework_metadata.provider_name = "LlamaIndex"
            framework_metadata.metadata_status = METADATA_STATUS_INFERRED
            framework_metadata.evidence.append("framework_indicator:LlamaIndex")
        elif "CrewAI" in unique_hits:
            framework_metadata.provider_name = "CrewAI"
            framework_metadata.metadata_status = METADATA_STATUS_INFERRED
            framework_metadata.evidence.append("framework_indicator:CrewAI")
        combined_metadata = merge_metadata(parsed_metadata, framework_metadata)
        self.add_detection(
            detection_type="framework_indicator",
            title="AI framework indicator",
            path=str(path),
            detail="Framework references found: " + ", ".join(unique_hits),
            source="filesystem",
            confidence_score=0.73,
            operational_criticality="medium",
            evidence=[*unique_hits, *combined_metadata.evidence],
            air_payload={
                "candidate_kind": "framework-indicator",
                "frameworks": unique_hits,
            },
            metadata=combined_metadata,
        )

    def _detect_registack_yaml(self, path: Path, lowered_text: str, parsed_metadata: ParsedMetadata) -> None:
        if path.name.lower() != ".registack.yaml":
            return
        if "agent_id" in lowered_text or "authorized_profile" in lowered_text or "functional_profile" in lowered_text:
            self.detections = [
                item
                for item in self.detections
                if not (
                    item.path == str(path)
                    and item.detection_type == "registack_marker_file"
                    and item.title == "Registack marker file"
                )
            ]
            self.add_detection(
                detection_type="registack_marker_file",
                title="Registack managed marker",
                path=str(path),
                detail="Registack YAML marker with managed identity semantics detected.",
                source="filesystem",
                confidence_score=0.99,
                operational_criticality="high",
                evidence=[".registack.yaml", "identity-semantic-content", *parsed_metadata.evidence],
                air_payload={
                    "candidate_kind": "registack-managed-agent",
                    "marker_file": ".registack.yaml",
                },
                metadata=parsed_metadata,
            )

    def _detect_kubernetes_manifest(self, path: Path, lowered_text: str, sample: str) -> None:
        if path.suffix.lower() not in {".yaml", ".yml", ".json"}:
            return
        if not any(pattern in lowered_text for pattern in KUBERNETES_KIND_PATTERNS):
            return

        images = re.findall(r"image\s*:\s*['\"]?([^\s\"']+)", lowered_text)
        matching_images = [image for image in images if has_ai_image_pattern(image)]
        if not matching_images:
            return
        manifest_metadata = self._metadata_from_yamlish_text(sample, path.name)
        inferred_image_metadata = ParsedMetadata()
        for image in matching_images[:5]:
            inferred_image_metadata = merge_metadata(inferred_image_metadata, infer_image_metadata(image))
        combined_metadata = merge_metadata(manifest_metadata, inferred_image_metadata)
        manifest_fields = extract_kubernetes_manifest_fields(sample)

        self.add_detection(
            detection_type="kubernetes_workload_detection",
            title="Kubernetes workload with AI image pattern",
            path=str(path),
            detail="Manifest references AI-related workload images.",
            source="filesystem",
            confidence_score=0.88,
            operational_criticality="high",
            evidence=[*matching_images[:5], *combined_metadata.evidence],
            air_payload={
                "candidate_kind": "kubernetes-workload-manifest",
                "workload_kind": first_non_empty(manifest_fields.get("workload_kind")),
                "workload_name": first_non_empty(manifest_fields.get("workload_name")),
                "namespace": first_non_empty(manifest_fields.get("namespace"), "default"),
                "service_account_name": first_non_empty(manifest_fields.get("service_account_name")),
                "container_names": as_string_list(manifest_fields.get("container_names")),
                "image_refs": matching_images[:5],
                "mounted_secrets": as_string_list(manifest_fields.get("mounted_secrets")),
                "schedule": first_non_empty(manifest_fields.get("schedule")),
                "images": matching_images[:5],
            },
            metadata=combined_metadata,
        )

    def scan_local_endpoints(self) -> None:
        for port, label, http_path in LOCAL_ENDPOINTS:
            open_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            open_socket.settimeout(0.35)
            try:
                result = open_socket.connect_ex(("127.0.0.1", port))
                if result != 0:
                    continue
                detail = f"Open TCP listener on 127.0.0.1:{port}"
                evidence = [f"127.0.0.1:{port}"]
                try:
                    payload = (
                        f"GET {http_path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
                    ).encode("ascii")
                    open_socket.sendall(payload)
                    response = open_socket.recv(256)
                    if response:
                        detail = f"Responsive local AI endpoint on 127.0.0.1:{port}"
                        evidence.append(response.decode("utf-8", errors="ignore").splitlines()[0][:120])
                except OSError:
                    pass

                self.add_detection(
                    detection_type="local_endpoint_detection",
                    title=label,
                    path=f"tcp://127.0.0.1:{port}",
                    detail=detail,
                    source="local-network",
                    confidence_score=0.81,
                    operational_criticality="high",
                    evidence=evidence,
                    air_payload={
                        "candidate_kind": "local-endpoint",
                        "host": "127.0.0.1",
                        "port": port,
                    },
                    metadata=ParsedMetadata(
                        provider_name=infer_provider_name(label),
                        metadata_status=METADATA_STATUS_INFERRED if infer_provider_name(label) else METADATA_STATUS_DETECTED,
                        evidence=[f"local_endpoint:{port}"] if infer_provider_name(label) else [],
                    ),
                )
            finally:
                open_socket.close()

    def scan_docker(self) -> None:
        try:
            import docker  # type: ignore
        except Exception:
            docker = None

        if docker is not None:
            try:
                client = docker.from_env()
                containers = client.containers.list()
                for container in containers:
                    image_name = ""
                    try:
                        image_name = container.image.tags[0] if container.image.tags else container.image.short_id
                    except Exception:
                        image_name = container.attrs.get("Config", {}).get("Image", "")
                    if not has_ai_image_pattern(image_name):
                        continue
                    labels = container.attrs.get("Config", {}).get("Labels", {}) or {}
                    verified_metadata = self._metadata_from_yamlish_text(
                        "\n".join(f"{key}: {value}" for key, value in labels.items()),
                        "docker_labels",
                    )
                    inferred_metadata = infer_image_metadata(image_name)
                    combined_metadata = merge_metadata(verified_metadata, inferred_metadata)
                    self.add_detection(
                        detection_type="container_runtime_detection",
                        title="Docker container with AI image pattern",
                        path=f"docker://{container.name}",
                        detail=f"Running container {container.name} uses image {image_name}",
                        source="docker",
                        confidence_score=0.93,
                        operational_criticality="high",
                        evidence=[container.name, image_name, *combined_metadata.evidence],
                        air_payload={
                            "candidate_kind": "docker-runtime",
                            "container_name": container.name,
                            "image": image_name,
                            "image_labels": labels,
                        },
                        metadata=combined_metadata,
                    )
                return
            except Exception as exc:
                self.warn(f"Docker SDK scan failed, falling back to docker CLI: {exc}")

        docker_path = shutil_which("docker")
        if not docker_path:
            self.warn("docker SDK and docker CLI unavailable; Docker scan skipped.")
            return

        try:
            result = subprocess.run(
                [docker_path, "ps", "--format", "{{.ID}}\t{{.Image}}\t{{.Names}}"],
                capture_output=True,
                text=True,
                check=False,
            )
        except OSError as exc:
            self.warn(f"docker CLI unavailable: {exc}")
            return

        if result.returncode != 0:
            self.warn("docker CLI returned non-zero status; Docker scan skipped.")
            return

        for line in result.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) != 3:
                continue
            container_id, image_name, name = parts
            if not has_ai_image_pattern(image_name):
                continue
            inferred_metadata = infer_image_metadata(image_name)
            self.add_detection(
                detection_type="container_runtime_detection",
                title="Docker container with AI image pattern",
                path=f"docker://{name}",
                detail=f"Running container {name} uses image {image_name}",
                source="docker",
                confidence_score=0.9,
                operational_criticality="high",
                evidence=[container_id, image_name, *inferred_metadata.evidence],
                air_payload={
                    "candidate_kind": "docker-runtime",
                    "container_name": name,
                    "container_id": container_id,
                    "image": image_name,
                },
                metadata=inferred_metadata,
            )

    def scan_kubernetes_manifests_only(self, scan_dirs: list[str], deep: bool) -> None:
        manifest_roots = [Path(item).expanduser() for item in scan_dirs]
        for root in manifest_roots:
            if not root.exists():
                continue
            if root.is_file():
                self._inspect_file(root, deep=deep, scan_kubernetes=True)
                continue
            if deep:
                walker = os.walk(root)
                for current_root, dirs, files in walker:
                    dirs[:] = [name for name in dirs if name not in SKIP_DIRS]
                    current_path = Path(current_root)
                    for filename in files:
                        self._inspect_file(current_path / filename, deep=deep, scan_kubernetes=True)
            else:
                for child in sorted(root.iterdir()):
                    if child.is_file():
                        self._inspect_file(child, deep=False, scan_kubernetes=True)

    def render_json(self) -> str:
        return json.dumps(
            {
                "detections": [asdict(detection) for detection in self.detections],
                "scan_metadata": {
                    "timestamp": now_iso(),
                    "scanner_version": VERSION,
                    "output_format": OUTPUT_FORMAT,
                    "scan_paths": self.paths_scanned,
                    "detection_count": len(self.detections),
                    "new_detection_count": self.new_detection_count,
                    "warnings": self.warnings,
                },
            },
            indent=2,
            sort_keys=False,
        )

    def render_text(self) -> str:
        lines = [
            "Registack AIR Agent Detector",
            f"scanner_version: {VERSION}",
            f"detections: {len(self.detections)}",
            f"new_detections: {self.new_detection_count}",
        ]
        if self.paths_scanned:
            lines.append("scan_paths:")
            for path in self.paths_scanned:
                lines.append(f"  - {path}")
        if self.warnings:
            lines.append("warnings:")
            for warning in self.warnings:
                lines.append(f"  - {warning}")
        lines.append("")
        if not self.detections:
            lines.append("No detections found.")
            return "\n".join(lines)
        lines.append("detections:")
        for index, detection in enumerate(self.detections, start=1):
            lines.append(
                f"{index}. [{detection.operational_criticality}] {detection.title} "
                f"(confidence={detection.confidence_score:.2f})"
            )
            lines.append(f"   type: {detection.detection_type}")
            lines.append(f"   source: {detection.source}")
            lines.append(f"   path: {detection.path}")
            lines.append(f"   detail: {detection.detail}")
            lines.append(f"   discovery_state: {detection.discovery_state}")
            lines.append(f"   review_state: {detection.review_state}")
            lines.append(f"   air_sync_state: {detection.air_sync_state}")
            if detection.detection_signature:
                lines.append(f"   detection_signature: {detection.detection_signature}")
            if detection.reviewed_at:
                lines.append(f"   reviewed_at: {detection.reviewed_at}")
            if detection.air_synced_at:
                lines.append(f"   air_synced_at: {detection.air_synced_at}")
            if detection.air_detection_record_id:
                lines.append(f"   air_detection_record_id: {detection.air_detection_record_id}")
            if detection.first_seen_at:
                lines.append(f"   first_seen_at: {detection.first_seen_at}")
            if detection.last_seen_at:
                lines.append(f"   last_seen_at: {detection.last_seen_at}")
            if detection.seen_count:
                lines.append(f"   seen_count: {detection.seen_count}")
            lines.append(f"   metadata_status: {detection.metadata_status}")
            lines.append(f"   air_record_type: {detection.air_record_type}")
            if detection.air_candidate:
                lines.append(f"   air_import_ready: {bool(detection.air_candidate.get('import_ready', True))}")
            if detection.provider_name:
                lines.append(f"   provider_name: {detection.provider_name}")
            if detection.operator_name:
                lines.append(f"   operator_name: {detection.operator_name}")
            if detection.model_name:
                lines.append(f"   model_name: {detection.model_name}")
            if detection.model_version:
                lines.append(f"   model_version: {detection.model_version}")
            if detection.model_release_date:
                lines.append(f"   model_release_date: {detection.model_release_date}")
            if detection.evidence:
                lines.append(f"   evidence: {', '.join(detection.evidence)}")
        return "\n".join(lines)

    def render_review(self) -> str:
        lines = [
            "Registack AIR Detection Review",
            f"scanner_version: {VERSION}",
            f"detections: {len(self.detections)}",
            f"new_detections: {self.new_detection_count}",
        ]
        reviewed = [item for item in self.detections if item.review_state == REVIEW_STATE_REVIEWED]
        pending = [item for item in self.detections if item.review_state != REVIEW_STATE_REVIEWED]
        ready = [item for item in self.detections if bool(item.air_candidate.get("import_ready", True))]
        lines.append(f"reviewed: {len(reviewed)}")
        lines.append(f"pending_review: {len(pending)}")
        lines.append(f"air_import_ready: {len(ready)}")
        lines.append("")
        if not self.detections:
            lines.append("No detections found.")
            return "\n".join(lines)

        sections = [
            ("Reviewed Detections", reviewed),
            ("Pending Review", pending),
        ]
        for heading, items in sections:
            if not items:
                continue
            lines.append(heading + ":")
            for index, detection in enumerate(
                sorted(
                    items,
                    key=lambda item: (
                        item.review_state != REVIEW_STATE_REVIEWED,
                        item.discovery_state != "new",
                        not bool(item.air_candidate.get("import_ready", True)),
                        item.path,
                    ),
                ),
                start=1,
            ):
                import_ready = bool(detection.air_candidate.get("import_ready", True))
                lines.append(
                    f"  {index}. [{detection.review_state}] [{detection.discovery_state}] "
                    f"{detection.title} -> {detection.air_record_type}"
                )
                lines.append(f"     path: {detection.path}")
                lines.append(
                    f"     provider/model: {first_non_empty(detection.provider_name, '-')} / "
                    f"{first_non_empty(detection.model_name, '-')} / "
                    f"{first_non_empty(detection.model_version, '-')}"
                )
                lines.append(
                    f"     metadata/confidence/criticality: {detection.metadata_status} / "
                    f"{detection.air_candidate.get('confidence', '-')} / {detection.operational_criticality}"
                )
                lines.append(f"     import_ready: {import_ready}")
                warnings = detection.air_candidate.get("validation_warnings", [])
                if isinstance(warnings, list) and warnings:
                    lines.append(f"     validation_warnings: {', '.join(str(item) for item in warnings)}")
                if detection.air_detection_record_id:
                    lines.append(f"     air_detection_record_id: {detection.air_detection_record_id}")
                if detection.reviewed_at:
                    lines.append(f"     reviewed_at: {detection.reviewed_at}")
            lines.append("")

        lines.append("Next step:")
        lines.append(
            "  Pipe this detector JSON into `registack-air-import --review` to record reviewed detections locally"
        )
        lines.append(
            "  and optionally import AIR detection records into the licensed Registack AIR Control Plane."
        )
        return "\n".join(lines)


def normalize_criticality(value: str) -> str:
    lowered = str(value).strip().lower()
    if lowered in {"low", "medium", "high", "critical"}:
        return lowered
    return "medium"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def has_ai_image_pattern(image_name: str) -> bool:
    lowered = str(image_name).lower()
    return any(pattern in lowered for pattern in DOCKER_IMAGE_PATTERNS)


def shutil_which(binary: str) -> str | None:
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        if not entry:
            continue
        candidate = Path(entry) / binary
        if candidate.exists() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Detect AI-agent candidates and AIR-relevant runtime artifacts locally.",
    )
    parser.add_argument("--scan-dir", action="append", default=[], help="Directory or file path to scan. Repeatable.")
    parser.add_argument(
        "--scan-default",
        action="store_true",
        help="Scan the default detection path saved during installation.",
    )
    parser.add_argument("--scan-docker", action="store_true", help="Inspect local Docker runtimes.")
    parser.add_argument("--scan-kubernetes", action="store_true", help="Inspect local Kubernetes manifests in scanned paths.")
    parser.add_argument("--deep", action="store_true", help="Enable recursive deep scan.")
    parser.add_argument("--review", action="store_true", help="Render a human review view for the detected list.")
    parser.add_argument("--output", choices=("json", "text"), default="text", help="Output format.")
    parser.add_argument("--quiet", action="store_true", help="Suppress warnings and non-essential stderr output.")
    parser.add_argument("--version", action="version", version=f"registack-agent-detector {VERSION}")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.scan_default and args.scan_dir:
        parser.error("--scan-default cannot be combined with --scan-dir")
    if args.review and args.output == "json":
        parser.error("--review cannot be combined with --output json")

    scan_dirs = list(args.scan_dir or [])
    if args.scan_default:
        scan_dirs = configured_scan_dirs()
        if not scan_dirs:
            if args.output == "json":
                print(
                    json.dumps(
                        {
                            "detections": [],
                            "scan_metadata": {
                                "timestamp": now_iso(),
                                "scanner_version": VERSION,
                                "output_format": OUTPUT_FORMAT,
                                "error": "No default detection path configured. Reinstall or use --scan-dir.",
                            },
                        },
                        indent=2,
                    )
                )
            else:
                print(
                    "error: no default detection path configured. Reinstall or use --scan-dir.",
                    file=sys.stderr,
                )
            return 2
    elif not scan_dirs:
        scan_dirs = configured_scan_dirs()
    if not scan_dirs:
        scan_dirs = [os.getcwd()]

    detector = Detector(quiet=args.quiet)
    try:
        detector.scan_paths(scan_dirs, deep=args.deep, scan_kubernetes=args.scan_kubernetes)
        detector.scan_local_endpoints()
        if args.scan_docker:
            detector.scan_docker()
        if args.scan_kubernetes:
            detector.scan_kubernetes_manifests_only(scan_dirs, deep=args.deep)
    except DetectorError as exc:
        if args.output == "json":
            print(
                json.dumps(
                    {
                        "detections": [],
                        "scan_metadata": {
                            "timestamp": now_iso(),
                            "scanner_version": VERSION,
                            "output_format": OUTPUT_FORMAT,
                            "error": str(exc),
                        },
                    },
                    indent=2,
                )
            )
        else:
            print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        if not args.quiet:
            print("error: interrupted", file=sys.stderr)
        return 2

    detector.apply_detection_history()

    if args.output == "json":
        print(detector.render_json())
    elif args.review:
        print(detector.render_review())
    else:
        print(detector.render_text())

    if detector.detections:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
