#!/usr/bin/env python3
# Registack AIR — Internal Pre-Release. © Registack.
"""
Registack AIR Agent Detector CLI.

Local-only detector for AI-agent candidates, runtime artifacts, Docker
containers, Kubernetes workload manifests, and local AI endpoints.
"""

from __future__ import annotations

import argparse
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

VERSION = "0.1.0"
OUTPUT_FORMAT = "air-compatible"
ENV_CONFIG_PATH = "REGISTACK_AGENT_DETECTOR_CONFIG"
CONFIG_POINTER_FILENAME = ".registack-agent-detector-config"

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
    evidence: list[str] = field(default_factory=list)
    air_record_type: str = "detection_record"
    air_payload: dict = field(default_factory=dict)


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
    scan_dirs = config.get("default_scan_dirs", [])
    if not isinstance(scan_dirs, list):
        return []
    return [str(item) for item in scan_dirs if str(item).strip()]


class Detector:
    def __init__(self, quiet: bool = False) -> None:
        self.quiet = quiet
        self.detections: list[Detection] = []
        self.warnings: list[str] = []
        self.paths_scanned: list[str] = []

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
    ) -> None:
        detection = Detection(
            detection_type=detection_type,
            title=title,
            path=path,
            detail=detail,
            source=source,
            confidence_score=max(0.0, min(1.0, confidence_score)),
            operational_criticality=normalize_criticality(operational_criticality),
            evidence=list(evidence or []),
            air_payload=air_payload or {},
        )
        self.detections.append(detection)

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

        registack_marker_emitted = False
        if lowered_name in REGISTACK_MARKER_FILES:
            self.add_detection(
                detection_type="registack_marker_file",
                title=REGISTACK_MARKER_FILES[lowered_name],
                path=str(path),
                detail="Registack-governed identity or profile artifact detected.",
                source="filesystem",
                confidence_score=0.98,
                operational_criticality="high",
                evidence=[lowered_name],
                air_payload={
                    "candidate_kind": "registack-managed-agent",
                    "marker_file": lowered_name,
                },
            )
            registack_marker_emitted = True

        if lowered_name in AGENT_CONFIG_FILES:
            self.add_detection(
                detection_type="agent_config_file",
                title=AGENT_CONFIG_FILES[lowered_name],
                path=str(path),
                detail="Agent-oriented configuration artifact detected.",
                source="filesystem",
                confidence_score=0.92,
                operational_criticality="medium",
                evidence=[lowered_name],
                air_payload={
                    "candidate_kind": "agent-config",
                    "config_file": lowered_name,
                },
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
                evidence=[lowered_name],
                air_payload={"candidate_kind": "runtime-artifact"},
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
            )

        should_read_text = lowered_name in FRAMEWORK_FILES or suffix in TEXT_EXTENSIONS or scan_kubernetes
        if not should_read_text:
            return

        try:
            sample = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return

        lowered_text = sample.lower()
        self._detect_framework_indicators(path, lowered_text)
        if deep:
            self._detect_registack_yaml(path, lowered_text, replace_generic=registack_marker_emitted)
        if scan_kubernetes:
            self._detect_kubernetes_manifest(path, lowered_text)

    def _detect_framework_indicators(self, path: Path, lowered_text: str) -> None:
        hits = []
        for keyword, label in FRAMEWORK_KEYWORDS.items():
            if keyword in lowered_text:
                hits.append(label)
        if not hits:
            return

        unique_hits = sorted(set(hits))
        self.add_detection(
            detection_type="framework_indicator",
            title="AI framework indicator",
            path=str(path),
            detail="Framework references found: " + ", ".join(unique_hits),
            source="filesystem",
            confidence_score=0.73,
            operational_criticality="medium",
            evidence=unique_hits,
            air_payload={
                "candidate_kind": "framework-indicator",
                "frameworks": unique_hits,
            },
        )

    def _detect_registack_yaml(self, path: Path, lowered_text: str, replace_generic: bool) -> None:
        if path.name.lower() != ".registack.yaml":
            return
        if "agent_id" in lowered_text or "authorized_profile" in lowered_text or "functional_profile" in lowered_text:
            if replace_generic:
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
                evidence=[".registack.yaml", "identity-semantic-content"],
                air_payload={
                    "candidate_kind": "registack-managed-agent",
                    "marker_file": ".registack.yaml",
                },
            )

    def _detect_kubernetes_manifest(self, path: Path, lowered_text: str) -> None:
        if path.suffix.lower() not in {".yaml", ".yml", ".json"}:
            return
        if not any(pattern in lowered_text for pattern in KUBERNETES_KIND_PATTERNS):
            return

        images = re.findall(r"image\s*:\s*['\"]?([^\s\"']+)", lowered_text)
        matching_images = [image for image in images if has_ai_image_pattern(image)]
        if not matching_images:
            return

        self.add_detection(
            detection_type="kubernetes_workload_detection",
            title="Kubernetes workload with AI image pattern",
            path=str(path),
            detail="Manifest references AI-related workload images.",
            source="filesystem",
            confidence_score=0.88,
            operational_criticality="high",
            evidence=matching_images[:5],
            air_payload={
                "candidate_kind": "kubernetes-workload-manifest",
                "images": matching_images[:5],
            },
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
                    self.add_detection(
                        detection_type="container_runtime_detection",
                        title="Docker container with AI image pattern",
                        path=f"docker://{container.name}",
                        detail=f"Running container {container.name} uses image {image_name}",
                        source="docker",
                        confidence_score=0.93,
                        operational_criticality="high",
                        evidence=[container.name, image_name],
                        air_payload={
                            "candidate_kind": "docker-runtime",
                            "container_name": container.name,
                            "image": image_name,
                        },
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
            self.add_detection(
                detection_type="container_runtime_detection",
                title="Docker container with AI image pattern",
                path=f"docker://{name}",
                detail=f"Running container {name} uses image {image_name}",
                source="docker",
                confidence_score=0.9,
                operational_criticality="high",
                evidence=[container_id, image_name],
                air_payload={
                    "candidate_kind": "docker-runtime",
                    "container_name": name,
                    "container_id": container_id,
                    "image": image_name,
                },
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
            if detection.evidence:
                lines.append(f"   evidence: {', '.join(detection.evidence)}")
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
    parser.add_argument("--output", choices=("json", "text"), default="text", help="Output format.")
    parser.add_argument("--quiet", action="store_true", help="Suppress warnings and non-essential stderr output.")
    parser.add_argument("--version", action="version", version=f"registack-agent-detector {VERSION}")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.scan_default and args.scan_dir:
        parser.error("--scan-default cannot be combined with --scan-dir")

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

    if args.output == "json":
        print(detector.render_json())
    else:
        print(detector.render_text())

    if detector.detections:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
