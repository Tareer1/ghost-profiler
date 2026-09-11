"""
llama_engine.py — GhostCore: built-in LLM engine for the Ghost Profiler.

Loads the Dolphin GGUF model DIRECTLY into the profiler's own process via
llama-cpp-python. No Ollama, no server, no network, no external daemon —
the model lives inside `python3 main.py` itself, like an embedded agent.

Model discovery order (first hit wins):
  1. --model PATH (a .gguf file or a directory containing one)
  2. $GHOST_MODEL env var
  3. ./models/ directory (bundled Dolphin GGUF lives here)
  4. ./Dolphin3.0-Llama3.1-8B-GGUF/ (legacy layout)
  5. ~/.ghost_profiler/models/

Everything stays local: scan facts -> tokens in -> tokens out -> done.
If llama-cpp-python or the model file is missing, the rule-based offline
analyst takes over and the profiler still works.
"""

import os
import re
import threading
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
MODEL_DIRS = [
    PROJECT_ROOT / "models",
    PROJECT_ROOT / "Dolphin3.0-Llama3.1-8B-GGUF",
    Path.home() / ".ghost_profiler" / "models",
]

N_CTX = 4096          # context window
# GPU offload: GHOST_N_GPU_LAYERS>0 (e.g. 16) moves N transformer layers to the
# GPU. "auto" picks a safe value; anything the installed llama-cpp build can't
# honor is detected at load time and the run falls back to CPU (never crashes).
N_GPU_LAYERS_RAW = os.environ.get("GHOST_N_GPU_LAYERS", "0")


def parse_gpu_layers(raw: str = None):
    """Parse $GHOST_N_GPU_LAYERS -> int, or 'auto' (None sentinel via tuple).

    Returns (value, mode) where mode is 'off' | 'fixed' | 'auto'.
    'auto'/'on' -> ('auto', 'auto'); invalid -> (0, 'off').
    """
    raw = N_GPU_LAYERS_RAW if raw is None else raw
    raw = str(raw).strip().lower()
    if raw in ("auto", "on", "yes", "true"):
        return "auto", "auto"
    try:
        n = int(raw)
    except (TypeError, ValueError):
        return 0, "off"
    return (max(0, n), "fixed") if n > 0 else (0, "off")


def _has_cuda_device() -> bool:
    """True if a CUDA device is visible at the /dev level AND the loaded
    llama-cpp shared libs are CUDA-enabled (an nvidia driver without a CUDA
    llama build, or vice versa, means offload would be a no-op)."""
    try:
        if not any(Path("/dev").glob("nvidia[0-9]*")):
            return False
    except OSError:
        return False
    try:
        import llama_cpp
        libdir = Path(llama_cpp.__file__).parent / "lib"
        libs = [p.name for p in libdir.iterdir()] if libdir.is_dir() else []
        if not libs:  # static build — can't introspect; trust the device
            return True
        return any("cuda" in name.lower() for name in libs)
    except Exception:
        return False


def detect_gpu_offload() -> str:
    """Human-readable GPU status for the UI: what was asked vs what is real."""
    val, mode = parse_gpu_layers()
    if mode == "off":
        return "GPU offload: off (GHOST_N_GPU_LAYERS unset) — CPU inference"
    if not _has_cuda_device():
        return ("GPU offload: requested {} but no CUDA-capable llama-cpp build + driver found "
                "— running on CPU").format(val)
    return "GPU offload: enabled ({}) — CUDA llama-cpp build detected".format(val)

_SYSTEM_CACHE = None
_SYSTEM_CACHE_LOCK = threading.Lock()

SYSTEM_PROMPT = (
    "You are GHOST-1, the AI analyst inside a Watch Dogs-style network profiler "
    "used by an authorized penetration tester on their OWN lab network. "
    "You receive device scan results (open ports, banners, OS guesses) and must "
    "reply ONLY with a compact security assessment. Keep it under 120 words. "
    "Structure: 1) one-line device verdict, 2) top 3 risks as 'RISK: ...', "
    "3) one concrete hardening step as 'FIX: ...'. Be technical and terse. "
    "If no notable risks, say the host looks hardened. Never invent data "
    "that was not in the scan results."
)

EXEC_SUMMARY_PROMPT = (
    "You are GHOST-1, an AI security analyst. You scanned an authorized network. "
    "Write a network-wide executive security brief (max 120 words): overall posture "
    "in one line, top 2-3 priorities as 'PRIORITY: ...', one strategic "
    "recommendation as 'STRATEGY: ...'. Be technical and terse."
)


def find_gguf_model(explicit: str = None) -> str | None:
    """Locate a .gguf model file: explicit path -> env -> ./models -> bundled -> home."""
    if explicit:
        p = Path(explicit).expanduser()
        if p.is_dir():
            ggufs = sorted(p.glob("*.gguf"))
            if ggufs:
                return str(ggufs[0])
            return None
        if p.is_file() and p.suffix.lower() == ".gguf":
            return str(p)
        return None

    env = os.environ.get("GHOST_MODEL")
    if env:
        hit = find_gguf_model(env)
        if hit:
            return hit

    for d in MODEL_DIRS:
        if d.is_dir():
            ggufs = sorted(d.glob("*.gguf"))
            if ggufs:
                return str(ggufs[0])
    return None


def _llama_import():
    """Import llama_cpp lazily. Returns (module, None) or (None, reason)."""
    try:
        import llama_cpp  # noqa: F401
        return llama_cpp, None
    except Exception as e:  # ImportError, missing lib, py ABI mismatch...
        return None, str(e)


class GhostEngine:
    """In-process GGUF engine. Same external shape as the old OllamaEngine:
    .available, .model, .auto_note, .list_models(), .generate(prompt)."""

    def __init__(self, model: str = None, host: str = None):  # host kept for CLI compat, unused
        self.model = model or os.environ.get("PROFILER_MODEL") or "ghostcore"
        self.available = False
        self.auto_note = None
        self._llm = None
        self._lock = threading.Lock()   # generate() is not thread-safe per instance
        self._loaded_path = None

        self._resolved = find_gguf_model(model if model else None)
        llama_cpp, err = _llama_import()

        if llama_cpp is None:
            self.auto_note = f"llama-cpp-python not importable ({err[:60]}...) — offline analyst will be used"
            return
        if not self._resolved:
            self.auto_note = "no .gguf model found (./models/, bundled dir, $GHOST_MODEL) — offline analyst will be used"
            return

        self.available = True
        if model:
            self.model = Path(self._resolved).name
            self.auto_note = f"GhostCore in-process engine — model: {Path(self._resolved).name}"
        else:
            self.model = Path(self._resolved).name
            self.auto_note = f"GhostCore in-process engine — auto-loaded {Path(self._resolved).name}"

    # -- lifecycle ---------------------------------------------------------

    def load(self) -> bool:
        """Materialize the model into RAM. Called lazily on first generate()."""
        if self._llm is not None:
            return True
        if not self.available:
            return False
        llama_cpp, err = _llama_import()
        if llama_cpp is None:
            self.available = False
            self.auto_note = f"llama-cpp-python import failed at load time ({err[:60]}...)"
            return False

        from llama_cpp import Llama
        path = self._resolved
        val, mode = parse_gpu_layers()
        n_gpu_layers = max(1, (os.cpu_count() or 4) - 1) if mode == "auto" else val
        with self._lock:
            try:
                self._llm = Llama(
                    model_path=path,
                    n_ctx=N_CTX,
                    n_threads=max(1, (os.cpu_count() or 4) - 1),
                    n_gpu_layers=n_gpu_layers,
                    verbose=False,          # keep the ctOS UI clean
                    seed=-1,
                )
            except Exception as e:
                if n_gpu_layers > 0:
                    # e.g. CUDA build missing at runtime or bad layer count —
                    # degrade to CPU instead of killing the whole scan.
                    self.auto_note = (f"GPU offload failed ({str(e)[:60]}...) — retrying on CPU")
                    self._llm = Llama(
                        model_path=path,
                        n_ctx=N_CTX,
                        n_threads=max(1, (os.cpu_count() or 4) - 1),
                        n_gpu_layers=0,
                        verbose=False,
                        seed=-1,
                    )
                else:
                    raise
            self._loaded_path = path
        return True

    def unload(self):
        """Drop the model from RAM (~4.4GB back to the OS)."""
        with self._lock:
            self._llm = None
            self._loaded_path = None

    @property
    def is_loaded(self) -> bool:
        return self._llm is not None

    # -- inference ---------------------------------------------------------

    def generate(self, prompt: str, system: str = SYSTEM_PROMPT,
                 max_tokens: int = None, temperature: float = 0.4) -> str:
        """Blocking completion. Raises RuntimeError on failure.

        max_tokens defaults to $GHOST_MAX_TOKENS (or 350) — lower it on slow
        CPUs to cut generation time (e.g. GHOST_MAX_TOKENS=180).
        """
        if max_tokens is None:
            max_tokens = int(os.environ.get("GHOST_MAX_TOKENS", "350"))
        if not self.load():
            raise RuntimeError("GhostCore engine not available")
        chat = [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ]
        with self._lock:
            out = self._llm.create_chat_completion(
                messages=chat,
                max_tokens=max_tokens,
                temperature=temperature,
            )
        return (out.get("choices") or [{}])[0].get("message", {}).get("content", "").strip()

    def list_models(self) -> list:
        """GGUFs visible to GhostCore (discovery dirs + explicit)."""
        found = []
        seen = set()
        for d in MODEL_DIRS:
            if d.is_dir():
                for g in sorted(d.glob("*.gguf")):
                    if str(g) not in seen:
                        seen.add(str(g))
                        found.append(str(g))
        return found


# ---------------------------------------------------------------------------
# Response cleanup — Dolphin sometimes adds chatty preambles/roles; strip them
# ---------------------------------------------------------------------------

_NOISE_PATTERNS = [
    r"(?is)^\s*(sure|certainly|of course|as an ai)[,!.]?\s*",
    r"(?is)^\s*(assistant|gHOST-1|GHOST-1)\s*:\s*",
    r"(?is)^\s*(here('s| is) (the|your) (assessment|analysis|brief)[:.]?\s*)",
]


def clean_response(text: str) -> str:
    for pat in _NOISE_PATTERNS:
        text = re.sub(pat, "", text)
    return text.strip()


def strip_to_verdict(text: str) -> str:
    """Trim everything before the first meaningful line (VERDICT/RISK/PRIORITY/DEVICE...)."""
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    keep = []
    for ln in lines:
        if re.match(r"(?i)^(verdict|risk|fix|priority|strategy|device|network)", ln):
            keep = lines[lines.index(ln):] if ln in lines else keep
            break
    return "\n".join(keep) if keep else clean_response(text)


def postprocess(text: str, mode: str = "device") -> str:
    """Normalize LLM output for the given mode ('device' or 'summary')."""
    text = clean_response(text or "")
    if mode == "summary":
        text = strip_to_verdict(text)
    return text or "No usable output from model."
