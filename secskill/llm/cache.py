"""Hash-based response cache for LLM queries to reduce latency and cost."""
import hashlib
import json
from pathlib import Path
from typing import Optional, Dict, Any

class LLMCache:
    def __init__(self, cache_dir: str = ".secskill_cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _hash_key(self, prompt: str, model: str) -> str:
        content = f"{model}:{prompt}".encode("utf-8")
        return hashlib.sha256(content).hexdigest()

    def get(self, prompt: str, model: str) -> Optional[Dict[str, Any]]:
        key = self._hash_key(prompt, model)
        target = self.cache_dir / f"{key}.json"
        if target.exists():
            try:
                return json.loads(target.read_text(encoding="utf-8"))
            except Exception:
                return None
        return None

    def set(self, prompt: str, model: str, response: Dict[str, Any]) -> None:
        key = self._hash_key(prompt, model)
        target = self.cache_dir / f"{key}.json"
        target.write_text(json.dumps(response, indent=2), encoding="utf-8")
