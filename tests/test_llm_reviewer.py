from pathlib import Path
from secskill.llm.cache import LLMCache

def test_cache(tmp_path: Path):
    cache = LLMCache(cache_dir=str(tmp_path))
    cache.set("test prompt", "ollama", {"status": "CONFIRMED"})
    res = cache.get("test prompt", "ollama")
    assert res is not None
    assert res.get("status") == "CONFIRMED"
