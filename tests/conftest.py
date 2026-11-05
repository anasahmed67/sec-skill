import pytest
from pathlib import Path
from secskill.models import ScanContext

@pytest.fixture
def sample_context(tmp_path: Path) -> ScanContext:
    f = tmp_path / "app.py"
    f.write_text("print('hello world')", encoding="utf-8")
    return ScanContext(target_path=str(tmp_path), files=["app.py"], languages=["python"])
