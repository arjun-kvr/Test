"""Make the repo root importable so `src` and the tools module resolve."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
