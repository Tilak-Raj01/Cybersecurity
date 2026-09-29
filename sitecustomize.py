"""Ensure project modules are importable from the workspace root.

This repository stores Python modules under the ``Backend`` directory, while
some tests import them as if they lived at the project root. Adding the backend
folder to ``sys.path`` here keeps imports stable across local runs and CI.
"""

import os
import sys

PROJECT_ROOT = os.path.dirname(__file__)
BACKEND_DIR = os.path.join(PROJECT_ROOT, "Backend")

for candidate in (PROJECT_ROOT, BACKEND_DIR):
    if candidate not in sys.path:
        sys.path.insert(0, candidate)
