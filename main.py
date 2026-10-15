#!/usr/bin/env python3
"""
Root entry point redirector for Leftover-Cleaner.
Enables running 'python main.py' directly from the root repository directory.
"""

import sys
import os
from pathlib import Path

# Add 'src' directory to Python search path
ROOT_DIR = Path(__file__).resolve().parent
SRC_DIR = ROOT_DIR / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# Import main supervisor from src/main.py
from main import main

if __name__ == "__main__":
    main()
