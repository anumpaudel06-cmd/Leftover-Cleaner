# Contributing to Leftover-Cleaner

Thank you for your interest in improving **Leftover-Cleaner**! We welcome bug reports, feature suggestions, and code contributions that adhere to our strict safety standards.

---

## 🛡️ Core Contribution Rule: Safety First

Leftover-Cleaner's primary design priority is **zero risk of Windows OS corruption**. Any PR or code modification must:
1. Never weaken or bypass the `SafetyEngine` path and registry blacklists (`System32`, `WinSxS`, `Drivers`, `HKLM\Software\Microsoft`, etc.).
2. Always ensure that `tests/test_safety.py` passes 100% of assertions before submitting.
3. Keep user deletions defaulted to **Dry-Run (Preview Only)** mode.

---

## 🛠️ Development Setup

1. **Fork and Clone the Repository**:
   ```bash
   git clone https://github.com/anumpaudel06-cmd/Leftover-Cleaner.git
   cd Leftover-Cleaner
   ```

2. **Create a Virtual Environment**:
   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On Linux/macOS:
   source venv/bin/activate
   ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Run Unit Tests**:
   ```bash
   python -m unittest discover -s tests -p "test_*.py"
   ```

---

## 🧪 Testing Your Changes

Before opening a pull request, run:
```bash
# Verify all safety guardrails
pytest tests/
# Or via standard library
python -m unittest discover -s tests
```

---

## 🚀 Pull Request Guidelines

1. Create a descriptive feature branch: `git checkout -b feature/my-enhancement`.
2. Commit with clean, standard commit messages (`feat: ...`, `fix: ...`, `docs: ...`).
3. Ensure no local `.pyc` or virtualenv files are committed.
4. Open your PR against the `main` branch.
