# Contributing to CertSeal

Thank you for your interest in contributing to **CertSeal**! Contributions are welcome and encouraged.

---

## Getting Started

1. **Fork** the repository on GitHub.
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/YOUR-USERNAME/certseal.git
   cd certseal
   ```
3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
4. **Create a branch** for your changes:
   ```bash
   git checkout -b feature/my-new-algorithm
   ```

---

## Adding a New Algorithm Module

1. Create a new file in `certseal/`, e.g. `certseal/my_algo.py`.
2. Implement your functions with **full docstrings** (Args, Returns, Raises).
3. Export the new functions from `certseal/__init__.py` if appropriate.
4. Add a corresponding test file in `tests/`, e.g. `tests/test_my_algo.py`.
5. If the algorithm is user-facing, add a CLI subcommand in `cli/main.py` and a GUI tab in `gui/app.py`.

---

## Code Standards

- **PEP 8** compliance is required. Lint with `flake8 --max-line-length=120`.
- Every public function must have a **complete docstring** with `Args:` and `Returns:` sections.
- All new functionality must include **unit tests** in `tests/`.
- Tests should use `pytest` and follow the naming convention `test_<description>`.
- Do not introduce new dependencies unless absolutely necessary. If you do, add them to `requirements.txt` and justify them in your PR.
- Security-sensitive code should be reviewed carefully. Avoid insecure defaults.

---

## Pull Request Process

1. Ensure all existing tests still pass: `pytest tests/ -v`.
2. Add tests for your new functionality.
3. Update `README.md` if your change adds new user-facing features.
4. Submit a pull request against the `main` branch with a clear description of:
   - What the change does.
   - Why it is needed.
   - Any trade-offs or limitations.

---

## Questions?

Open an issue on GitHub and we will respond as soon as possible.
