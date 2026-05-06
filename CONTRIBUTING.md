# Contributing to VulneraX

Thank you for your interest in contributing! VulneraX is an open-source project and welcomes contributions of all kinds.

---

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Code Standards](#code-standards)
- [Adding a Plugin](#adding-a-plugin)
- [Submitting a Pull Request](#submitting-a-pull-request)

---

## Code of Conduct

Please read our [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before participating.

---

## How to Contribute

You can contribute by:

- 🐛 **Reporting bugs** - open a GitHub Issue with steps to reproduce
- ✨ **Requesting features** - open an Issue with the `enhancement` label
- 🔌 **Submitting plugins** - new scanner integrations are highly welcome
- 📖 **Improving docs** - fix typos, add examples, improve clarity
- 🧪 **Adding tests** - unit tests for parsers and engines especially
- 🌐 **Translations** - help us localise the documentation

---

## Development Setup

### 1. Fork and Clone

```bash
git clone https://github.com/YOUR_USERNAME/vulnerax.git
cd vulnerax
```

### 2. Create a Virtual Environment

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux / macOS
source .venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Run VulneraX Locally

```bash
# Launch GUI
python main.py

# Run a CLI scan (no external tools needed for dry-run)
python main.py scan https://example.com --quick

# Start API server
python main.py api
```

### 5. Check Dependencies

```bash
python main.py deps
```

---

## Project Structure

| Directory | Purpose |
|---|---|
| `core/` | Orchestrator, correlation, risk, AI engines |
| `scanners/` | One file per tool (inherit `BaseScanner`) |
| `parsers/` | Raw output → Vulnerability objects |
| `plugins/` | User-added scanner plugins (auto-discovered) |
| `reports/` | HTML / JSON / CSV report generators |
| `gui/` | CustomTkinter panels and app window |
| `api/` | FastAPI server and route definitions |
| `utils/` | Shared utilities - schema, logger, config, etc. |

---

## Code Standards

- **Python 3.10+** - use type hints everywhere
- **Docstrings** - every public class and method needs a docstring
- **No hardcoding** - all paths, ports, and timeouts go in `config.yaml`
- **No silent failures** - log warnings or raise informative exceptions
- **Line length** - max 100 characters
- **Imports** - stdlib → third-party → local, each group alphabetically sorted
- **Naming** - `snake_case` for variables/functions, `PascalCase` for classes

Run a quick sanity check before submitting:

```bash
python -m py_compile main.py cli.py
python -c "from core.orchestrator import Orchestrator; print('OK')"
```

---

## Adding a Plugin

The plugin system is designed to be the primary extension point for the community.

### Step-by-step

1. Create `plugins/your_scanner.py`
2. Subclass `PluginBase`:

```python
from plugins.plugin_base import PluginBase
from utils.schema import Vulnerability

class YourScanner(PluginBase):
    name        = "your_scanner"       # unique snake_case ID
    description = "One-line description"
    author      = "Your Name"
    version     = "1.0.0"

    def run(self) -> list[Vulnerability]:
        """Scan self.target and return findings."""
        findings = []
        # ... your scan logic ...
        findings.append(
            Vulnerability(
                name="Finding Name",
                source=self.name,
                severity="medium",          # critical/high/medium/low/info
                url=self.target,
                description="What was found.",
                remediation="How to fix it.",
            )
        )
        return findings
```

3. Drop the file into `plugins/` - VulneraX will auto-discover it on next run.
4. Use `python main.py plugins` to verify it's loaded.

### Plugin guidelines

- Handle `FileNotFoundError` for missing binaries (the base class will catch and log it)
- Call `self._emit(message, percent)` to update the GUI progress bar
- Return an empty list `[]` when nothing is found - never `None`
- Use `self.log.warning(...)` for non-fatal issues

---

## Submitting a Pull Request

1. **Create a branch**: `git checkout -b feat/my-scanner`
2. **Write clean code** following the standards above
3. **Test it**: ensure it runs without errors
4. **Commit with a clear message**: `git commit -m "feat: add SSLyze scanner plugin"`
5. **Push and open a PR** against `main`

### PR Checklist

- [ ] Code follows project style (type hints, docstrings, no hardcoding)
- [ ] No new dependencies added without updating `requirements.txt`
- [ ] Plugin has `name`, `description`, `author`, `version` set
- [ ] Tested locally against at least one real target (with permission)
- [ ] `README.md` updated if the feature is user-visible
