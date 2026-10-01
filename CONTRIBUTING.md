# Contributing to Quantum-Safe Migration (QSM)

First — **thank you** for considering contributing to QSM! 🎉

This project exists because developers like you care about a
quantum-safe future. Every contribution — code, docs, bug reports,
ideas — makes a difference.

---

## 📜 Code of Conduct

By participating, you agree to abide by our
[Code of Conduct](./CODE_OF_CONDUCT.md). Be kind, be patient, be
professional. We're all here to build something meaningful.

---

## 🎯 What We're Looking For

### High Priority

- 🐛 **Bug reports** with reproduction steps
- 🔒 **Security vulnerabilities** (see [SECURITY.md](./SECURITY.md))
- 📖 **Documentation** improvements (typos, clarity, examples)
- ✅ **Test coverage** (unit + integration tests)
- 🌍 **Additional migration targets** (Apache, HAProxy, PostgreSQL)

### Medium Priority

- 🎨 **UI/UX improvements** to the Rich terminal output
- ⚡ **Performance optimizations** (especially in simulator)
- 🧪 **Algorithm accuracy** in Shor's metrics
- 📦 **Packaging** (pyproject.toml, Debian .deb, Docker image)

### Low Priority

- Cosmetic changes without functional value
- Dependencies upgrades without security justification

---

## 🚀 Development Workflow

### 1. Fork & Clone

```bash
git clone https://github.com/soufianecyber/Quantum-Safe-Migration.git
cd Quantum-Safe-Migration
git remote add upstream https://github.com/soufianecyber/Quantum-Safe-Migration.git
```

### 2. Set Up Environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install black mypy pytest
```

### 3. Create a Branch

Use descriptive branch names:

```bash
git checkout -b fix/rollback-checksum-edge-case
git checkout -b feat/apache-migration-target
git checkout -b docs/improve-quantum-explanation
```

**Branch naming convention:**
- `feat/` — new feature
- `fix/` — bug fix
- `docs/` — documentation only
- `refactor/` — code restructuring
- `test/` — test additions
- `chore/` — maintenance

### 4. Make Your Changes

- Follow the **existing code style** (Black, 88-char lines)
- Add **type hints** for new functions
- Add **docstrings** (Google style) for public functions
- Keep commits **atomic** and **well-described**

### 5. Test Locally

```bash
# Format
black qsm.py

# Type check
mypy --ignore-missing-imports qsm.py

# Smoke test
python3 qsm.py --version
python3 qsm.py --preflight
python3 qsm.py --simulate --target example.com
python3 qsm.py --migrate --target nginx --config /tmp/test.conf --dry-run
```

### 6. Commit

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add Apache httpd migration target
fix: handle empty config file in nginx parser
docs: clarify HNDL timeline in README
refactor: extract crypto detection into helper module
test: add unit tests for RollbackEngine
```

### 7. Push & Pull Request

```bash
git push origin your-branch-name
```

Then open a PR on GitHub with:

- **Clear title** (imperative mood)
- **Description** explaining *what* and *why*
- **Link to related issue** (`Closes #42`)
- **Screenshots** if UI changes
- **Test evidence** (commands run, results)

---

## 🧪 Testing Guidelines

We use **pytest** for testing. When adding a feature:

- Add **unit tests** for isolated logic
- Add **integration tests** for CLI behavior
- Test **edge cases**: empty files, malformed input, permission errors

Example test structure:

```python
def test_hybrid_enforcement_blocks_pure_pqc(tmp_path):
    """Pure PQC config must be rejected by the hybrid guard."""
    # ... setup
    with pytest.raises(MigrationError, match="Hybrid enforcement violated"):
        migrator._assert_hybrid_enforced("Kyber768 only content", "nginx")
```

---

## 📖 Documentation

If your change is user-facing:

- Update **README.md** if CLI changes
- Update **docstrings** in the code
- Add **examples** in the CLI epilog if new command
- Update **CHANGELOG.md** if it exists

---

## 🔍 Review Process

After you open a PR:

1. **Automated checks** run (when CI is set up)
2. **Maintainer review** within 5 business days
3. **Discussion** — we may ask for changes
4. **Approval & merge** — squash-merged into main

We aim to be **respectful** and **constructive** in reviews. If you
disagree with feedback, say so politely — we're all learning.

---

## 🏆 Recognition

Contributors are recognized in:

- The **release notes** of each version
- The **CONTRIBUTORS.md** file (once we have enough)
- **GitHub's contributor graph** (obviously)

---

## 📬 Questions?

- 💬 Open a [Discussion](https://github.com/soufianecyber/Quantum-Safe-Migration/discussions)
- 🐛 Open an [Issue](https://github.com/soufianecyber/Quantum-Safe-Migration/issues)
- 📧 Email: `soufiane.cyber.mail@gmail.com`

---

**Thank you for helping make the quantum transition safer for everyone.** 🌌🔐
