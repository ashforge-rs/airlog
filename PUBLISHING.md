# Publishing to PyPI

This document describes how to publish airlog to PyPI.

## Prerequisites

1. Install build tools:
   ```bash
   uv add --dev build twine
   ```

2. Create accounts on:
   - [PyPI](https://pypi.org/account/register/) (production)
   - [TestPyPI](https://test.pypi.org/account/register/) (testing)

3. Configure API tokens:
   - Generate API tokens from your PyPI/TestPyPI account settings
   - Store them securely (e.g., in password manager)

## Build the Package

```bash
# Clean previous builds
rm -rf dist/ build/ *.egg-info

# Build source distribution and wheel
uv run python -m build

# Verify the build
ls -lh dist/
```

This will create:
- `dist/airlog-0.1.0.tar.gz` (source distribution)
- `dist/airlog-0.1.0-py3-none-any.whl` (wheel)

## Verify the Package

```bash
# Check the package
uv run twine check dist/*

# Verify package contents
tar -tzf dist/airlog-0.1.0.tar.gz | head -20
unzip -l dist/airlog-0.1.0-py3-none-any.whl
```

Ensure:
- ✓ Examples are NOT included in the wheel
- ✓ Tests are NOT included in the wheel
- ✓ Source code is in `airlog/` directory
- ✓ README.md and LICENSE are included

## Test Installation Locally

```bash
# Create a fresh virtual environment
uv venv test-env
source test-env/bin/activate

# Install from local wheel
pip install dist/airlog-0.1.0-py3-none-any.whl

# Test import
python -c "from airlog import LoguruAuditStream, Principal; print('✓ Import successful')"

# Deactivate and clean up
deactivate
rm -rf test-env
```

## Publish to TestPyPI (Recommended First)

```bash
# Upload to TestPyPI
uv run twine upload --repository testpypi dist/*

# Enter your TestPyPI API token when prompted
```

Then test installation from TestPyPI:

```bash
pip install --index-url https://test.pypi.org/simple/ --no-deps airlog
```

## Publish to Production PyPI

Once you've verified everything works on TestPyPI:

```bash
# Upload to PyPI
uv run twine upload dist/*

# Enter your PyPI API token when prompted
```

## Using API Tokens

Instead of entering tokens interactively, you can configure them in `~/.pypirc`:

```ini
[distutils]
index-servers =
    pypi
    testpypi

[pypi]
username = __token__
password = pypi-AgEIcHlwaS5vcmcC...

[testpypi]
repository = https://test.pypi.org/legacy/
username = __token__
password = pypi-AgENdGVzdC5weXBpLm9yZwI...
```

**Important:** Keep this file secure (`chmod 600 ~/.pypirc`)

## GitHub Actions (Optional)

For automated publishing via GitHub Actions, see `.github/workflows/publish.yml` (if available).

Store PyPI token as a GitHub secret:
1. Go to repository Settings → Secrets → Actions
2. Add secret named `PYPI_API_TOKEN`
3. Paste your PyPI API token

## Version Management

Before publishing a new version:

1. Update version in `pyproject.toml`:
   ```toml
   version = "0.2.0"
   ```

2. Update CHANGELOG (if available)

3. Create a git tag:
   ```bash
   git tag -a v0.2.0 -m "Release version 0.2.0"
   git push origin v0.2.0
   ```

4. Build and publish following the steps above

## Checklist

Before publishing to PyPI, verify:

- [ ] Version number is correct in `pyproject.toml`
- [ ] README.md is up to date
- [ ] LICENSE file is present
- [ ] All tests pass (`uv run pytest`)
- [ ] Linting passes (`uv run ruff check`)
- [ ] Examples are excluded from package
- [ ] Package builds without errors
- [ ] Package can be installed and imported
- [ ] Tested on TestPyPI first
- [ ] Git tag created for the release

## Troubleshooting

**Problem:** Files missing from package

**Solution:** Check `[tool.hatch.build.targets.wheel]` in `pyproject.toml`

---

**Problem:** Package too large

**Solution:** Ensure examples and tests are excluded via `[tool.hatch.build.targets.sdist]`

---

**Problem:** Import errors after installation

**Solution:** Verify `packages` configuration points to `src/airlog`

---

**Problem:** Authentication failed

**Solution:** Use API tokens, not passwords. Ensure token has upload permissions.
