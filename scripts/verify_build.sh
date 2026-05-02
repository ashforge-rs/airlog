#!/usr/bin/env bash
# Build verification script for PyPI publishing
# Run this before publishing to ensure the package is correctly configured

set -e

echo "=== Airlog PyPI Build Verification ==="
echo

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Clean previous builds
echo "🧹 Cleaning previous builds..."
rm -rf dist/ build/ src/*.egg-info
echo

# Build the package
echo "📦 Building package..."
uv run python -m build
echo

# Check build artifacts exist
if [ ! -f dist/airlog-0.1.0.tar.gz ] || [ ! -f dist/airlog-0.1.0-py3-none-any.whl ]; then
    echo -e "${RED}❌ Build artifacts not found${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Build artifacts created${NC}"
echo

# Run twine check
echo "🔍 Running twine check..."
uv run twine check dist/*
echo -e "${GREEN}✓ Twine check passed${NC}"
echo

# Verify wheel contents
echo "📋 Checking wheel contents..."
echo "Wheel contents:"
unzip -l dist/airlog-0.1.0-py3-none-any.whl | head -30
echo

# Check that examples are NOT in the wheel
if unzip -l dist/airlog-0.1.0-py3-none-any.whl | grep -q "examples/"; then
    echo -e "${RED}❌ ERROR: examples/ found in wheel!${NC}"
    exit 1
else
    echo -e "${GREEN}✓ examples/ correctly excluded from wheel${NC}"
fi

# Check that tests are NOT in the wheel
if unzip -l dist/airlog-0.1.0-py3-none-any.whl | grep -q "tests/"; then
    echo -e "${RED}❌ ERROR: tests/ found in wheel!${NC}"
    exit 1
else
    echo -e "${GREEN}✓ tests/ correctly excluded from wheel${NC}"
fi
echo

# Verify source distribution contents
echo "📋 Checking source distribution contents..."
echo "Source distribution contents:"
tar -tzf dist/airlog-0.1.0.tar.gz | head -30
echo

# Check README is included
if tar -tzf dist/airlog-0.1.0.tar.gz | grep -q "README.md"; then
    echo -e "${GREEN}✓ README.md included in sdist${NC}"
else
    echo -e "${RED}❌ ERROR: README.md not found in sdist!${NC}"
    exit 1
fi

# Check LICENSE is included
if tar -tzf dist/airlog-0.1.0.tar.gz | grep -q "LICENSE"; then
    echo -e "${GREEN}✓ LICENSE included in sdist${NC}"
else
    echo -e "${YELLOW}⚠ WARNING: LICENSE not found in sdist${NC}"
fi
echo

# Test installation in a temporary environment
echo "🧪 Testing installation in temporary environment..."
TEMP_VENV=$(mktemp -d)
uv venv "$TEMP_VENV"
source "$TEMP_VENV/bin/activate"

pip install -q dist/airlog-0.1.0-py3-none-any.whl

# Test import
if python -c "from airlog import LoguruAuditStream, Principal; print('Import successful')" &> /dev/null; then
    echo -e "${GREEN}✓ Package imports successfully${NC}"
else
    echo -e "${RED}❌ ERROR: Import failed!${NC}"
    deactivate
    rm -rf "$TEMP_VENV"
    exit 1
fi

# Test basic functionality
python -c "
from airlog import LoguruAuditStream, Principal
stream = LoguruAuditStream()
event = stream.record('test', principal=Principal(subject='test', auth_method='test'), resource='test')
assert event.verify()
print('Basic functionality test passed')
" &> /dev/null

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Basic functionality test passed${NC}"
else
    echo -e "${RED}❌ ERROR: Functionality test failed!${NC}"
    deactivate
    rm -rf "$TEMP_VENV"
    exit 1
fi

deactivate
rm -rf "$TEMP_VENV"
echo

# Summary
echo "=== Summary ==="
echo -e "${GREEN}✓ Package built successfully${NC}"
echo -e "${GREEN}✓ All verification checks passed${NC}"
echo
echo "Build artifacts:"
ls -lh dist/
echo
echo "Next steps:"
echo "  1. Review the build artifacts above"
echo "  2. Test on TestPyPI: uv run twine upload --repository testpypi dist/*"
echo "  3. Verify on TestPyPI, then publish to PyPI: uv run twine upload dist/*"
echo
echo "See PUBLISHING.md for detailed instructions."
