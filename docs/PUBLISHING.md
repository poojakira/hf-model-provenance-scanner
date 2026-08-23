# Publishing to PyPI

## One-Time Setup (Required)

1. Create an account at https://pypi.org/account/register/
2. Go to https://pypi.org/manage/account/publishing/
3. Add a new pending publisher:
   - PyPI project name: `hf-model-provenance-scanner`
   - Owner: `poojakira`
   - Repository: `hf-model-provenance-scanner`
   - Workflow name: `publish.yml`
   - Environment name: `pypi`
4. Repeat for TestPyPI at https://test.pypi.org/manage/account/publishing/ with environment `testpypi`
5. Create GitHub environments:
   - Go to repo Settings > Environments
   - Create `pypi` environment
   - Create `testpypi` environment

## Publishing a Release

Once Trusted Publisher is configured:

```bash
# Ensure all tests pass
pytest --tb=short -q

# Ensure lint passes
ruff check scanner tests
ruff format --check scanner tests

# Create and push tag
git tag -a v1.0.0 -m "v1.0.0: description"
git push origin v1.0.0

# Create GitHub release (triggers publish workflow)
gh release create v1.0.0 --title "v1.0.0" --generate-notes
```

The `publish.yml` workflow will:
1. Build sdist + wheel
2. Verify with twine check
3. Publish to TestPyPI first
4. Then publish to PyPI

## Manual Publish (Alternative)

If Trusted Publisher isn't set up, use an API token:

```bash
# Get token from https://pypi.org/manage/account/token/
export TWINE_PASSWORD=pypi-...

# Build
python -m build

# Verify
twine check dist/*

# Upload
twine upload dist/* --username __token__
```

## Verify Publication

```bash
pip install hf-model-provenance-scanner==1.0.0
hf-scanner --version
```
