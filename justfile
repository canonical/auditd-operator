[private]
default:
  @just --list

# Run fix, static, and unittest recipes
check: fix static unittest

# Format the Python code
fix:
  uv run codespell -w .
  uv run ruff format .
  uv run ruff check --fix --exit-zero --silent .

# Run static code analysis
static:
  uv run codespell .
  uv run ruff format --diff .
  uv run ruff check --no-fix .
  uv run mypy --install-types --non-interactive .

# Run unit tests
unittest:
  uv run pytest ./tests/unit/ \
    -v \
    --cov \
    --cov-report=term-missing \
    --cov-report=html \
    --cov-report=xml
