#!/usr/bin/env python3
"""
Extract and run Python code blocks from README.md and docs/*.md.
Only runs blocks fenced with ```python (runnable examples).
Usage: from repo root, run: python scripts/run_doc_examples.py
"""
import re
import subprocess
import sys
from pathlib import Path


def find_repo_root() -> Path:
    script_dir = Path(__file__).resolve().parent
    return script_dir.parent


def extract_python_blocks(content: str) -> list[tuple[int, str]]:
    """Extract (start_line, code) for each ```python ... ``` block (runnable examples only)."""
    blocks = []
    # Match 3 or 4 backticks + "python", then content until same fence (only runnable blocks)
    pattern = re.compile(
        r"^(`{3,4})python\s*\n(.*?)^\1",
        re.MULTILINE | re.DOTALL,
    )
    for m in pattern.finditer(content):
        code = m.group(2).strip()
        if not code or "pip install" in code.split("\n")[0]:
            continue
        if "skip in doc examples" in code or "not runnable" in code:
            continue
        # Remove doc-style ">>" lines (e.g. ">> returns ...")
        lines = []
        for line in code.split("\n"):
            if line.strip().startswith(">>"):
                continue
            lines.append(line)
        code = "\n".join(lines).strip()
        if len(code) < 10:
            continue
        start = content[: m.start()].count("\n") + 1
        blocks.append((start, code))
    return blocks


def run_block(source: str, block_num: int, code: str, timeout: int = 30):
    """Run one code block in a subprocess. Return (success, stdout, stderr)."""
    try:
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            timeout=timeout,
            cwd=find_repo_root(),
        )
        return (result.returncode == 0, result.stdout, result.stderr)
    except subprocess.TimeoutExpired:
        return (False, b"", b"(timeout)")
    except Exception as e:
        return (False, b"", str(e).encode("utf-8"))


def main() -> int:
    repo_root = find_repo_root()
    sources = [repo_root / "README.md"]
    docs_dir = repo_root / "docs"
    if docs_dir.is_dir():
        sources.extend(sorted(docs_dir.glob("*.md")))

    failed = 0
    for path in sources:
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        blocks = extract_python_blocks(text)
        for i, (line_no, code) in enumerate(blocks):
            label = f"{path.name}:{line_no}"
            ok, out, err = run_block(str(path), i, code)
            if ok:
                print(f"OK: {label}")
            else:
                print(f"FAIL: {label}", file=sys.stderr)
                if err:
                    sys.stderr.buffer.write(err)
                    if not err.endswith(b"\n"):
                        sys.stderr.buffer.write(b"\n")
                if out:
                    sys.stderr.buffer.write(b"--- stdout ---\n")
                    sys.stderr.buffer.write(out)
                    if not out.endswith(b"\n"):
                        sys.stderr.buffer.write(b"\n")
                failed = 1

    if failed:
        return 1
    print("All doc examples passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
