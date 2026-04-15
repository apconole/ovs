#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2026 Stephen Hemminger
# Copyright(c) 2026 Aaron Conole

"""
Analyze OVS patches using AI providers.

Supported providers: openai-api, anthropic-ai, ollama api
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import date
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Iterator, NoReturn
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

# Output formats
OUTPUT_FORMATS = ["text", "markdown", "html", "json"]

# Large file handling modes
LARGE_FILE_MODES = ["error", "truncate", "chunk", "commits-only", "summary"]

# Default token limits by provider (leave room for system prompt and response)
PROVIDER_INPUT_LIMITS = {
    "anthropic": 180000,  # 200K context, reserve for system/response
    "openai": 900000,  # GPT-4.1 has 1M context
    "xai": 1800000,  # Grok 4.1 Fast has 2M context
    "google": 900000,  # Gemini 3 Flash has 1M context
}


@dataclass
class TokenUsage:
    """Accumulated token usage across API calls."""

    input_tokens: int = 0
    output_tokens: int = 0
    cache_creation_tokens: int = 0
    cache_read_tokens: int = 0
    api_calls: int = 0

    def add(self, other: "TokenUsage") -> None:
        """Accumulate usage from another TokenUsage."""
        self.input_tokens += other.input_tokens
        self.output_tokens += other.output_tokens
        self.cache_creation_tokens += other.cache_creation_tokens
        self.cache_read_tokens += other.cache_read_tokens
        self.api_calls += other.api_calls


# Pricing per million tokens (USD) - update as prices change.
# Keys are (provider, model-prefix) tuples; first prefix match wins.
# "default" key is fallback for unknown models within a provider.
def format_token_summary(usage: TokenUsage, provider: str, model: str) -> str:
    """Format a token usage summary string."""
    lines = ["=== Token Usage Summary ==="]
    lines.append(f"API calls:     {usage.api_calls}")
    lines.append(f"Input tokens:  {usage.input_tokens:,}")
    lines.append(f"Output tokens: {usage.output_tokens:,}")
    if usage.cache_creation_tokens:
        lines.append(f"Cache write:   {usage.cache_creation_tokens:,}")
    if usage.cache_read_tokens:
        lines.append(f"Cache read:    {usage.cache_read_tokens:,}")
    total = usage.input_tokens + usage.output_tokens
    lines.append(f"Total tokens:  {total:,}")
    lines.append("=" * 27)
    return "\n".join(lines)


# Provider configurations
PROVIDERS = {
    "anthropic": {
        "name": "Claude",
        "endpoint": "https://api.anthropic.com/v1/messages",
        "default_model": "claude-sonnet-4-5-20250929",
        "env_var": "ANTHROPIC_API_KEY",
    },
    "openai": {
        "name": "ChatGPT",
        "endpoint": "https://api.openai.com/v1/chat/completions",
        "default_model": "gpt-4.1",
        "env_var": "OPENAI_API_KEY",
    },
    "xai": {
        "name": "Grok",
        "endpoint": "https://api.x.ai/v1/chat/completions",
        "default_model": "grok-4-1-fast-non-reasoning",
        "env_var": "XAI_API_KEY",
    },
    "google": {
        "name": "Gemini",
        "endpoint": "https://generativelanguage.googleapis.com/v1beta/models",
        "default_model": "gemini-3-flash-preview",
        "env_var": "GOOGLE_API_KEY",
    },
}

# Maximum characters returned by a single tool call.
MAX_TOOL_OUTPUT_CHARS = 20_000
# Maximum tool-call/response rounds before forcing a final answer.
MAX_TOOL_ROUNDS = 10

# Tool definitions (provider-agnostic; converted per-provider below).
REPO_TOOLS = [
    {
        "name": "read_file",
        "description": (
            "Read the contents of a file from the OVS repository. "
            "Use this to retrieve the current source of a file referenced in "
            "the patch, look up a function or type definition, or examine the "
            "surrounding context of a change."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description":
                        "Path to the file, relative to the repository root.",
                },
                "start_line": {
                    "type": "integer",
                    "description": (
                        "First line to return (1-indexed, inclusive). "
                        "Omit to read from the beginning of the file."
                    ),
                },
                "end_line": {
                    "type": "integer",
                    "description": (
                        "Last line to return (1-indexed, inclusive). "
                        "Omit to read to the end of the file."
                    ),
                },
            },
            "required": ["path"],
        },
    },
    {
        "name": "grep_codebase",
        "description": (
            "Search the OVS codebase for a pattern using grep. "
            "Use this to locate function definitions, usages of a symbol, "
            "struct layouts, macro definitions, or any text pattern across "
            "source files."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Regular expression to search for.",
                },
                "path": {
                    "type": "string",
                    "description": (
                        "File or directory to search, relative to the "
                        "repository root. Defaults to the whole repository."
                    ),
                },
                "include": {
                    "type": "string",
                    "description": (
                        "Glob pattern to restrict which files are searched, "
                        "e.g. '*.c' or '*.h'."
                    ),
                },
                "context_lines": {
                    "type": "integer",
                    "description": (
                        "Lines of context to show around each match (grep -C)."
                        " Defaults to 0."
                    ),
                },
                "ignore_case": {
                    "type": "boolean",
                    "description":
                        "Case-insensitive match. Defaults to false.",
                },
            },
            "required": ["pattern"],
        },
    },
]


def _tools_for_anthropic(tools: list[dict]) -> list[dict]:
    """Convert generic tool defs to Anthropic tool format."""
    return [
        {
            "name": t["name"],
            "description": t["description"],
            "input_schema": t["parameters"],
        }
        for t in tools
    ]


def _tools_for_openai(tools: list[dict]) -> list[dict]:
    """Convert generic tool defs to OpenAI function-calling format."""
    return [
        {
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t["description"],
                "parameters": t["parameters"],
            },
        }
        for t in tools
    ]


def get_repo_dir(repo_dir: str | None) -> Path:
    """Return the repository root as an absolute Path."""
    if repo_dir:
        return Path(repo_dir).resolve()
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=True,
        )
        return Path(result.stdout.strip()).resolve()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return Path(".").resolve()


def _safe_path(repo_root: Path, user_path: str) -> Path | None:
    """Resolve user_path inside repo_root; return None if it would escape."""
    try:
        resolved = (repo_root / user_path).resolve()
        resolved.relative_to(repo_root)   # raises ValueError if outside
        return resolved
    except (ValueError, OSError):
        return None


def _tool_read_file(tool_input: dict, repo_root: Path) -> str:
    """Implement the read_file tool."""
    path_str = tool_input.get("path", "")
    safe = _safe_path(repo_root, path_str)
    if safe is None:
        return f"Error: path '{path_str}' is outside the repository"
    if not safe.exists():
        return f"Error: file not found: {path_str}"
    if not safe.is_file():
        return f"Error: not a regular file: {path_str}"

    try:
        lines = safe.read_text(errors="replace").splitlines()
    except OSError as exc:
        return f"Error reading file: {exc}"

    start = tool_input.get("start_line")
    end = tool_input.get("end_line")

    if start is not None or end is not None:
        start_idx = max(0, (start or 1) - 1)
        end_idx = end or len(lines)
        lines = lines[start_idx:end_idx]
        first_lineno = start_idx + 1
    else:
        first_lineno = 1

    numbered = "\n".join(
        f"{first_lineno + i:5d}  {line}" for i, line in enumerate(lines)
    )
    result = f"=== {path_str} ===\n{numbered}"

    if len(result) > MAX_TOOL_OUTPUT_CHARS:
        result = (
            result[:MAX_TOOL_OUTPUT_CHARS]
            + f"\n[... truncated at {MAX_TOOL_OUTPUT_CHARS} characters ...]"
        )
    return result


def _tool_grep(tool_input: dict, repo_root: Path) -> str:
    """Implement the grep_codebase tool."""
    pattern = tool_input.get("pattern", "")
    path_str = tool_input.get("path", ".")
    include = tool_input.get("include")
    context = int(tool_input.get("context_lines", 0))
    ignore_case = bool(tool_input.get("ignore_case", False))

    safe = _safe_path(repo_root, path_str)
    if safe is None:
        return f"Error: path '{path_str}' is outside the repository"
    if not safe.exists():
        return f"Error: path not found: {path_str}"

    cmd = ["grep", "-rn", "--color=never"]
    if ignore_case:
        cmd.append("-i")
    if context > 0:
        cmd.extend(["-C", str(context)])
    if include:
        cmd.extend(["--include", include])
    cmd.extend(["--", pattern, str(safe)])

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        # grep exits 1 on no matches — not an error
        output = proc.stdout if proc.stdout else "(no matches found)"
    except subprocess.TimeoutExpired:
        return "Error: grep timed out after 30 seconds"
    except FileNotFoundError:
        return "Error: grep not found in PATH"

    if len(output) > MAX_TOOL_OUTPUT_CHARS:
        output = (
            output[:MAX_TOOL_OUTPUT_CHARS]
            + f"\n[... truncated at {MAX_TOOL_OUTPUT_CHARS} characters ...]"
        )
    return output


def execute_tool(name: str, tool_input: dict, repo_root: Path) -> str:
    """Dispatch a tool call by name and return its string output."""
    if name == "read_file":
        return _tool_read_file(tool_input, repo_root)
    if name == "grep_codebase":
        return _tool_grep(tool_input, repo_root)
    return f"Error: unknown tool '{name}'"


# Known agentic tool config sources.
# Each entry maps a provider name to a list of JSON key paths to try.
# Key paths are lists of dict keys to traverse in the config file.
AGENT_CONFIG_SOURCES = [
    {
        "name": "Claude Code",
        "path": "~/.claude/settings.json",
        "provider_keys": {
            "anthropic": [["env", "ANTHROPIC_API_KEY"]],
        },
    },
    {
        "name": "OpenCode",
        "path": "~/.config/opencode/config.json",
        "provider_keys": {
            "anthropic": [["providers", "anthropic", "apiKey"],
                          ["anthropic", "apiKey"]],
            "openai": [["providers", "openai", "apiKey"],
                       ["openai", "apiKey"]],
            "google": [["providers", "google", "apiKey"],
                       ["google", "apiKey"]],
            "xai": [["providers", "xai", "apiKey"],
                    ["xai", "apiKey"]],
        },
    },
    {
        "name": "Aider",
        "path": "~/.aider.conf.yml",
        "format": "yaml-kv",   # simple "key: value" scan, no pyyaml needed
        "provider_keys": {
            "anthropic": [["anthropic-api-key"]],
            "openai": [["openai-api-key"]],
        },
    },
]

SYSTEM_PROMPT_BASE = """\
You are an expert openvswitch code reviewer. Analyze patches for compliance \
with Open vSwitch coding standards and contribution guidelines. Provide clear,
actionable feedback organized by severity (Error, Warning) as defined:

- Errors are issues with the patches such as making too many logical changes, \
  or making changes that might break the underlying functionality of the \
  system.

- Warnings are issues with the patches that don't rise to the level of an \
  outright error, such as missing error handling or possible race conditions.

If a patch mentions it is fixing an issue, please ensure that:

- Only bug fixes are included, no new features
- No new APIs (experimental or stable) are introduced
- ABIs must remain unchanged
- Backported fixes should reference the original commit with Fixes: tag
- Copyright years should reflect when the code was originally written
- Be conservative: flag changes that aren't clearly bug fixes"""

TOOL_USE_GUIDANCE = """

## Repository Lookup Tools

You have access to two tools for inspecting the OVS repository:

- **read_file** — read a file (or a range of lines) from the repository tree.
- **grep_codebase** — search for regexp pattern across source files.

The repository reflects the state *before* the patch is applied.  Use these
tools to see the original version of modified code, look up type and function
definitions, or check how a symbol is used elsewhere.

### When to use a tool

Call a tool only when the patch context alone is insufficient to make a
confident judgment.  Good trigger conditions:

- You need to see the **full body** of a function that is only partially shown
  in the diff — for example, to trace all error-return paths for a resource
  that was allocated earlier in the function.
- A new caller passes arguments to a function whose **contract or locking
  requirements** you need to verify (look up its definition or header comment).
- A type, macro, or constant appears in the patch but is not defined there
  and its **semantics affect correctness** (e.g. whether a flag value means
  "locked" or "unlocked", whether a destroy function accepts NULL).
- You want to confirm whether a **locking discipline or naming convention** is
  used consistently elsewhere before flagging an inconsistency.

### When NOT to use a tool

Skip the tool call when:

- The answer is already visible in the patch diff itself.
- You are performing a style check that depends only on the changed lines.
- You would be looking up a well-known standard library or POSIX function.
- The lookup is speculative rather than tied to a specific potential finding.

### Efficiency

Each tool call costs tokens and latency.  Be targeted:

- Pass **start_line** and **end_line** to read_file to fetch only the
  relevant portion of a large file rather than reading it in full.
- Use a specific grep pattern and restrict the search with **include** when
  you know the file type (e.g. `include='*.h'` to find a declaration).
- Aim for **at most 2–3 tool calls** per patch.  If the context you have
  already gathered is sufficient to write your review, write it."""

FORMAT_INSTRUCTIONS = {
    "text": """Provide your review in plain text format.""",
    "markdown": """Provide your review in Markdown format with:
- Headers (##) for each severity level (Errors, Warnings, Info)
- Bullet points for individual issues
- Code blocks (```) for code references
- Bold (**) for emphasis on key points""",
    "html": """Provide your review in HTML format with:
- <h2> tags for each severity level (Errors, Warnings, Info)
- <ul>/<li> for individual issues
- <pre><code> for code references
- <strong> for emphasis on key points
- Use appropriate semantic HTML tags
- Do NOT include <html>, <head>, or <body> tags - just the content""",
    "json": """Provide your review in JSON format with this structure:
{
  "summary": "Brief one-line summary of the review",
  "errors": [
    {"issue": "description", "location": "file:line", "suggestion": "fix"}
  ],
  "warnings": [
    {"issue": "description", "location": "file:line", "suggestion": "fix"}
  ],
  "info": [
    {"issue": "description", "location": "file:line", "suggestion": "fix"}
  ],
  "passed_checks": ["list of checks that passed"],
  "overall_status": "PASS|WARN|FAIL"
}
Output ONLY valid JSON, no markdown code fences or other text.""",
}

USER_PROMPT = """Please review the following ovs patch file '{patch_name}' \
against the AGENTS.md guidelines. Focus on:

1. Correctness bugs (resource leaks, use-after-free, race conditions, etc.)
2. C coding style (forbidden words, implicit comparisons, unnecessary patterns)
3. API and documentation requirements
4. Any other guideline violations

Note: spelling mistakes, compilation, and basic unit test coverage are
handled by additional CI and should NOT be flagged here.

{format_instruction}

--- PATCH CONTENT ---
"""


def error(msg: str) -> NoReturn:
    """Print error message and exit."""
    print(f"Error: {msg}", file=sys.stderr)
    sys.exit(1)


# Exit codes for review results
EXIT_CLEAN = 0
EXIT_WARNINGS = 2
EXIT_ERRORS = 3


def classify_review(review_text: str, output_format: str) -> int:
    """Classify review result and return appropriate exit code.

    Returns:
        0 - clean (no errors or warnings)
        2 - warnings found (no errors)
        3 - errors found
    """
    has_errors = False
    has_warnings = False

    if output_format == "json":
        try:
            data = json.loads(review_text)
            if data.get("errors"):
                has_errors = True
            if data.get("warnings"):
                has_warnings = True
            status = data.get("overall_status", "").upper()
            if status == "FAIL":
                has_errors = True
            elif status == "WARN":
                has_warnings = True
        except (json.JSONDecodeError, AttributeError):
            pass  # Fall through to text scanning

    if not has_errors and not has_warnings:
        # Scan review text for severity indicators.
        # Match section headers and inline markers across text/markdown/html.
        for line in review_text.splitlines():
            stripped = line.strip().lower()
            # Skip quoted patch context lines
            if stripped.startswith(">") or stripped.startswith("diff --git"):
                continue
            if re.match(r"^(#{1,3}\s+)?(\*{0,2})error", stripped) or re.match(
                r"^<h[1-3]>\s*error", stripped
            ):
                has_errors = True
            elif re.match(r"^(#{1,3}\s+)?(\*{0,2})warning",
                          stripped) or re.match(r"^<h[1-3]>\s*warning",
                                                stripped):
                has_warnings = True

    if has_errors:
        return EXIT_ERRORS
    if has_warnings:
        return EXIT_WARNINGS
    return EXIT_CLEAN


def get_git_config(key: str) -> str | None:
    """Get a value from git config."""
    try:
        result = subprocess.run(
            ["git", "config", "--get", key],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def _get_nested(obj: Any, keys: list[str]) -> str | None:
    """Walk a nested dict/list by key path; return str value or None."""
    for key in keys:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(key)
        if obj is None:
            return None
    return obj if isinstance(obj, str) else None


def find_api_key_from_agent_configs(provider: str, verbose: bool = False
                                    ) -> tuple[str | None, str | None]:
    """Search known agentic tool config files for an API key.

    Returns (api_key, source_description) or (None, None).
    """
    for source in AGENT_CONFIG_SOURCES:
        config_path = Path(source["path"]).expanduser()
        if not config_path.exists():
            continue

        provider_keys = source.get("provider_keys", {})
        if provider not in provider_keys:
            continue

        fmt = source.get("format", "json")

        try:
            if fmt == "json":
                data = json.loads(config_path.read_text())
                for key_path in provider_keys[provider]:
                    value = _get_nested(data, key_path)
                    if value:
                        if verbose:
                            print(f"API key found in {source['name']} "
                                  f"({config_path})",
                                  file=sys.stderr)
                        return value, source["name"]
            elif fmt == "yaml-kv":
                # Handle simple "key: value" YAML
                for key_path in provider_keys[provider]:
                    needle = key_path[0] + ":"   # e.g. "anthropic-api-key:"
                    for line in config_path.read_text().splitlines():
                        stripped = line.strip()
                        if stripped.lower().startswith(needle.lower()):
                            value = stripped[len(needle):].strip().strip('"\'')
                            if value:
                                if verbose:
                                    print(f"API key found in {source['name']} "
                                          f"({config_path})",
                                          file=sys.stderr)
                                return value, source["name"]
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            continue  # Unreadable config is not an error

    return None, None


CHARS_PER_TOKEN = 4  # According to Claude, ~4 chars / token


def estimate_tokens(text: str) -> int:
    """Estimate token count from text length."""
    return int(len(text) / CHARS_PER_TOKEN)


def split_mbox_patches(content: str) -> list[str]:
    """Split an mbox file into individual patches."""
    patches = []
    current_patch = []
    in_patch = False

    for line in content.split("\n"):
        # Detect start of new message in mbox format
        # git-format-patch: "From <40-char-hex> Mon Sep 17 00:00:00 2001"
        # general mbox: "From <addr> <day-of-week> ..."
        if line.startswith("From ") and (
            re.match(r"^From [0-9a-f]{40} ", line)
            or " Mon " in line
            or " Tue " in line
            or " Wed " in line
            or " Thu " in line
            or " Fri " in line
            or " Sat " in line
            or " Sun " in line
        ):
            if current_patch:
                patches.append("\n".join(current_patch))
            current_patch = [line]
            in_patch = True
        elif in_patch:
            current_patch.append(line)

    # Don't forget the last patch
    if current_patch:
        patches.append("\n".join(current_patch))

    return patches if patches else [content]


def extract_commit_messages(content: str) -> str:
    """Extract only commit messages from patch content."""
    patches = split_mbox_patches(content)
    messages = []

    for patch in patches:
        lines = patch.split("\n")
        msg_lines = []
        in_headers = True
        in_body = False
        found_subject = False

        for line in lines:
            # Collect headers we care about
            if in_headers:
                if line.startswith("Subject:"):
                    msg_lines.append(line)
                    found_subject = True
                elif line.startswith(("From:", "Date:")):
                    msg_lines.append(line)
                elif line.startswith((" ", "\t")) and found_subject:
                    # Subject continuation
                    msg_lines.append(line)
                elif line == "":
                    if found_subject:
                        in_headers = False
                        in_body = True
                        msg_lines.append("")
            elif in_body:
                # Stop at the diffstat separator or diff
                if line.rstrip() == "---":
                    break
                if line.startswith("diff --git"):
                    break
                msg_lines.append(line)

        if msg_lines:
            messages.append("\n".join(msg_lines))

    return "\n\n---\n\n".join(messages)


def truncate_content(content: str, max_tokens: float) -> tuple[str, bool]:
    """Truncate content to fit within token limit."""
    max_chars = int(max_tokens * CHARS_PER_TOKEN)

    if len(content) <= max_chars:
        return content, False

    # Try to truncate at a reasonable boundary
    truncated = content[:max_chars]

    # Find last complete diff hunk or patch boundary
    last_diff = truncated.rfind("\ndiff --git")
    last_patch = truncated.rfind("\nFrom ")

    if last_diff > max_chars * 0.5:
        truncated = truncated[:last_diff]
    elif last_patch > max_chars * 0.5:
        truncated = truncated[:last_patch]

    truncated += "\n\n[... Content truncated due to size limits ...]\n"
    return truncated, True


def chunk_content(content: str,
                  max_tokens: int) -> Iterator[tuple[str, int, int]]:
    """Split content into chunks that fit within token limit.

    Yields tuples of (chunk_content, chunk_number, total_chunks).
    """
    patches = split_mbox_patches(content)

    if len(patches) == 1:
        # Single large patch - split by diff sections
        yield from chunk_single_patch(content, max_tokens)
        return

    # Multiple patches - group them to fit within limits
    chunks = []
    current_chunk = []
    current_size = 0
    max_chars = int(max_tokens * CHARS_PER_TOKEN * 0.9)  # 90% to leave margin

    for patch in patches:
        patch_size = len(patch)
        if current_size + patch_size > max_chars and current_chunk:
            chunks.append("\n".join(current_chunk))
            current_chunk = []
            current_size = 0

        if patch_size > max_chars:
            # Single patch too large, truncate it
            if current_chunk:
                chunks.append("\n".join(current_chunk))
                current_chunk = []
                current_size = 0
            truncated, _ = truncate_content(patch, max_tokens * 0.9)
            chunks.append(truncated)
        else:
            current_chunk.append(patch)
            current_size += patch_size

    if current_chunk:
        chunks.append("\n".join(current_chunk))

    total = len(chunks)
    for i, chunk in enumerate(chunks, 1):
        yield chunk, i, total


def chunk_single_patch(content: str,
                       max_tokens: int) -> Iterator[tuple[str, int, int]]:
    """Split a single large patch by diff sections."""
    max_chars = int(max_tokens * CHARS_PER_TOKEN * 0.9)

    # Extract header (everything before first diff)
    first_diff = content.find("\ndiff --git")
    if first_diff == -1:
        # No diff sections, just truncate
        truncated, _ = truncate_content(content, max_tokens * 0.9)
        yield truncated, 1, 1
        return

    header = content[: first_diff + 1]
    diff_content = content[first_diff + 1 :]

    # Split by diff sections
    diffs = []
    current_diff = []
    for line in diff_content.split("\n"):
        if line.startswith("diff --git") and current_diff:
            diffs.append("\n".join(current_diff))
            current_diff = []
        current_diff.append(line)
    if current_diff:
        diffs.append("\n".join(current_diff))

    # Group diffs into chunks
    chunks = []
    current_chunk_diffs = []
    current_size = len(header)

    for diff in diffs:
        diff_size = len(diff)
        if current_size + diff_size > max_chars and current_chunk_diffs:
            chunks.append(header + "\n".join(current_chunk_diffs))
            current_chunk_diffs = []
            current_size = len(header)

        if diff_size + len(header) > max_chars:
            # Single diff too large
            if current_chunk_diffs:
                chunks.append(header + "\n".join(current_chunk_diffs))
                current_chunk_diffs = []
            truncated_diff = diff[: max_chars - len(header) - 100]
            truncated_diff += "\n[... diff truncated ...]\n"
            chunks.append(header + truncated_diff)
            current_size = len(header)
        else:
            current_chunk_diffs.append(diff)
            current_size += diff_size

    if current_chunk_diffs:
        chunks.append(header + "\n".join(current_chunk_diffs))

    total = len(chunks)
    for i, chunk in enumerate(chunks, 1):
        yield chunk, i, total


def get_summary_prompt() -> str:
    """Get prompt modifications for summary mode."""
    return """
NOTE: This is a LARGE patch series. Provide a HIGH-LEVEL summary review only:
- Focus on overall architecture and design concerns
- Check commit message formatting across the series
- Identify any obvious policy violations
- Do NOT attempt detailed line-by-line code review
- Summarize the scope and purpose of the changes
"""


def format_combined_reviews(
    reviews: list[tuple[str, str]], output_format: str, patch_name: str
) -> str:
    """Combine multiple chunk/patch reviews into a single output."""
    if output_format == "json":
        combined = {
            "patch_file": patch_name,
            "sections": [
                {"label": label, "review": review} for label, review in reviews
            ],
        }
        return json.dumps(combined, indent=2)
    elif output_format == "html":
        sections = []
        for label, review in reviews:
            sections.append(f"<h2>{label}</h2>\n{review}")
        return "\n<hr>\n".join(sections)
    elif output_format == "markdown":
        sections = []
        for label, review in reviews:
            sections.append(f"## {label}\n\n{review}")
        return "\n\n---\n\n".join(sections)
    else:  # text
        sections = []
        for label, review in reviews:
            sections.append(f"=== {label} ===\n\n{review}")
        separator = "\n\n" + "=" * 60 + "\n\n"
        return separator.join(sections)


def build_system_prompt(review_date: str, tools_enabled: bool = False) -> str:
    """Build system prompt with date and optional tool-use guidance."""
    prompt = SYSTEM_PROMPT_BASE
    if tools_enabled:
        prompt += TOOL_USE_GUIDANCE
    prompt += f"\n\nCurrent date: {review_date}."
    return prompt


def build_anthropic_request(
    model: str,
    max_tokens: int,
    system_prompt: str,
    agents_content: str,
    patch_content: str,
    patch_name: str,
    output_format: str = "text",
) -> dict[str, Any]:
    """Build request payload for Anthropic API."""
    format_instruction = FORMAT_INSTRUCTIONS.get(output_format, "")
    user_prompt = USER_PROMPT.format(
        patch_name=patch_name, format_instruction=format_instruction
    )
    return {
        "model": model,
        "max_tokens": max_tokens,
        "system": [
            {"type": "text", "text": system_prompt},
            {
                "type": "text",
                "text": agents_content,
                "cache_control": {"type": "ephemeral"},
            },
        ],
        "messages": [
            {
                "role": "user",
                "content": user_prompt + patch_content,
            }
        ],
    }


def build_openai_request(
    model: str,
    max_tokens: int,
    system_prompt: str,
    agents_content: str,
    patch_content: str,
    patch_name: str,
    output_format: str = "text",
) -> dict[str, Any]:
    """Build request payload for OpenAI-compatible APIs."""
    format_instruction = FORMAT_INSTRUCTIONS.get(output_format, "")
    user_prompt = USER_PROMPT.format(
        patch_name=patch_name, format_instruction=format_instruction
    )
    return {
        "model": model,
        "max_tokens": max_tokens,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "system", "content": agents_content},
            {
                "role": "user",
                "content": user_prompt + patch_content,
            },
        ],
    }


def build_google_request(
    max_tokens: int,
    system_prompt: str,
    agents_content: str,
    patch_content: str,
    patch_name: str,
    output_format: str = "text",
) -> dict[str, Any]:
    """Build request payload for Google Gemini API."""
    format_instruction = FORMAT_INSTRUCTIONS.get(output_format, "")
    user_prompt = USER_PROMPT.format(
        patch_name=patch_name, format_instruction=format_instruction
    )
    return {
        "system_instruction": {
            "parts": [
                {"text": system_prompt},
                {"text": agents_content},
            ]
        },
        "contents": [
            {
                "role": "user",
                "parts": [{"text": user_prompt + patch_content}],
            },
        ],
        "generationConfig": {"maxOutputTokens": max_tokens},
    }


def _http_post(url: str, headers: dict[str, str], body: dict,
               timeout: int) -> dict:
    """POST a JSON body and return the parsed response dict."""
    data = json.dumps(body).encode("utf-8")
    req = Request(url, data=data, headers=headers, method="POST")
    try:
        with urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except HTTPError as e:
        error_body = e.read().decode("utf-8")
        try:
            error_data = json.loads(error_body)
            error(f"API error: {error_data.get('error', error_body)}")
        except json.JSONDecodeError:
            error(f"API error ({e.code}): {error_body}")
    except URLError as e:
        if isinstance(e.reason, TimeoutError):
            error(f"API request timed out after {timeout} seconds")
        error(f"Connection error: {e.reason}")
    except TimeoutError:
        error(f"API request timed out after {timeout} seconds")


def _extract_usage_anthropic(result: dict) -> TokenUsage:
    raw = result.get("usage", {})
    return TokenUsage(
        api_calls=1,
        input_tokens=raw.get("input_tokens", 0),
        output_tokens=raw.get("output_tokens", 0),
        cache_creation_tokens=raw.get("cache_creation_input_tokens", 0),
        cache_read_tokens=raw.get("cache_read_input_tokens", 0),
    )


def _extract_usage_openai(result: dict) -> TokenUsage:
    raw = result.get("usage", {})
    usage = TokenUsage(
        api_calls=1,
        input_tokens=raw.get("prompt_tokens", 0),
        output_tokens=raw.get("completion_tokens", 0),
    )
    cache_details = raw.get("prompt_tokens_details", {})
    if cache_details:
        usage.cache_read_tokens = cache_details.get("cached_tokens", 0)
    return usage


def _extract_usage_google(result: dict) -> TokenUsage:
    raw = result.get("usageMetadata", {})
    return TokenUsage(
        api_calls=1,
        input_tokens=raw.get("promptTokenCount", 0),
        output_tokens=raw.get("candidatesTokenCount", 0),
    )


def _log_usage(verbose: bool, usage: TokenUsage) -> None:
    """Print per-round token details when verbose."""
    if not verbose:
        return
    print("=== Token Usage ===", file=sys.stderr)
    print(f"Input tokens:  {usage.input_tokens:,}", file=sys.stderr)
    print(f"Output tokens: {usage.output_tokens:,}", file=sys.stderr)
    if usage.cache_creation_tokens:
        print(f"Cache creation: {usage.cache_creation_tokens:,}",
              file=sys.stderr)
    if usage.cache_read_tokens:
        print(f"Cache read:    {usage.cache_read_tokens:,}", file=sys.stderr)
    print("===================", file=sys.stderr)


def call_api(
    provider: str,
    api_key: str,
    model: str,
    max_tokens: int,
    system_prompt: str,
    agents_content: str,
    patch_content: str,
    patch_name: str,
    output_format: str = "text",
    verbose: bool = False,
    timeout: int = 300,
    tools_enabled: bool = False,
    repo_root: Path | None = None,
) -> tuple[str, TokenUsage]:
    """Make API request(s) to the specified provider, running tool calls as
    needed until the model produces a final text response.

    When tools_enabled is True (Anthropic and OpenAI providers), the model
    may call read_file or grep_codebase to inspect the repository before
    writing its review.  Tool results are fed back to the model in a loop
    (up to MAX_TOOL_ROUNDS rounds) before the final answer is returned.

    Returns (response_text, accumulated_token_usage).
    """
    config = PROVIDERS[provider]
    format_instruction = FORMAT_INSTRUCTIONS.get(output_format, "")
    user_prompt = USER_PROMPT.format(
        patch_name=patch_name, format_instruction=format_instruction
    )
    total_usage = TokenUsage()
    effective_root = repo_root or Path(".")

    # ------------------------------------------------------------------ Google
    # Google Gemini uses a different tool schema; skip tool support for now.
    if provider == "google":
        request_data = build_google_request(
            max_tokens, system_prompt, agents_content,
            patch_content, patch_name, output_format,
        )
        headers = {"Content-Type": "application/json"}
        url = f"{config['endpoint']}/{model}:generateContent?key={api_key}"
        result = _http_post(url, headers, request_data, timeout)
        total_usage.add(_extract_usage_google(result))
        if "error" in result:
            error(f"API error: {result['error'].get('message', result)}")
        candidates = result.get("candidates", [])
        if not candidates:
            error("No response from Gemini")
        parts = candidates[0].get("content", {}).get("parts", [])
        text = "".join(part.get("text", "") for part in parts)
        _log_usage(verbose, total_usage)
        return text, total_usage

    # --------------------------------------------------------------- Anthropic
    if provider == "anthropic":
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        }
        url = config["endpoint"]

        system = [
            {"type": "text", "text": system_prompt},
            {
                "type": "text",
                "text": agents_content,
                "cache_control": {"type": "ephemeral"},
            },
        ]
        messages: list[dict] = [
            {"role": "user", "content": user_prompt + patch_content}
        ]
        base_body: dict[str, Any] = {
            "model": model,
            "max_tokens": max_tokens,
            "system": system,
        }
        if tools_enabled:
            base_body["tools"] = _tools_for_anthropic(REPO_TOOLS)

        content_blocks: list[dict] = []
        for round_num in range(MAX_TOOL_ROUNDS):
            body = {**base_body, "messages": messages}
            result = _http_post(url, headers, body, timeout)
            total_usage.add(_extract_usage_anthropic(result))

            if "error" in result:
                error(f"API error: {result['error'].get('message', result)}")

            content_blocks = result.get("content", [])
            stop_reason = result.get("stop_reason", "")

            if stop_reason == "tool_use" and tools_enabled:
                # Append this assistant turn and execute every tool call.
                messages.append({"role": "assistant",
                                 "content": content_blocks})
                tool_results: list[dict] = []
                for block in content_blocks:
                    if block.get("type") != "tool_use":
                        continue
                    tool_name = block["name"]
                    tool_input = block.get("input", {})
                    if verbose:
                        print(
                            f"[tool call #{round_num + 1}] "
                            f"{tool_name}({json.dumps(tool_input)[:160]})",
                            file=sys.stderr,
                        )
                    output = execute_tool(tool_name, tool_input,
                                          effective_root)
                    if verbose:
                        preview = output[:300].replace("\n", "\\n")
                        print(f"[tool result] {preview}", file=sys.stderr)
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block["id"],
                        "content": output,
                    })
                messages.append({"role": "user", "content": tool_results})
                if round_num == MAX_TOOL_ROUNDS - 2:
                    # One round left — tell the model to finalise.
                    messages.append({
                        "role": "user",
                        "content": (
                            "You have used the maximum number of tool calls. "
                            "Please provide your complete final review now."
                        ),
                    })
            else:
                # end_turn or max_tokens — extract text and return.
                break

        text = "".join(
            b.get("text", "")
            for b in content_blocks
            if b.get("type") == "text"
        )
        _log_usage(verbose, total_usage)
        return text, total_usage

    # --------------------------------------------------------- OpenAI / xAI
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }
    url = config["endpoint"]

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "system", "content": agents_content},
        {"role": "user", "content": user_prompt + patch_content},
    ]
    base_body = {"model": model, "max_tokens": max_tokens}
    if tools_enabled:
        base_body["tools"] = _tools_for_openai(REPO_TOOLS)
        base_body["tool_choice"] = "auto"

    last_message: dict = {}
    for round_num in range(MAX_TOOL_ROUNDS):
        body = {**base_body, "messages": messages}
        result = _http_post(url, headers, body, timeout)
        total_usage.add(_extract_usage_openai(result))

        if "error" in result:
            error(f"API error: {result['error'].get('message', result)}")

        choices = result.get("choices", [])
        if not choices:
            error("No response from API")

        choice = choices[0]
        last_message = choice.get("message", {})
        finish_reason = choice.get("finish_reason", "")

        if finish_reason == "tool_calls" and tools_enabled:
            messages.append(last_message)
            for tc in last_message.get("tool_calls", []):
                fn = tc.get("function", {})
                tool_name = fn.get("name", "")
                try:
                    tool_input = json.loads(fn.get("arguments", "{}"))
                except json.JSONDecodeError:
                    tool_input = {}
                if verbose:
                    print(
                        f"[tool call #{round_num + 1}] "
                        f"{tool_name}({fn.get('arguments', '')[:160]})",
                        file=sys.stderr,
                    )
                output = execute_tool(tool_name, tool_input, effective_root)
                if verbose:
                    preview = output[:300].replace("\n", "\\n")
                    print(f"[tool result] {preview}", file=sys.stderr)
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc["id"],
                    "content": output,
                })
            if round_num == MAX_TOOL_ROUNDS - 2:
                messages.append({
                    "role": "user",
                    "content": (
                        "You have used the maximum number of tool calls. "
                        "Please provide your complete final review now."
                    ),
                })
        else:
            break

    text = last_message.get("content", "")
    _log_usage(verbose, total_usage)
    return text, total_usage


def get_last_message_id(patch_content: str) -> str | None:
    """Extract Message-ID from the last patch in an mbox."""
    msg_ids = re.findall(
        r"^Message-I[Dd]:\s*(.+)$", patch_content, re.MULTILINE | re.IGNORECASE
    )
    if msg_ids:
        msg_id = msg_ids[-1].strip()
        # Normalize: remove < > and add them back
        msg_id = msg_id.strip("<>")
        return f"<{msg_id}>"
    return None


def get_last_subject(patch_content: str) -> str | None:
    """Extract subject from the last patch in an mbox."""
    # Find all Subject lines with potential continuations
    subjects = []
    lines = patch_content.split("\n")
    i = 0
    while i < len(lines):
        if lines[i].lower().startswith("subject:"):
            subject = lines[i][8:].strip()
            i += 1
            # Handle continuation lines (RFC 2822 folding)
            while i < len(lines) and lines[i].startswith((" ", "\t")):
                subject += " " + lines[i].strip()
                i += 1
            subjects.append(subject)
        else:
            i += 1
    return subjects[-1] if subjects else None


def send_email(
    to_addrs: list[str],
    cc_addrs: list[str],
    from_addr: str,
    subject: str,
    in_reply_to: str | None,
    body: str,
    dry_run: bool = False,
) -> bool:
    """Send review email using git send-email, sendmail, or msmtp."""
    msg = EmailMessage()
    msg["From"] = from_addr
    msg["To"] = ", ".join(to_addrs)
    if cc_addrs:
        msg["Cc"] = ", ".join(cc_addrs)
    msg["Subject"] = subject
    if in_reply_to:
        msg["In-Reply-To"] = in_reply_to
        msg["References"] = in_reply_to
    msg.set_content(body)

    email_text = msg.as_string()

    if dry_run:
        print("=== Email Preview (dry-run) ===", file=sys.stderr)
        print(email_text, file=sys.stderr)
        print("=== End Preview ===", file=sys.stderr)
        return True

    # Write to temp file for git send-email
    with tempfile.NamedTemporaryFile(mode="w", suffix=".eml",
                                     delete=False) as f:
        f.write(email_text)
        temp_file = f.name

    try:
        # Try git send-email first
        if get_git_config("sendemail.smtpserver"):
            # Build command with all arguments
            flat_cmd = ["git", "send-email", "--confirm=never", "--quiet"]
            for addr in to_addrs:
                flat_cmd.extend(["--to", addr])
            for addr in cc_addrs:
                flat_cmd.extend(["--cc", addr])
            if from_addr:
                flat_cmd.extend(["--from", from_addr])
            if in_reply_to:
                flat_cmd.extend(["--in-reply-to", in_reply_to])
            flat_cmd.append(temp_file)

            try:
                subprocess.run(flat_cmd, check=True, capture_output=True)
                print("Email sent via git send-email", file=sys.stderr)
                return True
            except (subprocess.CalledProcessError, FileNotFoundError):
                pass

        error("Could not send email. Configure git send-email.")

    finally:
        os.unlink(temp_file)


def get_commits_as_patch(count: int, verbose: bool = False) -> tuple[str, str]:
    """Generate a patch series from the last N commits using git format-patch.

    Returns (patch_content, patch_name).
    """
    cmd = ["git", "format-patch", f"-{count}", "--stdout"]
    if verbose:
        print(f"Running: {' '.join(cmd)}", file=sys.stderr)
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError as e:
        error(f"git format-patch failed: {e.stderr.strip()}")
    except FileNotFoundError:
        error("git not found in PATH")

    if not result.stdout.strip():
        error(f"No patches generated for last {count} commit(s)")

    try:
        branch = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        patch_name = f"{branch}-last{count}.patch"
    except subprocess.CalledProcessError:
        patch_name = f"HEAD~{count}.patch"

    return result.stdout, patch_name


def preprocess_argv(argv: list[str]) -> list[str]:
    """Convert git-style -N commit-count args (e.g. -5) to --commits=N."""
    processed = []
    for arg in argv:
        if re.match(r"^-\d+$", arg):
            processed.append(f"--commits={arg[1:]}")
        else:
            processed.append(arg)
    return processed


def list_providers() -> None:
    """Print available providers and exit."""
    print("Available AI Providers:\n")
    print(f"{'Provider':<12} {'Default Model':<30} {'API Key Variable'}")
    print(f"{'--------':<12} {'-------------':<30} {'----------------'}")
    for name, config in PROVIDERS.items():
        print(f"{name:<12} {config['default_model']:<30} {config['env_var']}")
    sys.exit(0)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyze DPDK patches using AI providers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s patch.patch                    # Review with default settings
    %(prog)s -p openai my-patch.patch       # Use OpenAI ChatGPT
    %(prog)s -f markdown patch.patch        # Output as Markdown
    %(prog)s -f json -o review.json patch.patch  # Save JSON to file
    %(prog)s -f html -o review.html patch.patch  # Save HTML to file
    %(prog)s -1                             # Review last commit
    %(prog)s -5                             # Review last 5 commits
    %(prog)s --send-email --to dev@dpdk.org series.mbox
    %(prog)s --send-email --to dev@dpdk.org --dry-run series.mbox

Large File Handling:
    %(prog)s --split-patches series.mbox    # Review each patch separately
    %(prog)s --split-patches --patch-range 1-5 series.mbox # Review patches 1-5
    %(prog)s --large-file=truncate patch.mbox   # Truncate to fit limit
    %(prog)s --large-file=commits-only series.mbox  # Review commit message
    %(prog)s --large-file=summary series.mbox   # High-level summary only
    %(prog)s --large-file=chunk series.mbox     # Split and review in chunks

Large File Modes:
    error       - Fail with error (default)
    truncate    - Truncate content to fit token limit
    chunk       - Split into chunks and review each
    commits-only - Extract and review only commit messages
    summary     - Request high-level summary review

Token Usage:
    Token counts are always printed to stderr after each run.

Exit Codes:
    0 - Clean review (no errors or warnings)
    1 - Operational failure (missing API key, file not found, etc.)
    2 - Review found warnings (no errors)
    3 - Review found errors
        """,
    )

    parser.add_argument("patch_file", nargs="?", help="Patch file to analyze")
    parser.add_argument(
        "--commits",
        type=int,
        metavar="N",
        help="Use last N commits from current branch (shorthand: -N, e.g. -5)",
    )
    parser.add_argument(
        "-p",
        "--provider",
        choices=PROVIDERS.keys(),
        default="anthropic",
        help="AI provider (default: anthropic)",
    )
    parser.add_argument(
        "-a",
        "--agents",
        default="AGENTS.md",
        help="Path to AGENTS.md file (default: AGENTS.md)",
    )
    parser.add_argument(
        "-m",
        "--model",
        help="Model to use (default: provider-specific)",
    )
    parser.add_argument(
        "-t",
        "--tokens",
        type=int,
        default=4096,
        help="Max tokens for response (default: 4096)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show API request details",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=OUTPUT_FORMATS,
        default="text",
        dest="output_format",
        help="Output format: text, markdown, html, json (default: text)",
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="Write output to file instead of stdout",
    )
    parser.add_argument(
        "-l",
        "--list-providers",
        action="store_true",
        help="List available providers and exit",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        metavar="SECONDS",
        help="API request timeout in seconds (default: 300)",
    )
    parser.add_argument(
        "--no-tools",
        action="store_true",
        help=(
            "Disable tool calling. By default models may call read_file and "
            "grep_codebase to look up repository context while reviewing. "
            "Tools are unavailable for some providers regardless of the flag."
        ),
    )
    parser.add_argument(
        "--repo-dir",
        metavar="DIR",
        help=(
            "Repository root used for tool file access "
            "(default: auto-detected via git rev-parse --show-toplevel)"
        ),
    )
    parser.add_argument(
        "--config",
        metavar="FILE",
        help="JSON config file to read API key from (provider-keyed dict)"
    )

    # Date option
    parser.add_argument(
        "-D",
        "--date",
        metavar="YYYY-MM-DD",
        help="Review date context (default: today)",
    )

    # Large file handling options
    large_group = parser.add_argument_group("Large File Handling")
    large_group.add_argument(
        "--large-file",
        choices=LARGE_FILE_MODES,
        default="error",
        metavar="MODE",
        help="How to handle large files: error (default), truncate, "
        "chunk, commits-only, summary",
    )
    large_group.add_argument(
        "--max-tokens",
        type=int,
        metavar="N",
        help="Max input tokens (default: provider-specific)",
    )
    large_group.add_argument(
        "--split-patches",
        action="store_true",
        help="Split mbox into individual patches and review each separately",
    )
    large_group.add_argument(
        "--patch-range",
        metavar="N-M",
        help="Review only patches N through M (1-indexed, "
        "use with --split-patches)",
    )

    # Email options
    email_group = parser.add_argument_group("Email Options")
    email_group.add_argument(
        "--send-email",
        action="store_true",
        help="Send review via email",
    )
    email_group.add_argument(
        "--to",
        action="append",
        dest="to_addrs",
        default=[],
        metavar="ADDRESS",
        help="Email recipient (can be specified multiple times)",
    )
    email_group.add_argument(
        "--cc",
        action="append",
        dest="cc_addrs",
        default=[],
        metavar="ADDRESS",
        help="CC recipient (can be specified multiple times)",
    )
    email_group.add_argument(
        "--from",
        dest="from_addr",
        metavar="ADDRESS",
        help="From address (default: from git config)",
    )
    email_group.add_argument(
        "--dry-run",
        action="store_true",
        help="Show email without sending",
    )

    args = parser.parse_args(preprocess_argv(sys.argv[1:]))

    if args.list_providers:
        list_providers()

    # Check patch source
    if args.commits and args.patch_file:
        parser.error("Cannot specify both a patch file and -N/--commits")
    if not args.commits and not args.patch_file:
        parser.error("patch_file is required (or use -N to review N commits)")

    # Get provider config
    config = PROVIDERS[args.provider]
    model = args.model or config["default_model"]

    if args.config:
        try:
            data = json.loads(Path(args.config).read_text())
            api_key = data.get(args.provider, {}).get("apiKey")
            key_source = args.config
        except (OSError, json.JSONDecodeError, AttributeError) as e:
            error(f"Could not read --config file: {e}")
    else:
        # Get API key
        api_key = os.environ.get(config["env_var"])
        key_source = f"${config['env_var']}"
        if not api_key:
            api_key, key_source = find_api_key_from_agent_configs(
                args.provider, verbose=args.verbose)

        if not api_key:
            error(f"{config['env_var']} not set and no API key found in "
                  f"agent tool configs (Claude Code, OpenCode, Aider). "
                  f"Set {config['env_var']} or configure one of those tools.")

    # Resolve tool settings
    tools_enabled = not args.no_tools and args.provider != "google"
    repo_root = get_repo_dir(args.repo_dir)
    if tools_enabled and args.verbose:
        print(f"Tool calling: enabled (repo root: {repo_root})",
              file=sys.stderr)
    elif args.verbose:
        reason = "disabled by --no-tools" if args.no_tools else \
            "not supported for google provider"
        print(f"Tool calling: {reason}", file=sys.stderr)

    # Validate agents file
    agents_path = Path(args.agents)
    if not agents_path.exists():
        error(f"AGENTS.md not found: {args.agents}")

    # Validate patch source
    if args.patch_file:
        patch_path = Path(args.patch_file)
        if not patch_path.exists():
            error(f"Patch file not found: {args.patch_file}")

    # Validate email options
    if args.send_email and not args.to_addrs:
        error("--send-email requires at least one --to address")

    # Get from address for email
    from_addr = args.from_addr
    if args.send_email and not from_addr:
        git_name = get_git_config("user.name")
        git_email = get_git_config("user.email")
        if git_email:
            from_addr = f"{git_name} <{git_email}>" if git_name else git_email
        else:
            error("No --from specified and git user.email not configured")

    # Determine review date
    review_date = args.date or date.today().isoformat()

    # Build system prompt with date and tool guidance (if tools are active)
    system_prompt = build_system_prompt(review_date,
                                        tools_enabled=tools_enabled)

    # Read content
    agents_content = agents_path.read_text()
    if args.commits:
        patch_content, patch_name = get_commits_as_patch(
            args.commits, verbose=args.verbose
        )
    else:
        patch_content = patch_path.read_text()
        patch_name = patch_path.name

    # Determine max tokens for this provider
    max_input_tokens = args.max_tokens or PROVIDER_INPUT_LIMITS.get(
        args.provider, 100000
    )

    # Estimate token count
    estimated_tokens = estimate_tokens(patch_content + agents_content)

    # Accumulate token usage across all API calls
    total_usage = TokenUsage()

    # Parse patch range if specified
    patch_start, patch_end = None, None
    if args.patch_range:
        try:
            if "-" in args.patch_range:
                start, end = args.patch_range.split("-", 1)
                patch_start = int(start)
                patch_end = int(end)
            else:
                patch_start = patch_end = int(args.patch_range)
        except ValueError:
            error(f"Invalid --patch-range format: {args.patch_range}")
        if not args.split_patches:
            print(
                "Warning: --patch-range has no effect without --split-patches",
                file=sys.stderr,
            )

    # Handle --split-patches mode
    review_text = ""
    if args.split_patches:
        patches = split_mbox_patches(patch_content)
        total_patches = len(patches)

        if total_patches == 1:
            print("Note: Only 1 patch found in mbox, "
                  "--split-patches has no effect",
                  file=sys.stderr)
        else:
            print(f"Found {total_patches} patches in mbox",
                  file=sys.stderr)

            # Apply patch range filter
            if patch_start is not None:
                if patch_start < 1 or patch_start > total_patches:
                    error(
                        f"Patch range start {patch_start} out of "
                        f"range (1-{total_patches})"
                    )
                if patch_end < patch_start or patch_end > total_patches:
                    error(
                        f"Patch range end {patch_end} out of "
                        f"range ({patch_start}-{total_patches})"
                    )
                patches = patches[patch_start - 1: patch_end]
                print(
                    f"Reviewing patches {patch_start}-{patch_end} "
                    f"({len(patches)} patches)",
                    file=sys.stderr,
                )

            # Review each patch separately
            all_reviews = []
            for i, patch in enumerate(patches, patch_start or 1):
                patch_label = f"Patch {i}/{total_patches}"
                print(f"\nReviewing {patch_label}...", file=sys.stderr)

                review_text, call_usage = call_api(
                    args.provider,
                    api_key,
                    model,
                    args.tokens,
                    system_prompt,
                    agents_content,
                    patch,
                    f"{patch_name} ({patch_label})",
                    args.output_format,
                    args.verbose,
                    args.timeout,
                    tools_enabled=tools_enabled,
                    repo_root=repo_root,
                )
                total_usage.add(call_usage)
                all_reviews.append((patch_label, review_text))

            # Combine reviews
            review_text = format_combined_reviews(
                all_reviews, args.output_format, patch_name
            )

            # Skip the normal API call since we've already processed
            estimated_tokens = 0

    # Check if content is too large
    is_large = estimated_tokens > max_input_tokens

    if is_large:
        print(
            f"Warning: Estimated {estimated_tokens:,} tokens exceeds limit of "
            f"{max_input_tokens:,}",
            file=sys.stderr,
        )

        if args.large_file == "error":
            error(
                f"Patch file too large ({estimated_tokens:,} tokens). "
                "Use --large-file=truncate|chunk|commits-only|summary "
                "or --split-patches to review patches individually."
            )
        elif args.large_file == "truncate":
            print("Truncating content to fit token limit...", file=sys.stderr)
            patch_content, was_truncated = truncate_content(
                patch_content, max_input_tokens
            )
            if was_truncated:
                print("Content was truncated.", file=sys.stderr)
        elif args.large_file == "commits-only":
            print("Extracting commit messages only...", file=sys.stderr)
            patch_content = extract_commit_messages(patch_content)
            new_estimate = estimate_tokens(patch_content + agents_content)
            print(
                f"Reduced to ~{new_estimate:,} tokens (commit messages only)",
                file=sys.stderr,
            )
            if new_estimate > max_input_tokens:
                patch_content, _ = truncate_content(patch_content,
                                                    max_input_tokens)
        elif args.large_file == "summary":
            print("Using summary mode for large patch...", file=sys.stderr)
            system_prompt += get_summary_prompt()
            patch_content, _ = truncate_content(patch_content,
                                                max_input_tokens)
        elif args.large_file == "chunk":
            print("Processing in chunks...", file=sys.stderr)
            all_reviews = []
            for chunk, chunk_num, total_chunks in chunk_content(
                patch_content, max_input_tokens
            ):
                chunk_label = f"Chunk {chunk_num}/{total_chunks}"
                print(f"Reviewing {chunk_label}...", file=sys.stderr)

                review_text, call_usage = call_api(
                    args.provider,
                    api_key,
                    model,
                    args.tokens,
                    system_prompt,
                    agents_content,
                    chunk,
                    f"{patch_name} ({chunk_label})",
                    args.output_format,
                    args.verbose,
                    args.timeout,
                    tools_enabled=tools_enabled,
                    repo_root=repo_root,
                )
                total_usage.add(call_usage)
                all_reviews.append((chunk_label, review_text))

            # Combine chunk reviews
            review_text = format_combined_reviews(
                all_reviews, args.output_format, patch_name
            )

            # Skip the normal single API call below
            estimated_tokens = 0

    if args.verbose:
        print("=== Request ===", file=sys.stderr)
        print(f"Provider: {args.provider}", file=sys.stderr)
        print(f"API key source: {key_source}", file=sys.stderr)
        print(f"Model: {model}", file=sys.stderr)
        print(f"Review date: {review_date}", file=sys.stderr)
        print(f"Output format: {args.output_format}", file=sys.stderr)
        print(f"AGENTS file: {args.agents}", file=sys.stderr)
        if args.commits:
            print(f"Commits: last {args.commits} (branch patch: {patch_name})",
                  file=sys.stderr)
        else:
            print(f"Patch file: {args.patch_file}", file=sys.stderr)
        print(f"Estimated tokens: {estimated_tokens:,}", file=sys.stderr)
        print(f"Max input tokens: {max_input_tokens:,}", file=sys.stderr)
        if args.large_file != "error":
            print(f"Large file mode: {args.large_file}", file=sys.stderr)
        print(
            f"Tool calling:  {'enabled' if tools_enabled else 'disabled'}",
            file=sys.stderr,
        )
        if tools_enabled:
            print(f"Repo root:     {repo_root}", file=sys.stderr)
        if args.split_patches:
            print("Split patches: yes", file=sys.stderr)
        if args.output:
            print(f"Output file: {args.output}", file=sys.stderr)
        if args.send_email:
            print("Send email: yes", file=sys.stderr)
            print(f"To: {', '.join(args.to_addrs)}", file=sys.stderr)
            if args.cc_addrs:
                print(f"Cc: {', '.join(args.cc_addrs)}", file=sys.stderr)
            print(f"From: {from_addr}", file=sys.stderr)
        print("===============", file=sys.stderr)

    # Call API (unless already processed via chunks/split)
    if estimated_tokens > 0:  # Not already processed
        review_text, call_usage = call_api(
            args.provider,
            api_key,
            model,
            args.tokens,
            system_prompt,
            agents_content,
            patch_content,
            patch_name,
            args.output_format,
            args.verbose,
            args.timeout,
            tools_enabled=tools_enabled,
            repo_root=repo_root,
        )
        total_usage.add(call_usage)

    if not review_text:
        error(f"No response received from {args.provider}")

    # Format output based on requested format
    provider_name = config["name"]

    if args.output_format == "json":
        # For JSON, try to parse and add metadata
        try:
            review_data = json.loads(review_text)
        except json.JSONDecodeError:
            # If AI didn't return valid JSON, wrap the text
            review_data = {"raw_review": review_text}

        usage_data = {
            "api_calls": total_usage.api_calls,
            "input_tokens": total_usage.input_tokens,
            "output_tokens": total_usage.output_tokens,
            "total_tokens": (total_usage.input_tokens +
                             total_usage.output_tokens),
        }
        if total_usage.cache_creation_tokens:
            usage_data["cache_creation_tokens"] = \
                total_usage.cache_creation_tokens
        if total_usage.cache_read_tokens:
            usage_data["cache_read_tokens"] = total_usage.cache_read_tokens

        output_data = {
            "metadata": {
                "patch_file": patch_name,
                "provider": args.provider,
                "provider_name": provider_name,
                "model": model,
                "review_date": review_date,
                "token_usage": usage_data,
            },
            "review": review_data,
        }
        output_text = json.dumps(output_data, indent=2)
    elif args.output_format == "html":
        # Wrap HTML content with header
        output_text = f"""<!-- AI-generated review of {patch_name} -->
<!-- Reviewed using {provider_name} ({model}) on {review_date} -->
<div class="patch-review">
<h1>Patch Review: {patch_name}</h1>
<p class="review-meta">Reviewed by {provider_name} ({model}) on {review_date}
</p>
{review_text}
</div>
"""
    elif args.output_format == "markdown":
        output_text = f"""# Patch Review: {patch_name}

*Reviewed by {provider_name} ({model}) on {review_date}*
{review_text}
"""
    else:  # text
        output_text = f"=== Patch Review: {patch_name} "
        f"(via {provider_name}) ===\n"
        output_text += f"Review date: {review_date}\n"
        output_text += "\n" + review_text

    # Write output
    if args.output:
        Path(args.output).write_text(output_text)
        print(f"Review written to: {args.output}", file=sys.stderr)
    else:
        print(output_text)

    # Print token usage summary
    if total_usage.api_calls > 0:
        print("", file=sys.stderr)
        print(
            format_token_summary(total_usage, args.provider, model),
            file=sys.stderr,
        )

    # Send email if requested
    if args.send_email:
        # Email always uses plain text - warn if different format requested
        if args.output_format != "text":
            print(
                f"Note: Email will be sent as plain text regardless of "
                f"--format={args.output_format}",
                file=sys.stderr,
            )

        in_reply_to = get_last_message_id(patch_content)
        orig_subject = get_last_subject(patch_content)

        if orig_subject:
            # Remove [PATCH n/m] prefix
            review_subject = re.sub(r"^\[PATCH[^\]]*\]\s*", "", orig_subject)
            review_subject = f"[REVIEW] {review_subject}"
        else:
            review_subject = f"[REVIEW] {patch_name}"

        # Build email body - always use plain text version
        email_body = f"""AI-generated review of {patch_name}
Reviewed using {provider_name} ({model}) on {review_date}
This is an automated review. Please verify all suggestions.

---

{review_text}
"""

        if args.verbose:
            print("", file=sys.stderr)
            print("=== Email Details ===", file=sys.stderr)
            print(f"Subject: {review_subject}", file=sys.stderr)
            print(f"In-Reply-To: {in_reply_to}", file=sys.stderr)
            print("=====================", file=sys.stderr)

        send_email(
            args.to_addrs,
            args.cc_addrs,
            from_addr,
            review_subject,
            in_reply_to,
            email_body,
            args.dry_run,
        )

        if not args.dry_run:
            print("", file=sys.stderr)
            print(f"Review sent to: {', '.join(args.to_addrs)}",
                  file=sys.stderr)

    # Exit with code based on review severity
    sys.exit(classify_review(review_text, args.output_format))


if __name__ == "__main__":
    main()
