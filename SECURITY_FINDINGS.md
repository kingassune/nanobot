# Security Audit of Nanobot: Finding and Fixing Vulnerabilities in a Lightweight AI Assistant

**Author:** Dontrail Cotlage (kingassune)
**Date:** February 2026

## Introduction

[Nanobot](https://github.com/HKUDS/nanobot) is an ultra-lightweight personal AI assistant framework -- a 99% smaller alternative to large agent frameworks, delivering core agent functionality in roughly 4,000 lines of Python. It supports multiple LLM providers (OpenRouter, Anthropic, OpenAI, DeepSeek, etc.), chat platform integrations (Telegram, WhatsApp, Feishu), and gives the AI agent the ability to execute shell commands, read/write files, and fetch web content.

That last sentence should raise some eyebrows. An AI agent that can run shell commands and touch the filesystem is powerful, but it's also a significant attack surface. I decided to conduct a full security audit of nanobot: identify vulnerabilities, build proof-of-concept exploits, contribute fixes upstream, and document the entire process. Here's what I found.

## Scope of the Audit

The audit covered the entire nanobot codebase with a focus on:

- **Dependency vulnerabilities** -- outdated libraries with known CVEs
- **Shell command execution** -- input validation and dangerous command filtering
- **File system operations** -- path traversal protection
- **Web request handling** -- URL validation and redirect control
- **Authentication and access control** -- channel allow-list design
- **Tool parameter validation** -- schema enforcement on all tool inputs

## Phase 1: Dependency Analysis -- Critical Findings

The first and most severe discovery was in the project's dependencies.

### LiteLLM: 10 Known Vulnerabilities Including RCE

Nanobot's `pyproject.toml` specified `litellm>=1.0.0`, which allowed installation of versions with **critical** known vulnerabilities:

| Vulnerability | Severity | Affected Versions | Impact |
|---|---|---|---|
| Remote Code Execution via `eval()` | CRITICAL | <= 1.28.11, < 1.40.16 | Arbitrary code execution |
| Server-Side Request Forgery (SSRF) | HIGH | < 1.44.8 | Internal network access |
| API Key Leakage via Logging | MEDIUM | < 1.44.12 | Credential exposure |
| Improper Authorization | HIGH | < 1.61.15 | Unauthorized access |
| Denial of Service | MEDIUM | < 1.56.2 | Service disruption |
| Arbitrary File Deletion | HIGH | < 1.35.36 | Data loss |
| Server-Side Template Injection | CRITICAL | < 1.34.42 | Remote code execution |

The RCE vulnerability was particularly concerning: older litellm versions pass user-controlled input to Python's `eval()` in multiple code paths including template string processing, callback handlers, and proxy configuration parsing.

**Fix applied:** Updated the minimum version constraint to `litellm>=1.61.15`.

### WebSocket (ws) DoS Vulnerability

The Node.js WhatsApp bridge used `ws ^8.17.0`, which was vulnerable to Denial of Service via HTTP header flooding (patched in 8.17.1).

**Fix applied:** Updated to `ws>=8.17.1`.

## Phase 2: Shell Command Injection Bypasses

Nanobot's `ExecTool` uses `asyncio.create_subprocess_shell()` to run commands. The original code had **no input validation at all** -- any command the LLM decided to run would execute directly.

### Building the Exploit POC

I wrote a comprehensive shell injection test suite (`poc/exploits/shell_injection.py`) that demonstrated 15 bypass techniques against the initial pattern-based filter that was later added:

```
Test  1: Command substitution     -- echo $(cat /etc/passwd)
Test  2: Backtick substitution    -- echo `cat /etc/shadow`
Test  3: Base64 encoded commands  -- echo <b64> | base64 -d | bash
Test  4: Hex encoded commands     -- echo -e '\x69\x64' | bash
Test  5: Environment exfiltration -- env | grep -iE '(key|secret|token)'
Test  6: Network reconnaissance   -- cat /etc/hosts && ip addr
Test  7: Process enumeration      -- ps aux
Test  8: SSH key exfiltration     -- cat ~/.ssh/id_rsa
Test  9: Alternative rm (find)    -- find /path -delete
Test 10: Reverse shell setup      -- write shell script to file
Test 11: Memory exhaustion        -- /dev/zero piped through xxd
Test 12: CPU exhaustion           -- yes > /dev/null
Test 13: Curl-pipe-bash pattern   -- curl ... | bash
Test 14: Python interpreter       -- python3 -c 'import os; ...'
Test 15: Config file access       -- read application configs
```

### The Fix: Multi-Layer Command Validation

Working with the upstream maintainers, a dangerous command pattern filter was added to `shell.py`:

```python
DANGEROUS_PATTERNS = [
    r'rm\s+-rf\s+/',          # rm -rf / at root
    r':\(\)\{\s*:\|:&\s*\};:',  # fork bomb
    r'mkfs\.',                 # format filesystem
    r'dd\s+if=.*\s+of=/dev/(sd|hd)',  # overwrite disk
    r'>\s*/dev/(sd|hd)',       # write to raw disk device
]
```

Additional protections were also added:
- Configurable command allow/deny lists
- Path restriction to workspace directory
- Timeout enforcement (60-second default)
- Output truncation (10KB limit)

While regex-based filtering will never be a complete solution (as my bypass tests demonstrated), these controls significantly raise the bar when combined with the other defenses.

## Phase 3: Path Traversal in File Operations

The filesystem tools (`ReadFileTool`, `WriteFileTool`, `EditFileTool`, `ListDirTool`) originally used `Path.expanduser()` without any directory traversal protection.

### The Exploit

My path traversal POC (`poc/exploits/path_traversal.py`) demonstrated reading sensitive files outside the intended workspace:

```python
# All of these succeeded before the fix:
read_file(path="/etc/passwd")              # System user enumeration
read_file(path="/proc/self/environ")       # Environment variable disclosure
read_file(path="/app/../etc/passwd")       # Dot-dot traversal
read_file(path="~/.ssh/id_rsa")            # SSH key disclosure
write_file(path="/tmp/malicious.txt", ...) # Arbitrary file write
```

### The Fix: Path Validation with Base Directory Restriction

A `_validate_path()` function was added to `filesystem.py`:

```python
def _validate_path(path: str, base_dir: Path | None = None) -> tuple[bool, Path | str]:
    file_path = Path(path).expanduser().resolve()
    if base_dir is not None:
        base_resolved = base_dir.resolve()
        file_path.relative_to(base_resolved)  # Raises ValueError if outside
    return True, file_path
```

All four file tools were updated to pass through this validation. The function uses `Path.resolve()` to normalize paths (eliminating `..` traversal) and optionally enforces a base directory constraint.

## Phase 4: Web Request Security

The `WebFetchTool` had two issues:

1. **No URL scheme validation** -- could potentially be abused with non-HTTP schemes
2. **Unlimited redirects** -- could be used for redirect-based DoS or SSRF

### The Fix

A `_validate_url()` function was added that enforces HTTP/HTTPS-only schemes, and the HTTP client was configured with a `MAX_REDIRECTS = 5` limit:

```python
def _validate_url(url: str) -> tuple[bool, str]:
    p = urlparse(url)
    if p.scheme not in ('http', 'https'):
        return False, f"Only http/https allowed, got '{p.scheme or 'none'}'"
    if not p.netloc:
        return False, "Missing domain"
    return True, ""
```

## Phase 5: Authentication Model -- Fail-Open to Fail-Closed

One of the more subtle but impactful findings was in the channel access control. The original implementation had a **fail-open** design:

```python
# BEFORE: Empty allow_from list allows ALL users
if not allow_list:
    return True
```

This meant that any unconfigured nanobot instance was open to everyone. The fix changed this to **fail-closed**:

```python
# AFTER: Empty allow_from list blocks ALL access
if not allow_list:
    return False
```

Additionally, logging was added for denied access attempts, giving operators visibility into unauthorized access.

## Phase 6: Tool Parameter Validation

A comprehensive JSON Schema validation layer was added to the tool base class, enforcing:

- Type checking (string, integer, number, boolean, array, object)
- Range validation (minimum, maximum, minLength, maxLength)
- Enum constraints
- Required field checking
- Recursive validation for nested objects

This prevents the LLM from passing malformed or unexpected parameters to any tool.

## The Contribution Timeline

The work was structured across three key PRs:

### PR #1: Security Audit (`kingassune/copilot/run-security-audit`)
- Full security audit report (`SECURITY_AUDIT.md`)
- Dependency version fixes (`litellm>=1.61.15`, `ws>=8.17.1`)
- Path traversal protection in `filesystem.py`
- Dangerous command pattern detection in `shell.py`
- Fail-closed authentication in `base.py`
- Comprehensive security documentation (`SECURITY.md`)
- Docker-based POC exploit environment with test scripts

### PR #2: Cleanup (`kingassune/copilot/clean-up-repo-security-exploit`)
- Removed excessive POC infrastructure (mock LLM server, extra Dockerfiles)
- Kept the elegant security fixes and core exploit test scripts
- Cleaned up test data to use non-realistic markers

### PR #3: Housekeeping (`kingassune/copilot/remove-poetry-lock-file`)
- Removed `poetry.lock` from the repository and added it to `.gitignore`

Upstream, the maintainers also merged related PRs:
- **PR #22**: Web fetch URL validation and security improvements
- **PR #30**: Exec tool parameter validation and safety guard hardening
- **PR #23**: Heartbeat token matching logic fix

## Lessons Learned

### 1. Dependency Pinning Matters
The `>=1.0.0` version constraint for litellm was effectively "any version." In a security-sensitive context, minimum version constraints should reflect the latest security patches.

### 2. AI Agents Need Defense in Depth
No single control is sufficient when an AI agent can execute shell commands. The combination of pattern filtering, path validation, timeout enforcement, output truncation, and access control creates meaningful defense in depth -- even though each layer alone is bypassable.

### 3. Fail-Closed is Non-Negotiable
The fail-open authentication default meant that every new deployment was insecure by default. Security-sensitive defaults should always deny access unless explicitly configured otherwise.

### 4. POC Exploits Drive Fixes
Abstract vulnerability reports get deprioritized. Working exploit code with clear demonstrations of impact -- reading `/etc/passwd`, exfiltrating environment variables, writing arbitrary files -- makes the risk concrete and the fix urgent.

### 5. Lightweight Doesn't Mean Insecure
Nanobot's small codebase (~4,000 lines) made the audit tractable and the fixes surgical. The security improvements added roughly 350 lines of code across the entire project. A small footprint is itself a security advantage -- there's less code to audit and fewer places for vulnerabilities to hide.

## Current Security Posture

After these changes, nanobot has:

- **Fail-closed access control** with per-channel allow-lists
- **Path traversal protection** on all file operations
- **Dangerous command pattern detection** on shell execution
- **URL validation** with redirect limits on web requests
- **JSON Schema validation** on all tool parameters
- **Secure dependency versions** with documented audit procedures
- **Comprehensive security documentation** with deployment checklists

### Acknowledged Limitations

The project transparently documents its remaining limitations:
- No built-in rate limiting
- Plain text configuration storage
- No session management/expiry
- Regex-based command filtering (not a sandbox)
- Limited audit trail

These are reasonable trade-offs for a lightweight framework, especially when documented clearly and accompanied by guidance for production hardening.

## Conclusion

Security auditing an AI agent framework is a different challenge than auditing a traditional web application. The attack surface includes not just the application code, but every action the AI can take -- and LLMs can be creative in finding unintended uses for available tools. The combination of dependency management, input validation, access control, and transparent documentation creates a solid foundation, but deploying any AI agent that can execute commands in production requires ongoing vigilance and layered defenses.

The full audit report, exploit POCs, and all fixes are available in the [nanobot repository](https://github.com/HKUDS/nanobot).
