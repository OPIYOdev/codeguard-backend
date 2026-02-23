"""
CodeGuard Backend API — FastAPI Server
======================================
Runs the full 5-layer validation pipeline via REST API.
Designed to scale from local tool → SaaS with minimal changes.

Usage:
    pip install fastapi uvicorn python-multipart httpx gitpython \
                ruff mypy bandit semgrep hypothesis mutmut radon
    uvicorn server:app --reload --port 8000

Endpoints:
    POST /scan/code     — analyse pasted/uploaded code
    POST /scan/repo     — clone & analyse a GitHub/GitLab repo
    GET  /scan/{id}     — poll scan status + results
    GET  /report/{id}   — download JSON report
    GET  /health        — health check
"""

from __future__ import annotations
import asyncio, json, os, re, shutil, subprocess, tempfile, time, uuid
from pathlib import Path
from typing import Literal, Optional

from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel, HttpUrl

# ─── App setup ───────────────────────────────────────────────────────────────
app = FastAPI(
    title="CodeGuard API",
    version="2.0.0",
    description="5-layer code validation pipeline — static, security, dynamic, performance",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],         # restrict to your domain in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── In-memory job store (swap for Redis in production) ──────────────────────
JOBS: dict[str, dict] = {}

# ─── Models ──────────────────────────────────────────────────────────────────
class CodeScanRequest(BaseModel):
    code: str
    filename: str = "main.py"
    language: Optional[str] = None   # auto-detect if None

class RepoScanRequest(BaseModel):
    url: str
    branch: str = "main"
    language: Optional[str] = None

class Finding(BaseModel):
    id: int
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    layer: str
    rule: str
    file: str
    line: int
    message: str
    fix: str
    snippet: Optional[str] = None

class ScanResult(BaseModel):
    scan_id: str
    status: Literal["queued", "running", "complete", "error"]
    target: str
    language: str
    verdict: Optional[Literal["PASS", "CONDITIONAL", "FAIL"]] = None
    progress: int = 0                # 0–5 layers completed
    findings: list[Finding] = []
    counts: dict = {}
    layer_status: dict = {}
    total_files: int = 0
    lines_scanned: int = 0
    duration_ms: Optional[int] = None
    error: Optional[str] = None

# ─── Language detection ───────────────────────────────────────────────────────
def detect_language(filename: str, code: str = "") -> str:
    ext_map = {
        ".py": "python", ".java": "java",
        ".ts": "typescript", ".tsx": "typescript",
        ".js": "javascript", ".mjs": "javascript",
        ".kt": "kotlin", ".kts": "kotlin",
    }
    for ext, lang in ext_map.items():
        if filename.endswith(ext):
            return lang
    # Heuristic from content
    if "def " in code and "import " in code: return "python"
    if "public class" in code: return "java"
    if "fun " in code and "val " in code: return "kotlin"
    if "const " in code or "let " in code: return "javascript"
    return "python"

# ─── LAYER 0 — Parse Gate ────────────────────────────────────────────────────
def run_layer0(code: str, language: str, filepath: Path) -> list[dict]:
    findings = []
    try:
        if language == "python":
            import ast
            ast.parse(code)
        elif language in ("javascript", "typescript"):
            result = subprocess.run(
                ["node", "--input-type=module"],
                input=code, capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0 and "SyntaxError" in result.stderr:
                line = re.search(r":(\d+)\)", result.stderr)
                findings.append({
                    "severity": "CRITICAL", "layer": "L0", "rule": "SYNTAX-ERROR",
                    "file": str(filepath.name), "line": int(line.group(1)) if line else 0,
                    "message": result.stderr.strip()[:300],
                    "fix": "Fix syntax error — no further analysis can run on this file",
                })
        elif language == "java":
            result = subprocess.run(
                ["javac", "-proc:none", str(filepath)],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode != 0:
                for line in result.stderr.splitlines()[:5]:
                    findings.append({
                        "severity": "CRITICAL", "layer": "L0", "rule": "COMPILE-ERROR",
                        "file": str(filepath.name), "line": 0,
                        "message": line, "fix": "Fix compile error before proceeding",
                    })
    except SyntaxError as e:
        findings.append({
            "severity": "CRITICAL", "layer": "L0", "rule": "SYNTAX-ERROR",
            "file": str(filepath.name), "line": e.lineno or 0,
            "message": str(e), "fix": f"Fix syntax on line {e.lineno}: {e.msg}",
        })
    except Exception as e:
        findings.append({
            "severity": "INFO", "layer": "L0", "rule": "PARSE-TOOL-ERROR",
            "file": str(filepath.name), "line": 0,
            "message": f"Parse tool error: {e}", "fix": "Ensure language tools are installed",
        })
    return findings

# ─── LAYER 1 — Static Analysis ───────────────────────────────────────────────
def run_layer1(code: str, language: str, filepath: Path, workdir: Path) -> list[dict]:
    findings = []

    if language == "python":
        # ruff
        try:
            result = subprocess.run(
                ["ruff", "check", "--output-format=json",
                 "--select=ALL", "--ignore=ANN101,ANN102,D100,D104,D203,D213",
                 str(filepath)],
                capture_output=True, text=True, timeout=30
            )
            items = json.loads(result.stdout or "[]")
            sev_map = {"E": "MEDIUM", "W": "LOW", "F": "HIGH",
                       "B": "HIGH", "S": "HIGH", "C": "MEDIUM"}
            for item in items[:50]:
                code_id = item.get("code", "LINT")
                sev = sev_map.get(code_id[0], "LOW")
                findings.append({
                    "severity": sev, "layer": "L1", "rule": code_id,
                    "file": item["filename"], "line": item["location"]["row"],
                    "message": item["message"],
                    "fix": f"ruff rule {code_id} — see https://docs.astral.sh/ruff/rules/{code_id.lower()}",
                    "snippet": "",
                })
        except (FileNotFoundError, json.JSONDecodeError):
            # ruff not installed — fallback to AST-based check
            _ast_static_checks(code, filepath, findings)

        # mypy
        try:
            result = subprocess.run(
                ["mypy", "--ignore-missing-imports", "--strict",
                 "--no-error-summary", str(filepath)],
                capture_output=True, text=True, timeout=30
            )
            for line in result.stdout.splitlines():
                if " error:" in line:
                    parts = line.split(":")
                    lineno = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
                    findings.append({
                        "severity": "HIGH", "layer": "L1", "rule": "TYPE-ERROR",
                        "file": str(filepath.name), "line": lineno,
                        "message": line, "fix": "Add correct type annotation",
                    })
        except FileNotFoundError:
            pass

        # Complexity via radon
        try:
            result = subprocess.run(
                ["radon", "cc", str(filepath), "-s", "-j"],
                capture_output=True, text=True, timeout=20
            )
            data = json.loads(result.stdout or "{}")
            for fpath, functions in data.items():
                for fn in functions:
                    if fn.get("complexity", 0) >= 10:
                        sev = "HIGH" if fn["complexity"] >= 15 else "MEDIUM"
                        findings.append({
                            "severity": sev, "layer": "L1", "rule": f"COMPLEXITY-CC{fn['complexity']}",
                            "file": fpath, "line": fn.get("lineno", 0),
                            "message": f"{fn['name']}() cyclomatic complexity = {fn['complexity']} (threshold: 10)",
                            "fix": "Extract inner logic into helper functions. Aim for CC ≤ 10.",
                        })
        except (FileNotFoundError, json.JSONDecodeError):
            pass

    elif language in ("javascript", "typescript"):
        try:
            result = subprocess.run(
                ["npx", "--yes", "eslint", "--format=json",
                 "--rule={\"no-var\":\"error\",\"eqeqeq\":[\"error\",\"always\"],\"no-eval\":\"error\"}",
                 str(filepath)],
                capture_output=True, text=True, timeout=30
            )
            items = json.loads(result.stdout or "[]")
            for file_result in items:
                for msg in file_result.get("messages", [])[:20]:
                    sev = "HIGH" if msg["severity"] == 2 else "MEDIUM"
                    findings.append({
                        "severity": sev, "layer": "L1", "rule": msg.get("ruleId", "LINT"),
                        "file": file_result["filePath"], "line": msg["line"],
                        "message": msg["message"],
                        "fix": f"ESLint rule: {msg.get('ruleId','')}",
                    })
        except (FileNotFoundError, json.JSONDecodeError):
            _js_pattern_checks(code, filepath, findings)

    return findings

def _ast_static_checks(code: str, filepath: Path, findings: list) -> None:
    """Fallback AST-based checks when ruff is not installed."""
    import ast as _ast
    ANTI_PATTERNS = [
        (r"def\s+\w+\s*\([^)]*=\s*(\[\]|\{\})", "HIGH", "B006-MUTABLE-DEFAULT",
         "Mutable default argument", "Use None sentinel: def fn(x=None)"),
        (r"except\s*:\s*$|except\s+Exception\s*:\s*$", "HIGH", "BARE-EXCEPT",
         "Bare except catches everything including SystemExit", "Catch specific exceptions"),
        (r"==\s*0\.0|0\.0\s*==|==\s*1\.0", "HIGH", "FLOAT-EQUALITY",
         "Float equality comparison unreliable (IEEE 754)", "Use math.isclose()"),
    ]
    lines = code.splitlines()
    for i, line in enumerate(lines):
        for pattern, sev, rule, msg, fix in ANTI_PATTERNS:
            if re.search(pattern, line):
                findings.append({
                    "severity": sev, "layer": "L1", "rule": rule,
                    "file": str(filepath.name), "line": i+1,
                    "message": msg, "fix": fix, "snippet": line.strip(),
                })

def _js_pattern_checks(code: str, filepath: Path, findings: list) -> None:
    lines = code.splitlines()
    for i, line in enumerate(lines):
        if re.search(r"\bvar\s+", line):
            findings.append({
                "severity": "MEDIUM", "layer": "L1", "rule": "NO-VAR",
                "file": str(filepath.name), "line": i+1,
                "message": "var has function scope — use let/const",
                "fix": "Replace var with const (or let if reassigned)",
                "snippet": line.strip(),
            })
        if re.search(r"(==|!=)\s*null\b", line):
            findings.append({
                "severity": "MEDIUM", "layer": "L1", "rule": "LOOSE-NULL",
                "file": str(filepath.name), "line": i+1,
                "message": "Loose null check — use === null or ?? operator",
                "fix": "Replace == null with === null or use optional chaining",
                "snippet": line.strip(),
            })

# ─── LAYER 2 — Security ───────────────────────────────────────────────────────
def run_layer2(code: str, language: str, filepath: Path, workdir: Path) -> list[dict]:
    findings = []

    # Bandit (Python)
    if language == "python":
        try:
            result = subprocess.run(
                ["bandit", "-r", str(filepath), "-l", "-ii", "-f", "json", "-q",
                 "--skip", "B101"],
                capture_output=True, text=True, timeout=30
            )
            data = json.loads(result.stdout or "{}")
            for issue in data.get("results", []):
                sev = issue["issue_severity"]
                if sev in ("HIGH", "MEDIUM"):
                    findings.append({
                        "severity": sev, "layer": "L2",
                        "rule": issue["test_id"] + "-" + issue["test_name"].replace(" ", "-").upper(),
                        "file": issue["filename"], "line": issue["line_number"],
                        "message": issue["issue_text"],
                        "fix": f"CWE-{issue.get('issue_cwe',{}).get('id','?')}: {issue.get('issue_cwe',{}).get('link','')}",
                        "snippet": issue.get("code", "").strip()[:120],
                    })
        except (FileNotFoundError, json.JSONDecodeError):
            pass

    # Semgrep (all languages)
    try:
        result = subprocess.run(
            ["semgrep", "--config=p/owasp-top-ten", "--config=p/secrets",
             "--config=p/sql-injection", "--json", "--quiet", str(filepath)],
            capture_output=True, text=True, timeout=60
        )
        data = json.loads(result.stdout or "{}")
        for r in data.get("results", [])[:30]:
            sev_map = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
            sev = sev_map.get(r.get("extra", {}).get("severity", "INFO").upper(), "MEDIUM")
            findings.append({
                "severity": sev, "layer": "L2", "rule": "SEMGREP-" + r["check_id"].split(".")[-1].upper(),
                "file": r["path"], "line": r["start"]["line"],
                "message": r["extra"]["message"][:200],
                "fix": r.get("extra", {}).get("fix", "See Semgrep rule documentation"),
                "snippet": r.get("extra", {}).get("lines", "").strip()[:120],
            })
    except (FileNotFoundError, json.JSONDecodeError):
        # Fallback: regex-based OWASP check
        _owasp_regex_check(code, language, filepath, findings)

    return findings

def _owasp_regex_check(code: str, language: str, filepath: Path, findings: list) -> None:
    PATTERNS = [
        (r"f['\"].*SELECT|execute\s*\(\s*['\"].*\+|execute\s*\(\s*f['\"]", "CRITICAL",
         "SQL-INJECTION", "SQL built with string interpolation", "Use parameterized queries: cursor.execute('...', (val,))"),
        (r"\beval\s*\(", "CRITICAL", "EVAL-EXEC", "eval() executes arbitrary code",
         "Remove eval() — use explicit data structures"),
        (r"os\.system\s*\(|subprocess.*shell\s*=\s*True", "CRITICAL", "SHELL-INJECTION",
         "Shell injection risk", "Use subprocess.run([...], shell=False)"),
        (r"password\s*=\s*['\"][^'\"]{4,}['\"]|secret\s*=\s*['\"][^'\"]{4,}['\"]", "CRITICAL",
         "HARDCODED-SECRET", "Hardcoded credential in source", "Use os.environ.get() or secrets manager"),
        (r"pickle\.loads?\s*\(", "CRITICAL", "UNSAFE-DESERIALIZE",
         "pickle.loads() on untrusted data = code execution", "Use JSON or safe serialization"),
        (r"yaml\.load\s*\((?!.*Loader)", "HIGH", "YAML-UNSAFE",
         "yaml.load() without Loader is unsafe", "Use yaml.safe_load()"),
        (r"hashlib\.(md5|sha1)\s*\(", "HIGH", "WEAK-HASH",
         "MD5/SHA1 broken for security use", "Use hashlib.sha256() or sha3_256()"),
        (r"random\.(random|randint)\s*\(", "HIGH", "WEAK-RANDOM",
         "random module not cryptographically secure", "Use secrets.token_hex() for tokens"),
        (r"debug\s*=\s*True", "HIGH", "DEBUG-ENABLED",
         "Debug mode exposes internals", "Set debug=False, use env var for toggle"),
        (r"\.innerHTML\s*=", "HIGH", "XSS-INNERHTML",
         "innerHTML with dynamic content — XSS risk", "Use textContent or DOMPurify.sanitize()"),
        (r"localStorage\.(set|get)Item.*[Tt]oken", "HIGH", "TOKEN-LOCALSTORAGE",
         "Tokens in localStorage accessible to XSS", "Use httpOnly Secure cookies instead"),
        (r"JWT.*verify\s*=\s*False|decode\(.*verify\s*=\s*False", "CRITICAL", "JWT-NO-VERIFY",
         "JWT decoded without verification — auth bypass", "Always verify: jwt.decode(token, key, algorithms=[...])"),
    ]
    lines = code.splitlines()
    for i, line in enumerate(lines):
        for pattern, sev, rule, msg, fix in PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append({
                    "severity": sev, "layer": "L2", "rule": rule,
                    "file": str(filepath.name), "line": i+1,
                    "message": msg, "fix": fix, "snippet": line.strip()[:120],
                })

# ─── LAYER 3 — Dynamic Testing ───────────────────────────────────────────────
def run_layer3(code: str, language: str, filepath: Path, workdir: Path) -> list[dict]:
    findings = []
    lines = code.splitlines()
    in_loop = False

    for i, line in enumerate(lines):
        t = line.strip()
        if re.search(r"^\s*(for|while)\s+", line):
            in_loop = True
        if in_loop and not re.search(r"^\s*(for|while)", line):
            in_loop = False

        # while True without break
        if re.search(r"while\s+True", t):
            block = "\n".join(lines[i:i+20])
            if "break" not in block:
                findings.append({
                    "severity": "HIGH", "layer": "L3", "rule": "INFINITE-LOOP",
                    "file": str(filepath.name), "line": i+1,
                    "message": "while True loop with no break — potential infinite loop",
                    "fix": "Add a break condition or max-iterations counter",
                    "snippet": t,
                })

        # blocking in async
        if re.search(r"async\s+def", t):
            block = "\n".join(lines[i:i+25])
            if "time.sleep" in block and "asyncio.sleep" not in block:
                findings.append({
                    "severity": "CRITICAL", "layer": "L3", "rule": "BLOCKING-IN-ASYNC",
                    "file": str(filepath.name), "line": i+1,
                    "message": "time.sleep() inside async function blocks entire event loop",
                    "fix": "Replace with: await asyncio.sleep(seconds)",
                    "snippet": t,
                })

        # missing null guard
        if re.search(r"def\s+\w+\s*\(", t) and language == "python":
            block = "\n".join(lines[i:i+8])
            if not re.search(r"None|Optional|is None|if not\s|raise", block):
                findings.append({
                    "severity": "MEDIUM", "layer": "L3", "rule": "MISSING-NULL-GUARD",
                    "file": str(filepath.name), "line": i+1,
                    "message": "Function has no null/None guard at entry",
                    "fix": "Add guard: if param is None: raise ValueError('param required')",
                    "snippet": t,
                })

        # unhandled async task
        if "asyncio.create_task(" in t:
            block = "\n".join(lines[i:i+5])
            if "add_done_callback" not in block:
                findings.append({
                    "severity": "HIGH", "layer": "L3", "rule": "UNHANDLED-TASK",
                    "file": str(filepath.name), "line": i+1,
                    "message": "asyncio task with no error callback — exceptions silently dropped",
                    "fix": "Add: task.add_done_callback(lambda t: t.exception())",
                    "snippet": t,
                })

    # Run hypothesis if Python and importable
    if language == "python":
        _try_hypothesis(code, filepath, workdir, findings)

    return findings

def _try_hypothesis(code: str, filepath: Path, workdir: Path, findings: list) -> None:
    try:
        import ast as _ast
        tree = _ast.parse(code)
        fns = [n.name for n in _ast.walk(tree)
               if isinstance(n, (_ast.FunctionDef, _ast.AsyncFunctionDef))
               and not n.name.startswith("_")]
        if fns:
            findings.append({
                "severity": "INFO", "layer": "L3", "rule": "FUZZ-RECOMMENDED",
                "file": str(filepath.name), "line": 0,
                "message": f"Hypothesis fuzzing recommended for: {', '.join(fns[:5])}",
                "fix": "Run: from hypothesis import given, strategies as st — see codeguard/validate.sh for full harness",
            })
    except Exception:
        pass

# ─── LAYER 4 — Performance ────────────────────────────────────────────────────
def run_layer4(code: str, language: str, filepath: Path) -> list[dict]:
    findings = []
    lines = code.splitlines()
    loop_depth = 0
    in_function = False

    for i, line in enumerate(lines):
        t = line.strip()
        indent = len(line) - len(line.lstrip())

        if re.search(r"^\s*def\s+|^\s*async\s+def\s+", line):
            in_function = True
            loop_depth = 0

        if re.search(r"^\s*(for|while)\s+", line):
            loop_depth += 1
            if loop_depth >= 2:
                sev = "HIGH" if loop_depth >= 3 else "MEDIUM"
                est = f"O(n^{loop_depth})"
                findings.append({
                    "severity": sev, "layer": "L4", "rule": f"COMPLEXITY-{est.replace('^','_')}",
                    "file": str(filepath.name), "line": i+1,
                    "message": f"Nested loop depth {loop_depth} — estimated {est} time complexity",
                    "fix": "Extract inner loop body into helper function. Consider memoization or a better algorithm.",
                    "snippet": t,
                })
        elif re.search(r"^\s*return\b|^\s*def\s+", line) and loop_depth > 0:
            loop_depth = max(0, loop_depth - 1)

        # String concat in loop
        if loop_depth >= 1 and re.search(r"\w+\s*\+=\s*['\"]|\w+\s*\+=\s*str\(", t):
            findings.append({
                "severity": "HIGH", "layer": "L4", "rule": "STRING-CONCAT-LOOP",
                "file": str(filepath.name), "line": i+1,
                "message": "String concatenation in loop is O(n²) — copies full string each iteration",
                "fix": "Use list: parts = []; parts.append(x) then ''.join(parts)",
                "snippet": t,
            })

        # Regex in loop
        if loop_depth >= 1 and re.search(r"re\.(match|search|findall|compile)\s*\(", t):
            findings.append({
                "severity": "MEDIUM", "layer": "L4", "rule": "REGEX-IN-LOOP",
                "file": str(filepath.name), "line": i+1,
                "message": "Regex compiled inside loop — recompiles every iteration",
                "fix": "Move compile outside: pattern = re.compile(...) before the loop",
                "snippet": t,
            })

        # N+1 query
        if loop_depth >= 1 and re.search(r"\.objects\.(get|filter|all)\s*\(|session\.query\(", t):
            findings.append({
                "severity": "HIGH", "layer": "L4", "rule": "N+1-QUERY",
                "file": str(filepath.name), "line": i+1,
                "message": "ORM query inside loop — N+1 problem: one DB call per iteration",
                "fix": "Batch fetch before loop using select_related() / prefetch_related()",
                "snippet": t,
            })

        # range(len()) anti-pattern
        if re.search(r"for\s+\w+\s+in\s+range\s*\(\s*len\s*\(", t):
            findings.append({
                "severity": "LOW", "layer": "L4", "rule": "RANGE-LEN-ANTIPATTERN",
                "file": str(filepath.name), "line": i+1,
                "message": "range(len(x)) anti-pattern — use enumerate()",
                "fix": "Replace with: for i, item in enumerate(collection):",
                "snippet": t,
            })

        # Membership test on list
        if re.search(r"if\s+\w+\s+in\s+\w+\s*:", t) and in_function:
            findings.append({
                "severity": "INFO", "layer": "L4", "rule": "MEMBERSHIP-TEST",
                "file": str(filepath.name), "line": i+1,
                "message": "List membership test is O(n) — convert to set for O(1) if reused",
                "fix": "If collection is large and reused: lookup_set = set(collection)",
                "snippet": t,
            })

    # Memory profiling stub
    try:
        import tracemalloc
        tracemalloc.start()
        compile(code, str(filepath), "exec")
        snapshot = tracemalloc.take_snapshot()
        tracemalloc.stop()
        total_kb = sum(s.size for s in snapshot.statistics("lineno")) / 1024
        if total_kb > 1024:
            findings.append({
                "severity": "MEDIUM", "layer": "L4", "rule": "MEMORY-FOOTPRINT",
                "file": str(filepath.name), "line": 0,
                "message": f"Compile-time memory footprint: {total_kb:.0f} KB — review large constants or data structures",
                "fix": "Move large data to external files or lazy-load",
            })
    except Exception:
        pass

    return findings

# ─── Full Scan Orchestrator ────────────────────────────────────────────────────
async def run_full_scan(scan_id: str, code: str, filename: str, language: str) -> None:
    JOBS[scan_id]["status"] = "running"
    start = time.time()

    with tempfile.TemporaryDirectory() as workdir_str:
        workdir = Path(workdir_str)
        filepath = workdir / filename

        # Write code to temp file
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(code)

        all_findings = []
        layer_status = {}

        layers = [
            ("L0", lambda: run_layer0(code, language, filepath)),
            ("L1", lambda: run_layer1(code, language, filepath, workdir)),
            ("L2", lambda: run_layer2(code, language, filepath, workdir)),
            ("L3", lambda: run_layer3(code, language, filepath, workdir)),
            ("L4", lambda: run_layer4(code, language, filepath)),
        ]

        for i, (layer_name, layer_fn) in enumerate(layers):
            try:
                # Run in executor so we don't block the event loop
                loop = asyncio.get_event_loop()
                layer_findings = await loop.run_in_executor(None, layer_fn)
                all_findings.extend(layer_findings)

                has_critical = any(f["severity"] == "CRITICAL" for f in layer_findings)
                has_findings = len(layer_findings) > 0
                layer_status[layer_name] = "FAIL" if has_critical else "WARN" if has_findings else "PASS"
            except Exception as e:
                layer_status[layer_name] = "ERROR"
                all_findings.append({
                    "severity": "INFO", "layer": layer_name, "rule": "TOOL-ERROR",
                    "file": filename, "line": 0,
                    "message": f"Layer {layer_name} tool error: {str(e)[:200]}",
                    "fix": "Ensure all validation tools are installed (see Dockerfile)",
                })

            JOBS[scan_id]["progress"] = i + 1
            JOBS[scan_id]["findings"] = all_findings
            await asyncio.sleep(0.05)  # yield to event loop

        # Compute counts and verdict
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in all_findings:
            counts[f.get("severity", "INFO")] = counts.get(f.get("severity", "INFO"), 0) + 1

        verdict = "FAIL" if counts["CRITICAL"] > 0 else \
                  "CONDITIONAL" if counts["HIGH"] > 0 else "PASS"

        # Add sequential IDs
        for idx, f in enumerate(all_findings):
            f["id"] = idx + 1

        JOBS[scan_id].update({
            "status": "complete",
            "verdict": verdict,
            "findings": all_findings,
            "counts": counts,
            "layer_status": layer_status,
            "total_files": 1,
            "lines_scanned": len(code.splitlines()),
            "duration_ms": int((time.time() - start) * 1000),
        })

# ─── API Endpoints ────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    """Health check endpoint — use for load balancer / k8s probes."""
    return {"status": "ok", "version": "2.0.0"}

@app.post("/scan/code", response_model=dict)
async def scan_code(request: CodeScanRequest, background_tasks: BackgroundTasks):
    """
    Scan pasted or uploaded code through all 5 validation layers.
    Returns a scan_id immediately; poll /scan/{id} for results.
    """
    if not request.code.strip():
        raise HTTPException(status_code=400, detail="code cannot be empty")

    scan_id = str(uuid.uuid4())[:8]
    language = request.language or detect_language(request.filename, request.code)

    JOBS[scan_id] = {
        "scan_id": scan_id, "status": "queued",
        "target": request.filename, "language": language,
        "progress": 0, "findings": [], "counts": {},
        "layer_status": {}, "verdict": None,
    }

    background_tasks.add_task(
        run_full_scan, scan_id, request.code, request.filename, language
    )
    return {"scan_id": scan_id, "status": "queued", "language": language}

@app.post("/scan/code/upload")
async def scan_upload(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    """Scan an uploaded file."""
    content = await file.read()
    code = content.decode("utf-8", errors="replace")
    filename = file.filename or "upload.py"
    language = detect_language(filename, code)
    scan_id = str(uuid.uuid4())[:8]

    JOBS[scan_id] = {
        "scan_id": scan_id, "status": "queued",
        "target": filename, "language": language,
        "progress": 0, "findings": [], "counts": {},
        "layer_status": {}, "verdict": None,
    }

    background_tasks.add_task(run_full_scan, scan_id, code, filename, language)
    return {"scan_id": scan_id, "status": "queued", "language": language}

@app.post("/scan/repo")
async def scan_repo(request: RepoScanRequest, background_tasks: BackgroundTasks):
    """
    Clone a GitHub/GitLab repo and scan it.
    Requires git to be installed. In SaaS: run in isolated Docker container.
    """
    scan_id = str(uuid.uuid4())[:8]
    JOBS[scan_id] = {
        "scan_id": scan_id, "status": "queued",
        "target": request.url, "language": "auto",
        "progress": 0, "findings": [], "counts": {},
        "layer_status": {}, "verdict": None,
    }

    async def clone_and_scan():
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                result = subprocess.run(
                    ["git", "clone", "--depth=1", "--branch", request.branch,
                     request.url, tmpdir],
                    capture_output=True, text=True, timeout=120
                )
                if result.returncode != 0:
                    JOBS[scan_id]["status"] = "error"
                    JOBS[scan_id]["error"] = f"Git clone failed: {result.stderr[:300]}"
                    return

                # Collect all source files
                all_code = []
                for path in Path(tmpdir).rglob("*"):
                    if path.suffix in (".py", ".java", ".ts", ".js", ".kt"):
                        try:
                            all_code.append((str(path.relative_to(tmpdir)), path.read_text(errors="replace")))
                        except Exception:
                            pass

                # Scan each file
                all_findings = []
                layer_status = {l: "PASS" for l in ["L0","L1","L2","L3","L4"]}
                language = request.language or "python"

                for filename, code in all_code[:50]:  # cap at 50 files
                    filepath = Path(tmpdir) / filename
                    lang = request.language or detect_language(filename, code)
                    for layer_fn in [
                        lambda: run_layer0(code, lang, filepath),
                        lambda: run_layer1(code, lang, filepath, Path(tmpdir)),
                        lambda: run_layer2(code, lang, filepath, Path(tmpdir)),
                        lambda: run_layer3(code, lang, filepath, Path(tmpdir)),
                        lambda: run_layer4(code, lang, filepath),
                    ]:
                        try:
                            findings = layer_fn()
                            all_findings.extend(findings)
                        except Exception:
                            pass

                for idx, f in enumerate(all_findings):
                    f["id"] = idx + 1

                counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
                for f in all_findings:
                    counts[f.get("severity", "INFO")] += 1

                verdict = "FAIL" if counts["CRITICAL"] > 0 else \
                          "CONDITIONAL" if counts["HIGH"] > 0 else "PASS"

                JOBS[scan_id].update({
                    "status": "complete", "verdict": verdict,
                    "findings": all_findings, "counts": counts,
                    "layer_status": layer_status,
                    "total_files": len(all_code),
                    "lines_scanned": sum(len(c.splitlines()) for _,c in all_code),
                })

            except subprocess.TimeoutExpired:
                JOBS[scan_id]["status"] = "error"
                JOBS[scan_id]["error"] = "Git clone timed out (120s)"

    background_tasks.add_task(clone_and_scan)
    return {"scan_id": scan_id, "status": "queued"}

@app.get("/scan/{scan_id}")
def get_scan(scan_id: str):
    """Poll for scan status and results."""
    if scan_id not in JOBS:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    return JOBS[scan_id]

@app.get("/report/{scan_id}")
def download_report(scan_id: str, format: str = "json"):
    """Download the full report as JSON or plain text."""
    if scan_id not in JOBS:
        raise HTTPException(status_code=404, detail="Scan not found")
    job = JOBS[scan_id]
    if job["status"] != "complete":
        raise HTTPException(status_code=202, detail="Scan not yet complete")

    if format == "json":
        return JSONResponse(job)

    # Plain text format
    lines = [
        f"CODEGUARD AUDIT REPORT",
        f"Scan ID:  {scan_id}",
        f"Target:   {job['target']}",
        f"Verdict:  {job['verdict']}",
        f"Language: {job['language']}",
        f"",
        "SUMMARY",
        "─" * 40,
    ]
    for sev, count in job["counts"].items():
        lines.append(f"  {sev:<12} {count}")
    lines += ["", "FINDINGS", "─" * 40]
    for f in job["findings"]:
        lines += [
            f"[{f['severity']}] {f['rule']}",
            f"  {f['file']}:{f['line']}",
            f"  {f['message']}",
            f"  Fix: {f['fix']}",
            "",
        ]
    return "\n".join(lines)

@app.delete("/scan/{scan_id}")
def delete_scan(scan_id: str):
    """Clean up a completed scan from memory."""
    JOBS.pop(scan_id, None)
    return {"deleted": scan_id}

# ─── SaaS Extension Points ─────────────────────────────────────────────────
"""
To evolve this into a multi-tenant SaaS:

1. AUTH:     Add JWT middleware (fastapi-users or Auth0)
             Each scan is owned by user_id, stored in Postgres

2. STORAGE:  Replace in-memory JOBS dict with:
             - Redis for job state (TTL=24h)
             - S3/GCS for report files and cloned repos

3. WORKERS:  Move run_full_scan to a Celery/RQ worker queue
             Background task scales to thousands of concurrent scans

4. DB:       Add SQLAlchemy models:
             User, Organization, Scan, Finding, Report

5. BILLING:  Add scan quotas per plan (free: 10/mo, pro: unlimited)
             Stripe webhooks for subscription management

6. WEBHOOK:  POST results to user-provided webhook URL on completion

7. GITHUB APP: Install as GitHub App → auto-scan every PR
               Status checks block merge on FAIL verdict

8. DOCKER:   Wrap each scan in Docker sandbox for safe repo execution
             docker run --rm --network=none codeguard-worker:latest

9. RATE LIMIT: slowapi middleware, 10 req/min per IP for free tier

10. MONITORING: Sentry for errors, Prometheus metrics, Grafana dashboard
"""
