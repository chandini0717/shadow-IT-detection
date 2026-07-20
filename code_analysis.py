"""
Heuristic code analyzer.

IMPORTANT (honesty note, also surfaced to the frontend):
There is no reliable technical way to prove which AI tool (or human) produced
a snippet of code. This module scores stylistic/textual signals that are
*commonly associated* with certain AI assistants' output style, and returns a
confidence-weighted best guess plus a separate, independent security-risk
scan (secrets, dangerous calls, insecure patterns). Treat the "source" field
as a heuristic indicator for triage, not a forensic fact.
"""
import re

# --- Source heuristics -------------------------------------------------
# Each pattern contributes points toward a platform "signal". This is a
# simple weighted heuristic, not a trained classifier.
SOURCE_SIGNALS = {
    "ChatGPT (OpenAI)": [
        (r"#\s*Step \d+", 2),
        (r"Here('?s| is) (an?|the) (updated|complete|full) (code|version|example)", 3),
        (r"""^\s*'''[\s\S]*?'''""", 1),
        (r"# This function", 1),
        (r"Note:\s", 1),
        (r"import\s+os\s*\nimport\s+sys", 1),
    ],
    "Google Gemini": [
        (r"# @title", 3),
        (r"#@param", 3),
        (r"Colab", 3),
        (r"In summary,", 2),
        (r"# Explanation:", 2),
        (r"Key improvements:", 2),
    ],
    "GitHub Copilot": [
        (r"^\s*// TODO", 1),
        (r"^\s*#\s*TODO", 1),
        (r"function\s+\w+\(.*\)\s*\{\s*$", 1),
        (r"console\.log\(", 1),
    ],
    "Anthropic Claude": [
        (r"I'll (help|create|write|implement)", 3),
        (r"Here'?s (a|an|the) .*implementation", 2),
        (r"# This (implementation|approach|solution)", 2),
        (r"Let me (know|explain)", 2),
    ],
}

GENERIC_HUMAN_SIGNALS = [
    r"\bXXX\b",
    r"\bhack\b",
    r"\bfixme\b",
    r"# temp",
    r"# quick and dirty",
]

# --- Security risk heuristics -------------------------------------------
RISK_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "Hardcoded AWS access key", "Critical"),
    (r"-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----", "Embedded private key", "Critical"),
    (r"(?i)api[_-]?key\s*=\s*['\"][A-Za-z0-9_\-]{10,}['\"]", "Hardcoded API key", "High"),
    (r"(?i)password\s*=\s*['\"].+['\"]", "Hardcoded password", "High"),
    (r"eval\(", "Use of eval() - code injection risk", "High"),
    (r"exec\(", "Use of exec() - code injection risk", "High"),
    (r"os\.system\(", "Shell command execution via os.system", "Medium"),
    (r"subprocess\.(Popen|call|run)\(.*shell\s*=\s*True", "Shell injection risk (shell=True)", "High"),
    (r"pickle\.loads?\(", "Insecure deserialization (pickle)", "Medium"),
    (r"(?i)select .* from .* \+ ", "Possible SQL injection via string concatenation", "High"),
    (r"innerHTML\s*=", "Potential DOM XSS via innerHTML", "Medium"),
    (r"http://", "Insecure HTTP (not HTTPS) endpoint referenced", "Low"),
]


def detect_source(code: str):
    scores = {}
    for platform, patterns in SOURCE_SIGNALS.items():
        total = 0
        for pattern, weight in patterns:
            matches = re.findall(pattern, code, flags=re.MULTILINE)
            total += len(matches) * weight
        scores[platform] = total

    human_hits = sum(len(re.findall(p, code, flags=re.IGNORECASE)) for p in GENERIC_HUMAN_SIGNALS)

    best_platform = max(scores, key=scores.get)
    best_score = scores[best_platform]
    total_signal = sum(scores.values()) + human_hits

    if total_signal == 0:
        return {
            "predicted_source": "Unknown / Insufficient signal",
            "confidence": 0,
            "note": "No strong stylistic signals detected. This heuristic cannot reliably "
                    "attribute authorship without more context (comments, formatting habits).",
            "signal_breakdown": scores,
        }

    confidence = round(min(95, (best_score / total_signal) * 100)) if total_signal else 0

    if human_hits > best_score:
        return {
            "predicted_source": "Likely Human-Written",
            "confidence": min(90, 40 + human_hits * 10),
            "note": "Contains informal developer markers (TODO/FIXME/hack) more typical of manual editing.",
            "signal_breakdown": scores,
        }

    return {
        "predicted_source": best_platform if best_score > 0 else "Unknown / Insufficient signal",
        "confidence": confidence,
        "note": "Heuristic stylistic match based on comment phrasing and formatting patterns. "
                "Not a forensic guarantee — treat as a triage signal only.",
        "signal_breakdown": scores,
    }


def scan_risk(code: str):
    findings = []
    severity_rank = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    max_severity = "Low"

    for pattern, description, severity in RISK_PATTERNS:
        matches = re.findall(pattern, code)
        if matches:
            findings.append({
                "issue": description,
                "severity": severity,
                "occurrences": len(matches),
            })
            if severity_rank[severity] > severity_rank[max_severity]:
                max_severity = severity

    is_risky = len(findings) > 0
    risk_percentage = {"Low": 20, "Medium": 50, "High": 75, "Critical": 95}[max_severity] if is_risky else 5

    return {
        "is_risky": is_risky,
        "risk_level": max_severity if is_risky else "Low",
        "risk_percentage": risk_percentage,
        "findings": findings,
    }


def analyze_code(code: str):
    if not code or not code.strip():
        return {"error": "No code provided."}

    return {
        "source": detect_source(code),
        "risk": scan_risk(code),
        "lines_analyzed": len(code.splitlines()),
    }
