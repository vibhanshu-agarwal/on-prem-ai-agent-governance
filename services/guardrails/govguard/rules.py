"""Deterministic rules: no model, no network, fully unit-testable.

- prompt-injection heuristics for UNTRUSTED content (tool results, retrieved documents)
- secret / key patterns (input and output)
- helpers to read tool declarations and tool calls in OpenAI chat format

Heuristics are weighted patterns over normalised text (NFKC, invisible characters
stripped, lower-cased). A finding is raised when the summed weight reaches the
policy threshold. They are a cheap first screen, NOT a complete defence: the
report's actual containment for prompt injection is least privilege, untrusted
content kept separate, and human approval of consequential actions.
"""
from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass
from typing import Any, Iterable

# --------------------------------------------------------------------------- injection
_P = re.compile
INJECTION_PATTERNS: list[tuple[str, re.Pattern, int]] = [
    ("override_instructions", _P(
        r"\b(ignore|disregard|forget|override|bypass|discard)\b[^.\n]{0,40}"
        r"\b(previous|prior|above|earlier|preceding|all|any|your|the|these|those|system)\b[^.\n]{0,30}"
        r"\b(instructions?|prompts?|rules?|guidelines?|directions?|constraints?|guardrails?|polic(?:y|ies))\b"), 3),
    ("reveal_prompt", _P(
        r"\b(reveal|print|show|output|repeat|leak|disclose|display)\b[^.\n]{0,40}"
        r"\b(system prompt|hidden prompt|your instructions|initial prompt|developer message|your rules)\b"), 3),
    ("role_hijack", _P(r"\byou are now\b|\bfrom now on,? you (?:are|will|must|should)\b"
                       r"|\bnew (?:instructions?|task|role|objective)\s*:"), 2),
    ("jailbreak_persona", _P(r"\bact as (?:an? )?(?:unrestricted|jailbroken|uncensored)\b|\bdo anything now\b|\bdan mode\b"), 3),
    ("chat_template_markers", _P(r"<\|(?:im_start|im_end|system|assistant|user)\|>|\[/?inst\]|<<\/?sys>>"
                                 r"|^\s*#{2,}\s*(?:system|instruction)s?\b|^\s*(?:system|assistant)\s*:", re.M), 2),
    ("authority_claim", _P(r"\bthis is (?:an? )?(?:system|admin|administrator|developer|security) "
                           r"(?:message|override|notice|instruction)\b"), 2),
    ("exfiltration_send", _P(  # generic (legit documents say "send the invoice to x@y"): below threshold alone
        r"\b(send|forward|email|e-mail|post|upload|exfiltrate|transmit|leak)\b[^.\n]{0,60}"
        r"\b(?:to|at)\b[^.\n]{0,20}(?:https?://|[\w.+-]+@[\w-]+\.)"), 2),
    ("exfiltration_sensitive", _P(
        r"\b(send|forward|email|e-mail|post|upload|exfiltrate|transmit|leak|share)\b[^.\n]{0,60}"
        r"\b(?:passwords?|credentials?|api[ _-]?keys?|secrets?|tokens?|system prompt|conversation|chat history|"
        r"customer (?:list|data|records)|database|private key|ssh key)\b[^.\n]{0,80}"
        r"\b(?:to|at|via)\b[^.\n]{0,30}(?:https?://|[\w.+-]+@[\w-]+\.|\b\d{1,3}(?:\.\d{1,3}){3}\b)"), 3),
    ("markdown_image_exfil", _P(r"!\[[^\]]*\]\(https?://[^)\s]*[?&][^)\s]*=[^)\s]*\)"), 3),
    ("conceal_from_user", _P(r"\b(?:do not|don't|never|without)\b[^.\n]{0,20}\b(?:tell|inform|mention|alert|notify|show)\b"
                             r"[^.\n]{0,20}\b(?:the )?(?:user|human|operator)\b"), 3),
    ("shell_pipe", _P(r"\b(?:curl|wget)\b[^|\n]{0,200}\|\s*(?:ba|z)?sh\b|\brm\s+-rf\s+[/~]"), 3),
    ("tool_coercion", _P(r"\b(?:call|invoke|use|run|execute|trigger)\b[^.\n]{0,30}\b(?:tool|function|command)\b"
                         r"[^.\n]{0,40}\b(?:with|using|to)\b"), 1),
    ("urgent_override", _P(r"\b(?:important|urgent|critical)\b[^.\n]{0,20}\b(?:ignore|instead|must now|immediately)\b"), 1),
]
_INVISIBLE = re.compile("[​‌‍⁠﻿‪-‮⁦-⁩]")
_B64_BLOB = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")


def normalise(text: str) -> str:
    t = unicodedata.normalize("NFKC", text)
    t = "".join(ch for ch in t if unicodedata.category(ch) != "Cf")
    return re.sub(r"[ \t\r\f\v]+", " ", t).lower()


@dataclass(frozen=True)
class InjectionResult:
    score: int
    matched: tuple[str, ...]


def scan_injection(text: str) -> InjectionResult:
    score, matched = 0, []
    norm = normalise(text)
    for name, rx, w in INJECTION_PATTERNS:
        if rx.search(norm):
            score += w
            matched.append(name)
    if len(_INVISIBLE.findall(text)) >= 3:  # hidden-text smuggling
        score += 2
        matched.append("invisible_characters")
    if _B64_BLOB.search(text) and re.search(r"\b(?:decode|base64|execute|run)\b", norm):
        score += 2
        matched.append("encoded_payload")
    return InjectionResult(score, tuple(matched))


# --------------------------------------------------------------------------- secrets
SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("aws_access_key", _P(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("private_key", _P(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----(?:[\s\S]*?-----END (?:[A-Z]+ )?PRIVATE KEY-----)?")),
    ("github_token", _P(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("api_key_sk", _P(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("slack_token", _P(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("google_api_key", _P(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("jwt", _P(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("password_assignment", _P(r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|token)\b\s*[:=]\s*[\"']?[^\s\"']{8,}")),
]


def find_secrets(text: str) -> list[tuple[str, int, int]]:
    hits: list[tuple[str, int, int]] = []
    for name, rx in SECRET_PATTERNS:
        for m in rx.finditer(text):
            hits.append((name, m.start(), m.end()))
    return hits


def redact_secrets(text: str) -> tuple[str, list[str]]:
    hits = sorted(find_secrets(text), key=lambda h: (h[1], -(h[2] - h[1])))
    out, pos, kinds = [], 0, []
    for name, s, e in hits:
        if s < pos:
            continue
        out.append(text[pos:s])
        out.append(f"<REDACTED:{name}>")
        kinds.append(name)
        pos = e
    out.append(text[pos:])
    return "".join(out), kinds


# --------------------------------------------------------------------------- tools
def declared_tool_names(data: dict) -> list[str]:
    names: list[str] = []
    for t in data.get("tools") or []:
        if isinstance(t, dict):
            fn = t.get("function") if isinstance(t.get("function"), dict) else t
            if fn.get("name"):
                names.append(str(fn["name"]))
    for f in data.get("functions") or []:
        if isinstance(f, dict) and f.get("name"):
            names.append(str(f["name"]))
    tc = data.get("tool_choice")
    if isinstance(tc, dict):
        fn = tc.get("function")
        if isinstance(fn, dict) and fn.get("name"):
            names.append(str(fn["name"]))
    return names


def message_tool_calls(msg: Any) -> list[dict]:
    """[{name, arguments(str), id}] from an assistant message (dict or object)."""
    get = (lambda o, k: o.get(k)) if isinstance(msg, dict) else (lambda o, k: getattr(o, k, None))
    calls = []
    for tc in get(msg, "tool_calls") or []:
        fn = tc.get("function") if isinstance(tc, dict) else getattr(tc, "function", None)
        fget = (lambda k: fn.get(k)) if isinstance(fn, dict) else (lambda k: getattr(fn, k, None))
        if fn is not None:
            calls.append({"name": str(fget("name") or ""), "arguments": fget("arguments") or "",
                          "id": (tc.get("id") if isinstance(tc, dict) else getattr(tc, "id", None))})
    fc = get(msg, "function_call")
    if fc:
        fget = (lambda k: fc.get(k)) if isinstance(fc, dict) else (lambda k: getattr(fc, k, None))
        if fget("name"):
            calls.append({"name": str(fget("name")), "arguments": fget("arguments") or "", "id": None})
    return calls


def args_digest(arguments: Any) -> str:
    import hashlib
    if isinstance(arguments, str):
        try:
            arguments = json.loads(arguments)
        except ValueError:
            return hashlib.sha256(arguments.encode()).hexdigest()[:16]
    return hashlib.sha256(json.dumps(arguments, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:16]


def iter_text_parts(content: Any) -> Iterable[tuple[int | None, str]]:
    """Yield (part_index or None, text) for str content or list-of-parts content."""
    if isinstance(content, str):
        yield None, content
    elif isinstance(content, list):
        for i, p in enumerate(content):
            if isinstance(p, dict) and isinstance(p.get("text"), str):
                yield i, p["text"]
