"""
Dynamic Application Name & Identity Classifier for NetVisor.

Provides multi-layered heuristics to dynamically extract and cleanse application names from:
1. Web metadata / HTML page titles / Open Graph tags
2. Second-Level Domains (SLD) with multi-tenant hosting awareness
3. Endpoint process binaries
4. TLS Certificate Subject Organization (O) with CDN/CA denylisting
"""

from __future__ import annotations

import re
from typing import Optional

from .domain_utils import get_base_domain, normalize_host

# Multi-tenant / PaaS / Serverless hosting suffixes where the SUBDOMAIN is the actual tenant app
MULTI_TENANT_SUFFIXES = frozenset(
    [
        "vercel.app",
        "herokuapp.com",
        "netlify.app",
        "pages.dev",
        "github.io",
        "gitlab.io",
        "azurewebsites.net",
        "render.com",
        "fly.dev",
        "replit.app",
        "replit.dev",
        "glitch.me",
        "firebaseapp.com",
        "web.app",
        "workers.dev",
        "supabase.co",
        "s3.amazonaws.com",
        "cloudfront.net",
        "mybluemix.net",
        "appspot.com",
        "surge.sh",
        "onrender.com",
    ]
)

# Generic CDN, Cloud, and Certificate Authority organizations to reject in Layer 4
GENERIC_CERT_ORGS = frozenset(
    [
        "cloudflare, inc.",
        "cloudflare",
        "let's encrypt",
        "amazon.com, inc.",
        "amazon",
        "amazon corporate llc",
        "digicert inc",
        "digicert, inc.",
        "google trust services llc",
        "google trust services",
        "sectigo limited",
        "sectigo",
        "fastly, inc.",
        "fastly",
        "akamai technologies, inc.",
        "akamai technologies",
        "cpanel, inc.",
        "microsoft corporation",
        "gandi sas",
        "godaddy.com, inc.",
        "identrust",
        "trustwave holdings, inc.",
        "globalsign nv-sa",
        "globalsign",
        "zerossl",
        "verisign, inc.",
    ]
)

# Known boilerplate words to strip from page titles
TITLE_BOILERPLATE_TOKENS = frozenset(
    [
        "home",
        "login",
        "log in",
        "sign in",
        "signin",
        "sign up",
        "signup",
        "dashboard",
        "official site",
        "official website",
        "welcome",
        "welcome to",
        "portal",
        "online",
        "index",
        "overview",
        "app",
        "web app",
        "the best",
        "free",
        "start",
        "get started",
        "platform",
    ]
)

KNOWN_PROCESS_MAPPINGS = {
    "code.exe": ("Visual Studio Code", "dev"),
    "code": ("Visual Studio Code", "dev"),
    "cursor.exe": ("Cursor", "dev"),
    "cursor": ("Cursor", "dev"),
    "windsurf.exe": ("Windsurf", "dev"),
    "windsurf": ("Windsurf", "dev"),
    "slack.exe": ("Slack", "chat"),
    "slack": ("Slack", "chat"),
    "discord.exe": ("Discord", "chat"),
    "discord": ("Discord", "chat"),
    "spotify.exe": ("Spotify", "streaming"),
    "spotify": ("Spotify", "streaming"),
    "postman.exe": ("Postman", "dev"),
    "postman": ("Postman", "dev"),
    "dbeaver.exe": ("DBeaver", "dev"),
    "dbeaver": ("DBeaver", "dev"),
    "whatsapp.exe": ("WhatsApp", "chat"),
    "whatsapp": ("WhatsApp", "chat"),
    "telegram.exe": ("Telegram", "chat"),
    "telegram": ("Telegram", "chat"),
    "zoom.exe": ("Zoom", "meeting"),
    "zoom": ("Zoom", "meeting"),
    "teams.exe": ("Microsoft Teams", "chat"),
    "teams": ("Microsoft Teams", "chat"),
    "docker.exe": ("Docker Desktop", "dev"),
    "docker": ("Docker Desktop", "dev"),
    "msedge.exe": ("Microsoft Edge", "system"),
    "chrome.exe": ("Google Chrome", "system"),
    "firefox.exe": ("Mozilla Firefox", "system"),
}

CATEGORY_KEYWORDS = {
    "ai": {"ai", "gpt", "bot", "claude", "gemini", "copilot", "perplexity", "deepseek", "groq", "openai", "anthropic", "llm", "diffusion", "midjourney", "neural"},
    "dev": {"github", "gitlab", "stack", "overflow", "npm", "docker", "pypi", "postman", "api", "console", "terminal", "code", "dev", "git", "hub", "repo", "huggingface"},
    "chat": {"chat", "message", "messenger", "talk", "whatsapp", "telegram", "slack", "discord", "signal", "mattermost", "zulip"},
    "meeting": {"meet", "zoom", "teams", "conference", "webex", "hangout", "chime"},
    "streaming": {"video", "stream", "music", "youtube", "netflix", "spotify", "hulu", "twitch", "vimeo", "disney", "prime"},
    "social": {"social", "twitter", "facebook", "instagram", "linkedin", "tiktok", "reddit", "threads", "mastodon", "pinterest"},
    "productivity": {"docs", "sheets", "notion", "linear", "jira", "confluence", "trello", "asana", "canva", "figma", "miro", "airtable", "clickup"},
    "cloud": {"aws", "azure", "cloud", "gcp", "hosting", "server", "compute", "storage", "database", "supabase", "firebase", "vercel", "render"},
}


def _split_compound_name(name: str) -> str:
    """Splits kebab-case, snake_case, or camelCase into space-separated title words."""
    if not name:
        return ""
    # Replace separators with spaces
    s = re.sub(r"[-_.]+", " ", name)
    # Split camelCase (e.g. HuggingFace -> Hugging Face, DeepSeek -> Deep Seek, ElevenLabs -> Eleven Labs)
    s = re.sub(r"([a-z])([A-Z])", r"\1 \2", s)
    # Split digits if attached to letters (e.g. web3 -> web 3)
    s = re.sub(r"([a-zA-Z])([0-9]{2,})", r"\1 \2", s)

    # Clean and capitalize words
    words = []
    for word in s.split():
        w = word.strip()
        if not w:
            continue
        if len(w) <= 3 and w.isalpha() and w.lower() not in {"and", "for", "the", "in", "of", "to"}:
            words.append(w.upper())
        else:
            words.append(w.capitalize())
    return " ".join(words)


def infer_app_category(name: str, domain: str = "", context: str = "") -> str:
    combined = f"{name} {domain} {context}".lower()
    for category, keywords in CATEGORY_KEYWORDS.items():
        if any(kw in combined for kw in keywords):
            return category
    return "web"


def clean_title_to_app_name(title: str | None) -> Optional[str]:
    """
    Extracts brand / application name from an HTML title string.
    Example: 'Linear – A better way to build products' -> 'Linear'
    Example: 'Notion – Your connected workspace' -> 'Notion'
    Example: 'Claude' -> 'Claude'
    """
    if not title:
        return None

    raw = str(title).strip()
    if not raw or len(raw) < 2:
        return None

    # Delimiters separating brand from page title/tagline
    chunks = re.split(r"\s*[–—|•·»/:\-]\s*", raw)
    candidates = [c.strip() for c in chunks if c.strip()]
    if not candidates:
        return None

    # Look for candidate chunk that is not boilerplate
    for c in candidates:
        lowered = c.lower()
        if lowered in TITLE_BOILERPLATE_TOKENS or any(b == lowered for b in TITLE_BOILERPLATE_TOKENS):
            continue
        # If candidate starts with 'Welcome to ' or 'Sign in to ', extract the trailing name
        for prefix in ("welcome to ", "sign in to ", "log in to ", "introducing "):
            if lowered.startswith(prefix):
                c = c[len(prefix):].strip()
                break
        if len(c) >= 2 and len(c) <= 40:
            return _split_compound_name(c)

    # Fallback to the first candidate if it is reasonable length
    first = candidates[0]
    if len(first) <= 40:
        return _split_compound_name(first)
    return None


def clean_domain_to_app_name(host_or_domain: str | None) -> tuple[str, str]:
    """
    Extracts clean application name and category from a domain with multi-tenant hosting awareness.
    Example: 'my-crm.vercel.app' -> ('My Crm', 'productivity')
    Example: 'groq.com' -> ('Groq', 'ai')
    Example: 'huggingface.co' -> ('Hugging Face', 'dev')
    """
    normalized = normalize_host(host_or_domain)
    if not normalized:
        return "Unknown", "web"

    # Check multi-tenant suffixes
    for suffix in MULTI_TENANT_SUFFIXES:
        if normalized == suffix:
            return _split_compound_name(suffix.split(".")[0]), "cloud"
        if normalized.endswith(f".{suffix}"):
            # Extract subdomain prefix
            subdomain = normalized[: -(len(suffix) + 1)]
            # Take the leftmost tenant identifier if nested
            tenant_token = subdomain.split(".")[-1]
            app_name = _split_compound_name(tenant_token)
            category = infer_app_category(app_name, normalized)
            return app_name or "Unknown", category

    base_domain = get_base_domain(normalized) or normalized
    root_label = base_domain.split(".", 1)[0]
    if root_label.lower() in {"example", "test", "invalid", "localhost", "localdomain"}:
        return "Unknown", "web"

    # Strip generic prefixes or suffixes
    for suffix in ("hq", "app", "labs", "tech", "io", "ai", "platform"):
        if root_label.lower().endswith(suffix) and len(root_label) > len(suffix) + 3:
            root_label = root_label[: -len(suffix)]
            break

    app_name = _split_compound_name(root_label)
    category = infer_app_category(app_name, normalized)
    return app_name or "Unknown", category


def clean_process_to_app_name(process_name: str | None) -> tuple[str, str]:
    """
    Extracts clean application name from process binary.
    Example: 'code.exe' -> ('Visual Studio Code', 'dev')
    Example: 'spotify.exe' -> ('Spotify', 'streaming')
    """
    if not process_name:
        return "Unknown", "web"

    cleaned = str(process_name).strip().lower()
    if cleaned in KNOWN_PROCESS_MAPPINGS:
        return KNOWN_PROCESS_MAPPINGS[cleaned]

    base = cleaned.replace(".exe", "").replace(".bin", "").strip()
    app_name = _split_compound_name(base)
    category = infer_app_category(app_name)
    return app_name or "Unknown", category


def clean_cert_org_to_app_name(org_name: str | None) -> Optional[str]:
    """
    Extracts clean application name from TLS Certificate Subject Organization (O).
    Rejects generic CA / CDN issuers.
    Example: 'Anthropic, PBC' -> 'Anthropic'
    Example: 'OpenAI, L.L.C.' -> 'OpenAI'
    Example: 'Cloudflare, Inc.' -> None (rejected)
    """
    if not org_name:
        return None

    raw = str(org_name).strip()
    lowered = raw.lower()
    if not raw or lowered in GENERIC_CERT_ORGS or any(denied in lowered for denied in GENERIC_CERT_ORGS):
        return None

    # Strip legal entity suffixes
    clean = re.sub(
        r",?\s*(?:inc\.?|llc\.?|l\.l\.c\.?|ltd\.?|limited|pbc\.?|p\.b\.c\.?|corp\.?|corporation|gmbh|ab\.?|s\.a\.?|co\.,?\s*ltd\.?)$",
        "",
        raw,
        flags=re.IGNORECASE,
    ).strip()


    if len(clean) >= 2 and len(clean) <= 64:
        return clean
    return None
