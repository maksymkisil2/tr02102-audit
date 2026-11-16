"""Interface languages.

The English text is the message id, as in gettext: a missing translation
shows the English original instead of a placeholder. Translations live in
``locale/<code>.json``. Rule texts and references are quoted from English
standards and stay in English in every language.
"""

import json
from functools import cache
from importlib import resources
from typing import Any

LANGUAGES: dict[str, str] = {
    "en": "English",
    "de": "Deutsch",
    "uk": "Українська",
    "ru": "Русский",
}
DEFAULT = "en"


@cache
def catalog(lang: str) -> dict[str, str]:
    if lang == DEFAULT or lang not in LANGUAGES:
        return {}
    path = resources.files("tr02102_audit.web").joinpath("locale", f"{lang}.json")
    data: dict[str, str] = json.loads(path.read_text(encoding="utf-8"))
    return data


def translate(lang: str, text: str, **params: Any) -> str:
    template = catalog(lang).get(text, text)
    return template % params if params else template


def from_header(accept_language: str) -> str | None:
    """Best supported language of an Accept-Language header, or None."""
    choices: list[tuple[float, str]] = []
    for part in accept_language.split(",")[:20]:
        tag, _, weight = part.strip().partition(";q=")
        code = tag.split("-")[0].lower()
        if code not in LANGUAGES:
            continue
        try:
            quality = float(weight) if weight else 1.0
        except ValueError:
            quality = 0.0
        choices.append((quality, code))
    choices.sort(key=lambda c: -c[0])
    return choices[0][1] if choices else None
