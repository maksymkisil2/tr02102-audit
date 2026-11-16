"""Every text of the interface has a translation in every language."""

import re
from pathlib import Path

import pytest

from tr02102_audit import rating
from tr02102_audit.standards import CATEGORIES, CONTROLS
from tr02102_audit.web import i18n, views_account, views_public
from tr02102_audit.web.frameworks import FRAMEWORKS

WEB = Path(i18n.__file__).parent
_IN_TEMPLATE = re.compile(r"""_\(\s*(?:'((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)")""")
_IN_PYTHON = re.compile(r"""\b(?:tr|notice)\(\s*"((?:[^"\\]|\\.)*)\"""")

# Texts that reach the translation function through a variable.
INDIRECT = [
    *CONTROLS.values(),
    *CATEGORIES.values(),
    *(c.title for c in (*rating.load().caps, *rating.load().bonus)),
    *views_public.DEMOS.values(),
    *views_account.TARGET_PROBLEMS.values(),
    *(f.asks for f in FRAMEWORKS),
    # verdicts and finding states
    "Conforms",
    "Conforms, with warnings",
    "Does not conform",
    "Incomplete",
    "Met",
    "Not met",
    "Warning",
    "Unknown",
    "Not applicable",
    # probe and job states
    "accepted",
    "refused",
    "inconclusive",
    "queued",
    "running",
    "done",
    "error",
    # labels passed through loops in templates
    "Overview",
    "Audit log",
    "Checks",
    "Accounts",
    "Extended master secret",
    "Secure renegotiation",
    # password rules
    "The password needs at least %(n)s characters.",
    "The password is too long.",
    "The password must differ from the login name.",
]


def message_ids() -> set[str]:
    found = set(INDIRECT)
    for template in (WEB / "templates").glob("*.html"):
        for single, double in _IN_TEMPLATE.findall(template.read_text("utf-8")):
            found.add((single or double).replace("\\'", "'"))
    for module in WEB.glob("*.py"):
        found.update(_IN_PYTHON.findall(module.read_text("utf-8")))
    return found


@pytest.mark.parametrize("lang", [code for code in i18n.LANGUAGES if code != i18n.DEFAULT])
def test_catalog_is_complete_and_has_no_leftovers(lang: str) -> None:
    catalog = i18n.catalog(lang)
    ids = message_ids()
    assert sorted(ids - set(catalog)) == [], f"{lang}: texts without a translation"
    assert sorted(set(catalog) - ids) == [], f"{lang}: translations nothing uses"


@pytest.mark.parametrize("lang", [code for code in i18n.LANGUAGES if code != i18n.DEFAULT])
def test_translations_keep_their_placeholders(lang: str) -> None:
    placeholder = re.compile(r"%\((\w+)\)s")
    for source, translated in i18n.catalog(lang).items():
        assert sorted(placeholder.findall(source)) == sorted(placeholder.findall(translated)), (
            source
        )
        assert translated.strip(), source


def test_language_is_chosen_from_the_browser_header() -> None:
    assert i18n.from_header("de-DE,de;q=0.9,en;q=0.8") == "de"
    assert i18n.from_header("fr-FR,uk;q=0.7,en;q=0.9") == "en"
    assert i18n.from_header("fr-FR, es;q=0.5") is None
    assert i18n.from_header("") is None


def test_missing_translation_falls_back_to_english() -> None:
    assert i18n.translate("de", "A text nobody translated") == "A text nobody translated"
    assert i18n.translate("en", "%(n)s days", n=3) == "3 days"
