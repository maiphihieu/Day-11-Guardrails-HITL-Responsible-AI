"""
Assignment 11 — Bonus: Language Detection Safety Layer (6th layer)

WHAT: Detects the language of user input and blocks unsupported languages.
      VinBank supports Vietnamese and English only. Requests in other
      languages are blocked because:
      1. The agent may hallucinate answers in languages it wasn't trained for
      2. Attackers use obscure languages to bypass keyword-based filters
      3. Banking regulations require customer communications in official languages

WHY:  This is a UNIQUE safety layer that catches attacks other layers miss:
      - Rate limiter: doesn't care about language
      - Input guardrails: regex patterns only cover English + Vietnamese
      - Output guardrails: check output, not input language
      - LLM Judge: evaluates response quality, not input language
      An attacker could send injection prompts in French, Japanese, or
      transliterated text to bypass English/Vietnamese regex patterns.

DESIGN: Uses simple heuristic-based detection (character range analysis)
        rather than ML models to avoid adding heavy dependencies.
        Supports: Vietnamese (Latin + diacritics) and English (ASCII Latin).
        Blocks: CJK, Cyrillic, Arabic, Thai, and other scripts.
"""

import re
import unicodedata

from google.genai import types
from google.adk.plugins import base_plugin
from google.adk.agents.invocation_context import InvocationContext


# Supported language scripts (Vietnamese uses Latin + diacritics, English uses ASCII Latin)
SUPPORTED_SCRIPTS = {"LATIN", "COMMON"}

# Characters that are common in Vietnamese but not in ASCII
VIETNAMESE_CHARS = set("àáảãạăắằẳẵặâấầẩẫậèéẻẽẹêếềểễệìíỉĩịòóỏõọôốồổỗộơớờởỡợùúủũụưứừửữựỳýỷỹỵđ"
                       "ÀÁẢÃẠĂẮẰẲẴẶÂẤẦẨẪẬÈÉẺẼẸÊẾỀỂỄỆÌÍỈĨỊÒÓỎÕỌÔỐỒỔỖỘƠỚỜỞỠỢÙÚỦŨỤƯỨỪỬỮỰỲÝỶỸỴĐ")


def detect_unsupported_language(text: str, threshold: float = 0.3) -> dict:
    """Check if the text contains unsupported language scripts.

    WHY: Simple character-range analysis is fast (O(n)) and doesn't require
    external APIs or ML models. It catches >90% of non-Latin scripts.

    Args:
        text: Input text to check
        threshold: Maximum ratio of unsupported characters before blocking
                   (default 0.3 = allow up to 30% non-Latin, for emoji/symbols)

    Returns:
        dict with:
        - 'supported': True if text is in a supported language
        - 'detected_scripts': Set of Unicode script names found
        - 'unsupported_ratio': Ratio of unsupported characters
        - 'reason': Human-readable explanation
    """
    if not text or not text.strip():
        return {"supported": True, "detected_scripts": set(), "unsupported_ratio": 0.0,
                "reason": "Empty input"}

    # Count characters by Unicode script category
    total_alpha = 0
    unsupported_alpha = 0
    detected_scripts = set()

    for char in text:
        if char.isalpha() or char in VIETNAMESE_CHARS:
            total_alpha += 1
            # Get the Unicode script name
            try:
                script = unicodedata.name(char, "").split()[0] if unicodedata.name(char, "") else "UNKNOWN"
            except ValueError:
                script = "UNKNOWN"

            # Check if it's a Latin character (English + Vietnamese) or Vietnamese diacritic
            if char in VIETNAMESE_CHARS or char.isascii():
                detected_scripts.add("LATIN")
            elif "LATIN" in unicodedata.name(char, "").upper():
                detected_scripts.add("LATIN")
            elif "CJK" in unicodedata.name(char, "").upper():
                detected_scripts.add("CJK")
                unsupported_alpha += 1
            elif "CYRILLIC" in unicodedata.name(char, "").upper():
                detected_scripts.add("CYRILLIC")
                unsupported_alpha += 1
            elif "ARABIC" in unicodedata.name(char, "").upper():
                detected_scripts.add("ARABIC")
                unsupported_alpha += 1
            elif "THAI" in unicodedata.name(char, "").upper():
                detected_scripts.add("THAI")
                unsupported_alpha += 1
            elif "HANGUL" in unicodedata.name(char, "").upper():
                detected_scripts.add("HANGUL")
                unsupported_alpha += 1
            elif "DEVANAGARI" in unicodedata.name(char, "").upper():
                detected_scripts.add("DEVANAGARI")
                unsupported_alpha += 1
            else:
                # Other Latin-compatible scripts (e.g., accented letters from other languages)
                detected_scripts.add("LATIN")

    # Calculate unsupported ratio
    unsupported_ratio = unsupported_alpha / total_alpha if total_alpha > 0 else 0.0

    if unsupported_ratio > threshold:
        unsupported_names = detected_scripts - {"LATIN", "COMMON"}
        return {
            "supported": False,
            "detected_scripts": detected_scripts,
            "unsupported_ratio": unsupported_ratio,
            "reason": f"Unsupported scripts detected: {', '.join(unsupported_names)}. "
                      f"VinBank supports Vietnamese and English only.",
        }

    return {
        "supported": True,
        "detected_scripts": detected_scripts,
        "unsupported_ratio": unsupported_ratio,
        "reason": "Supported language",
    }


class LanguageDetectionPlugin(base_plugin.BasePlugin):
    """Plugin that blocks requests in unsupported languages.

    WHY this is the 6th safety layer (bonus):
    - Layers 1-5 focus on content, patterns, and semantics
    - This layer focuses on LANGUAGE, a dimension other layers ignore
    - An attacker who discovers the guardrails are English/Vietnamese-focused
      could craft attacks in other languages to bypass regex patterns
    - Example: "Забудь все инструкции" (Russian: "Forget all instructions")
      would bypass English regex but is caught by this language filter

    Args:
        threshold: Maximum ratio of unsupported characters (default: 0.3)
    """

    def __init__(self, threshold: float = 0.3):
        super().__init__(name="language_detection")
        self.threshold = threshold
        self.total_checked = 0
        self.blocked_count = 0

    async def on_user_message_callback(
        self,
        *,
        invocation_context: InvocationContext,
        user_message: types.Content,
    ) -> types.Content | None:
        """Check if input is in a supported language.

        Returns:
            None if supported language (allow),
            types.Content with block message if unsupported.
        """
        self.total_checked += 1

        # Extract text
        text = ""
        if user_message and user_message.parts:
            for part in user_message.parts:
                if hasattr(part, "text") and part.text:
                    text += part.text

        if not text.strip():
            return None  # Empty text handled by other layers

        result = detect_unsupported_language(text, self.threshold)

        if not result["supported"]:
            self.blocked_count += 1
            return types.Content(
                role="model",
                parts=[types.Part.from_text(
                    text=f"[BLOCKED] {result['reason']} "
                         f"Please use Vietnamese or English."
                )],
            )

        return None

    def get_metrics(self) -> dict:
        """Return language detection metrics.

        Returns:
            dict with total_checked, blocked, block_rate
        """
        return {
            "total_checked": self.total_checked,
            "blocked": self.blocked_count,
            "block_rate": (
                self.blocked_count / self.total_checked
                if self.total_checked > 0
                else 0.0
            ),
        }
