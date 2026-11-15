"""Zero-I/O pure functions for anti-noise share URL, password, and -n flag parsing (§5.1).

Strict Dependency Boundary:
Depends ONLY on Python 3.12 standard library and `models`.
Structurally satisfies `providers.base.ShareRecognizer` without importing `providers/`.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import replace
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit

from yunbot.models import ParsedInput, ParsedShareItem, RecognizedShareUrl

# Leading Telegram command: /cmd or /cmd@BotUsername followed by whitespace or end-of-string.
_COMMAND_RE: re.Pattern[str] = re.compile(
    r"^\s*/([A-Za-z0-9_]{1,32})(?:@[A-Za-z0-9_]{3,64})?(?:\s+([\s\S]*)|$)"
)

# Standalone -n direct transfer flag bounded by whitespace or string boundaries (§5.1).
_NO_SUBDIR_RE: re.Pattern[str] = re.compile(r"(?:^|\s)-n(?=\s|$)")

# Pure-ASCII non-backtracking candidate URL pattern (§5.1) — immune to ReDoS.
_URL_RE: re.Pattern[str] = re.compile(r"(?i:https?)://[^\s<>\"'`()\u0080-\U0010ffff]+")

# Trailing CN/EN punctuation & brackets stripped from raw URL matches.
_TRAILING_URL_PUNCTUATION: str = "，。！？；：、）】》”’「』,.!?;:)]}'\"["

# Possessive / linear-time labeled code patterns (zero catastrophic backtracking).
_CN_CODE_KEYWORDS: tuple[str, ...] = ("提取码", "访问码", "分享码", "密码")
_CN_LABELED_CODE_RE: re.Pattern[str] = re.compile(
    r"(?:提取码|访问码|分享码|密码)(?:[ \t]{0,16}(?:为|是))?"
    r"[ \t]{0,32}[:：=]?[ \t\r\n]{0,32}([A-Za-z0-9]{4,12})(?![A-Za-z0-9_-])"
)
_EN_LABELED_CODE_RE: re.Pattern[str] = re.compile(
    r"(?i:pwd|pass_code|passcode|code)(?:[ \t]{1,16}(?i:is))?"
    r"(?:[ \t]{0,32}[:：=][ \t\r\n]{0,32}|[ \t]{1,32})([A-Za-z0-9]{4,12})(?![A-Za-z0-9_-])"
)

# Pure-ASCII 4-char token scanner (keeps C-level ASCII fast path); CJK neighbor check runs in O(1).
_EN_CODE_KEYWORDS: tuple[str, ...] = ("pwd", "code")
_STANDALONE_ASCII_4_BYTES_RE: re.Pattern[bytes] = re.compile(
    rb"(?<![A-Za-z0-9_/.-])[A-Za-z0-9]{4}(?![A-Za-z0-9_/.-])"
)
_STANDALONE_ASCII_4_RE: re.Pattern[str] = re.compile(
    r"(?<![A-Za-z0-9_/.-])[A-Za-z0-9]{4}(?![A-Za-z0-9_/.-])"
)
_EN_LABEL_PREV_DISALLOWED: frozenset[str] = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
)
# Noise URL-prefix label like "link: <url>" that leaves "link:" before the stripped URL span.
_NOISE_LINK_LABEL_RE: re.Pattern[str] = re.compile(r"(?i:link)[ \t]*+[:：=]")
# Official share copywriting title blocks (only stripped for unlabeled fallback when a URL exists).
_CJK_TITLE_BRACKETS_RE: re.Pattern[str] = re.compile(
    r"「[^「」\r\n]{1,300}」|『[^『』\r\n]{1,300}』|《[^《》\r\n]{1,300}》"
)
_SHARE_FILENAME_LINE_RE: re.Pattern[str] = re.compile(
    r"(?:^|[\r\n])[^\r\n]{0,80}?分享的文件[ \t]*+[:：][^\r\n]*"
)

_SHARE_ID_GENERIC_RE: re.Pattern[str] = re.compile(r"^[A-Za-z0-9_-]{4,128}$")
_QUARK_SHARE_ID_RE: re.Pattern[str] = re.compile(r"^[A-Za-z0-9_-]{4,64}$")
_CODE_4_RE: re.Pattern[str] = re.compile(r"^[A-Za-z0-9]{4}$")
_CODE_4_TO_12_RE: re.Pattern[str] = re.compile(r"^[A-Za-z0-9]{4,12}$")
_QUARK_FID_SEGMENT_RE: re.Pattern[str] = re.compile(r"^([0-9a-fA-F]{32})(?:-.*)?$")


def _split_and_validate_http_url(url: str, allowed_hosts: frozenset[str]) -> Any | None:
    """Validate HTTP/HTTPS scheme, standard port, absence of credentials, and exact hostname."""
    if not isinstance(url, str) or not url or len(url) > 4096:
        return None
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        return None

    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        return None
    allowed_ports = (None, 80) if scheme == "http" else (None, 443)
    if parsed.username or parsed.password or port not in allowed_ports:
        return None
    if parsed.hostname not in allowed_hosts:
        return None
    return parsed


def _extract_single_query_code(
    values: Sequence[str],
    pattern: re.Pattern[str],
) -> tuple[bool, str | None]:
    """Validate optional query password values; returns (ok, code)."""
    non_empty = [v for v in values if v != ""]
    if not non_empty:
        return True, None
    unique = set(non_empty)
    if len(unique) != 1:
        return False, None
    candidate = non_empty[0]
    if not pattern.fullmatch(candidate):
        return False, None
    return True, candidate


class BaiduShareRecognizer:
    """Pure share URL recognizer for Baidu Netdisk (`pan.baidu.com`)."""

    provider_id: str = "baidu"
    _HOSTS: frozenset[str] = frozenset({"pan.baidu.com"})

    def recognize(self, url: str) -> RecognizedShareUrl | None:
        parsed = _split_and_validate_http_url(url, self._HOSTS)
        if parsed is None:
            return None

        query = parse_qs(parsed.query, keep_blank_values=True)
        path = parsed.path.rstrip("/") if parsed.path != "/" else parsed.path

        external_id: str | None = None
        if path.startswith("/s/1") and path.count("/") == 2:
            # Baidu /s/1<surl> maps to verify/list `surl` without the leading '1'.
            external_id = path.removeprefix("/s/1")
        elif path == "/share/init":
            surl_values = [v for v in query.get("surl", []) if v != ""]
            if len(set(surl_values)) == 1:
                external_id = surl_values[0]

        if external_id is None or not _SHARE_ID_GENERIC_RE.fullmatch(external_id):
            return None

        ok, embedded_code = _extract_single_query_code(query.get("pwd", []), _CODE_4_RE)
        if not ok:
            return None

        normalized_url = f"https://pan.baidu.com/share/init?{urlencode({'surl': external_id})}"
        return RecognizedShareUrl(
            provider_id=self.provider_id,
            normalized_url=normalized_url,
            external_id=external_id,
            embedded_code=embedded_code,
        )


class PikPakShareRecognizer:
    """Pure share URL recognizer for PikPak (`mypikpak.com` / `www.mypikpak.com`)."""

    provider_id: str = "pikpak"
    _HOSTS: frozenset[str] = frozenset({"mypikpak.com", "www.mypikpak.com"})

    def recognize(self, url: str) -> RecognizedShareUrl | None:
        parsed = _split_and_validate_http_url(url, self._HOSTS)
        if parsed is None:
            return None

        parts = [seg for seg in parsed.path.split("/") if seg]
        if len(parts) != 2 or parts[0] != "s":
            return None
        share_id = parts[1]
        if not _SHARE_ID_GENERIC_RE.fullmatch(share_id):
            return None

        query = parse_qs(parsed.query, keep_blank_values=True)
        pwd_candidates = [*query.get("pwd", []), *query.get("pass_code", [])]
        ok, embedded_code = _extract_single_query_code(pwd_candidates, _CODE_4_TO_12_RE)
        if not ok:
            return None

        normalized_url = f"https://mypikpak.com/s/{share_id}"
        return RecognizedShareUrl(
            provider_id=self.provider_id,
            normalized_url=normalized_url,
            external_id=share_id,
            embedded_code=embedded_code,
        )


class QuarkShareRecognizer:
    """Pure share URL recognizer strictly restricted to official `pan.quark.cn` and `quark.cn`."""

    provider_id: str = "quark"
    _HOSTS: frozenset[str] = frozenset({"pan.quark.cn", "quark.cn"})

    def recognize(self, url: str) -> RecognizedShareUrl | None:
        parsed = _split_and_validate_http_url(url, self._HOSTS)
        if parsed is None:
            return None

        parts = [seg for seg in parsed.path.split("/") if seg]
        if len(parts) != 2 or parts[0] != "s":
            return None
        pwd_id = parts[1]
        if not _QUARK_SHARE_ID_RE.fullmatch(pwd_id):
            return None

        query = parse_qs(parsed.query, keep_blank_values=True)
        pwd_values = list(query.get("pwd", []))

        sub_dir_fid = "0"
        if parsed.fragment:
            frag_path, _, frag_query = parsed.fragment.partition("?")
            if frag_query:
                frag_qs = parse_qs(frag_query, keep_blank_values=True)
                pwd_values.extend(frag_qs.get("pwd", []))
            frag_segments = [seg for seg in frag_path.split("/") if seg]
            if (
                len(frag_segments) >= 3
                and frag_segments[0] == "list"
                and frag_segments[1] == "share"
            ):
                for seg in frag_segments[2:]:
                    fid_match = _QUARK_FID_SEGMENT_RE.fullmatch(seg)
                    if fid_match is not None:
                        sub_dir_fid = fid_match.group(1).lower()

        ok, embedded_code = _extract_single_query_code(pwd_values, _CODE_4_RE)
        if not ok:
            return None

        if sub_dir_fid != "0":
            normalized_url = f"https://pan.quark.cn/s/{pwd_id}#/list/share/{sub_dir_fid}"
        else:
            normalized_url = f"https://pan.quark.cn/s/{pwd_id}"

        return RecognizedShareUrl(
            provider_id=self.provider_id,
            normalized_url=normalized_url,
            external_id=pwd_id,
            embedded_code=embedded_code,
            sub_dir_fid=sub_dir_fid,
        )


DEFAULT_RECOGNIZERS: tuple[BaiduShareRecognizer, PikPakShareRecognizer, QuarkShareRecognizer] = (
    BaiduShareRecognizer(),
    PikPakShareRecognizer(),
    QuarkShareRecognizer(),
)


def strip_command_prefix(text: str) -> tuple[str | None, str]:
    """Strip leading `/command` or `/command@BotUsername`, returning `(command_lower, rest)`."""
    if not isinstance(text, str):
        return None, ""
    if not text.lstrip().startswith("/"):
        return None, text
    match = _COMMAND_RE.match(text)
    if match is None:
        return None, text
    command_lower = match.group(1).lower()
    remaining = match.group(2) if match.group(2) is not None else ""
    return command_lower, remaining


def _trim_candidate_url(raw_url: str) -> str:
    """Strip trailing CN/EN punctuation and normalize valid http:// URLs to https://."""
    trimmed = raw_url.rstrip(_TRAILING_URL_PUNCTUATION)
    if trimmed.lower().startswith("https://"):
        return "https://" + trimmed[8:]
    if trimmed.lower().startswith("http://"):
        try:
            split = urlsplit(trimmed)
            port = split.port
        except ValueError:
            return trimmed
        if port is None:
            return "https://" + trimmed[7:]
        if port == 80 and split.hostname:
            rest = trimmed[7:]
            host_port_prefix = f"{split.hostname}:80"
            if rest.lower().startswith(host_port_prefix):
                return "https://" + split.hostname + rest[len(host_port_prefix) :]
    return trimmed


def _strip_noise_link_labels(text: str) -> str:
    if "link" not in text.lower():
        return text

    def _repl(match: re.Match[str]) -> str:
        idx = match.start()
        if idx > 0 and text[idx - 1] in _EN_LABEL_PREV_DISALLOWED:
            return match.group(0)
        return " "

    return _NOISE_LINK_LABEL_RE.sub(_repl, text)


def _extract_labeled_codes(non_url_text: str) -> list[str]:
    """Extract distinct explicitly labeled extraction codes (`提取码/密码/pwd/code`)."""
    labeled: list[str] = []
    if any(kw in non_url_text for kw in _CN_CODE_KEYWORDS):
        for match in _CN_LABELED_CODE_RE.finditer(non_url_text):
            code = match.group(1)
            if code not in labeled:
                labeled.append(code)
    lowered_non_url = non_url_text.lower()
    if any(kw in lowered_non_url for kw in _EN_CODE_KEYWORDS):
        for match in _EN_LABELED_CODE_RE.finditer(non_url_text):
            start_idx = match.start()
            if start_idx > 0 and non_url_text[start_idx - 1] in _EN_LABEL_PREV_DISALLOWED:
                continue
            code = match.group(1)
            if code not in labeled:
                labeled.append(code)
    return labeled


def _extract_text_codes(
    non_url_text: str,
    *,
    has_embedded_code: bool,
    has_url: bool = False,
) -> list[str]:
    """Extract distinct extraction code candidates from non-URL text."""
    labeled = _extract_labeled_codes(non_url_text)
    if labeled:
        return labeled

    cleaned = _strip_noise_link_labels(non_url_text)
    if has_url:
        if "「" in cleaned or "『" in cleaned or "《" in cleaned:
            cleaned = _CJK_TITLE_BRACKETS_RE.sub(" ", cleaned)
        if "分享的文件" in cleaned:
            cleaned = _SHARE_FILENAME_LINE_RE.sub(" ", cleaned)
    if _STANDALONE_ASCII_4_BYTES_RE.search(cleaned.encode("utf-8")) is None:
        return []
    cleaned_len = len(cleaned)
    standalone: list[str] = []
    for match in _STANDALONE_ASCII_4_RE.finditer(cleaned):
        s, e = match.span()
        if s > 0 and ("\u4e00" <= cleaned[s - 1] <= "\u9fff"):
            continue
        if e < cleaned_len and ("\u4e00" <= cleaned[e] <= "\u9fff"):
            continue
        token = match.group(0)
        if token not in standalone:
            standalone.append(token)
            if not has_embedded_code and len(standalone) > 1:
                return standalone

    # Avoid false-positive conflicts against multi-word English prose when URL already
    # embeds `?pwd=xxxx`, while still flagging bare trailing codes like `<url>?pwd=ab12 xy99`.
    if has_embedded_code and standalone:
        stripped_words = [
            w
            for w in re.split(r"[\s,.;:!?()\[\]{}，。！？；：、（）【】《》“”‘’\"']+", cleaned)
            if w
        ]
        if len(stripped_words) > 1 or (
            len(stripped_words) == 1 and stripped_words[0] != standalone[0]
        ):
            return []

    return standalone


def _extract_batch_segment_codes(segment: str) -> list[str]:
    """Extract code candidates belonging to one URL's trailing segment in multi-link text.

    Accepts labeled codes (`提取码: ab12`, `pwd=ab12`, etc.) anywhere in `segment`, or bare
    4-char codes on the exact same line immediately following the URL (`<url> ab12`) so
    next-line headings like `EP02` before the following URL are never mistaken for codes.
    """
    labeled = _extract_labeled_codes(segment)
    if labeled:
        return labeled

    same_line = segment.splitlines()[0] if segment else ""
    if not same_line.strip():
        return []
    cleaned_line = _strip_noise_link_labels(same_line)
    if "「" in cleaned_line or "『" in cleaned_line or "《" in cleaned_line:
        cleaned_line = _CJK_TITLE_BRACKETS_RE.sub(" ", cleaned_line)
    words = [
        w
        for w in re.split(r"[\s,.;:!?()\[\]{}，。！？；：、（）【】《》“”‘’\"']+", cleaned_line)
        if w
    ]
    if not words or not all(_CODE_4_RE.fullmatch(w) for w in words):
        return []

    unique_codes: list[str] = []
    for w in words:
        if w not in unique_codes:
            unique_codes.append(w)
    return unique_codes


def _strip_url_spans(
    text: str,
    start: int,
    end: int,
    noise_spans: Sequence[tuple[int, int]],
) -> str:
    """Slice `text[start:end]` while replacing any noise URL spans inside it with spaces."""
    if start >= end:
        return ""
    parts: list[str] = []
    cursor = start
    for ns, ne in noise_spans:
        if ne <= cursor:
            continue
        if ns >= end:
            break
        cut_start = max(cursor, ns)
        cut_end = min(end, ne)
        if cut_start > cursor:
            parts.append(text[cursor:cut_start])
        parts.append(" ")
        cursor = cut_end
    if cursor < end:
        parts.append(text[cursor:end])
    return "".join(parts)


def parse_transfer_text(
    text: str,
    recognizers: Sequence[Any] = DEFAULT_RECOGNIZERS,
    *,
    forced_provider_id: str | None = None,
) -> ParsedInput:
    """Parse noisy user text into `-n` flag and one or more recognized share links + codes."""
    if not isinstance(text, str) or not text.strip():
        return ParsedInput()

    _, working = strip_command_prefix(text)

    # 1. Extract standalone -n flag(s) before URL and code extraction.
    no_subdir = False
    if "-n" in working and _NO_SUBDIR_RE.search(working) is not None:
        no_subdir = True
        working = _NO_SUBDIR_RE.sub(" ", working)

    # 2. Extract candidate URLs with ASCII-bounded non-backtracking regex and strip URL spans.
    url_matches = list(_URL_RE.finditer(working)) if "://" in working else []
    all_recognizers = tuple(recognizers)

    candidate_urls: list[str] = []
    non_url_parts: list[str] = []
    recognized_occurrences: list[tuple[int, int, RecognizedShareUrl]] = []
    noise_url_spans: list[tuple[int, int]] = []
    last_idx = 0

    for m in url_matches:
        s, e = m.start(), m.end()
        non_url_parts.append(working[last_idx:s])
        non_url_parts.append(" ")
        last_idx = e
        trimmed = _trim_candidate_url(m.group(0))
        if not trimmed:
            noise_url_spans.append((s, e))
            continue
        candidate_urls.append(trimmed)
        matched_rec: RecognizedShareUrl | None = None
        for recognizer in all_recognizers:
            rec = recognizer.recognize(trimmed)
            if rec is not None:
                matched_rec = rec
                break
        if matched_rec is not None:
            recognized_occurrences.append((s, e, matched_rec))
        else:
            noise_url_spans.append((s, e))

    non_url_parts.append(working[last_idx:])
    non_url_text = "".join(non_url_parts)

    # 3. Zero recognized cloud shares -> either invalid URL candidate or bare code/prose.
    if not recognized_occurrences:
        if candidate_urls:
            return ParsedInput(no_subdir=no_subdir, invalid_link_candidate=True)
        text_codes = _extract_text_codes(
            non_url_text,
            has_embedded_code=False,
            has_url=False,
        )
        if len(text_codes) > 1:
            return ParsedInput(no_subdir=no_subdir, ambiguous=True)
        return ParsedInput(
            no_subdir=no_subdir,
            code=text_codes[0] if text_codes else None,
        )

    # 4. Single recognized cloud share occurrence -> exact single-link semantics.
    if len(recognized_occurrences) == 1:
        only_share = recognized_occurrences[0][2]
        if forced_provider_id is not None and only_share.provider_id != forced_provider_id:
            return ParsedInput(no_subdir=no_subdir, invalid_link_candidate=True)

        has_embedded = bool(only_share.embedded_code)
        text_codes = _extract_text_codes(
            non_url_text,
            has_embedded_code=has_embedded,
            has_url=True,
        )
        if len(text_codes) > 1:
            return ParsedInput(no_subdir=no_subdir, ambiguous=True)
        text_code = text_codes[0] if text_codes else None
        if only_share.embedded_code and text_code and only_share.embedded_code != text_code:
            return ParsedInput(no_subdir=no_subdir, ambiguous=True)
        final_code = only_share.embedded_code or text_code
        item = ParsedShareItem(share=only_share, code=final_code)
        return ParsedInput(
            no_subdir=no_subdir,
            share=only_share,
            code=final_code,
            shares=(item,),
        )

    # 5. Multiple recognized share occurrences -> per-link segment code pairing & deduplication.
    leading_prefix = _strip_url_spans(working, 0, recognized_occurrences[0][0], noise_url_spans)
    prefix_labeled_codes = _extract_labeled_codes(leading_prefix)

    paired_items: list[tuple[RecognizedShareUrl, str | None, bool]] = []
    occ_count = len(recognized_occurrences)
    for idx, (_s, end_pos, rec_share) in enumerate(recognized_occurrences):
        next_start = recognized_occurrences[idx + 1][0] if idx + 1 < occ_count else len(working)
        segment = _strip_url_spans(working, end_pos, next_start, noise_url_spans)
        seg_codes = _extract_batch_segment_codes(segment)

        item_ambiguous = False
        if len(seg_codes) > 1:
            item_ambiguous = True
        seg_code = seg_codes[0] if len(seg_codes) == 1 else None

        if idx == 0 and prefix_labeled_codes:
            if len(prefix_labeled_codes) > 1:
                item_ambiguous = True
            else:
                p_code = prefix_labeled_codes[0]
                if seg_code is not None and seg_code != p_code:
                    item_ambiguous = True
                elif seg_code is None:
                    seg_code = p_code

        if rec_share.embedded_code and seg_code and rec_share.embedded_code != seg_code:
            item_ambiguous = True

        resolved_code = rec_share.embedded_code or seg_code
        paired_items.append((rec_share, resolved_code, item_ambiguous))

    if forced_provider_id is not None:
        paired_items = [it for it in paired_items if it[0].provider_id == forced_provider_id]
        if not paired_items:
            return ParsedInput(no_subdir=no_subdir, invalid_link_candidate=True)

    for _share, _code, is_amb in paired_items:
        if is_amb:
            return ParsedInput(no_subdir=no_subdir, ambiguous=True)

    # Deduplicate identical `(provider_id, external_id, sub_dir_fid)` preserving first-seen order.
    deduped_by_key: dict[tuple[str, str, str], ParsedShareItem] = {}
    for rec_share, resolved_code, _ in paired_items:
        key = (rec_share.provider_id, rec_share.external_id, rec_share.sub_dir_fid)
        existing_item = deduped_by_key.get(key)
        if existing_item is None:
            merged_share = (
                replace(rec_share, embedded_code=resolved_code)
                if resolved_code and not rec_share.embedded_code
                else rec_share
            )
            deduped_by_key[key] = ParsedShareItem(share=merged_share, code=resolved_code)
        else:
            if existing_item.code and resolved_code and existing_item.code != resolved_code:
                return ParsedInput(no_subdir=no_subdir, ambiguous=True)
            merged_code = existing_item.code or resolved_code
            if merged_code != existing_item.code:
                updated_share = (
                    replace(existing_item.share, embedded_code=merged_code)
                    if merged_code and not existing_item.share.embedded_code
                    else existing_item.share
                )
                deduped_by_key[key] = ParsedShareItem(share=updated_share, code=merged_code)

    final_items = tuple(deduped_by_key.values())
    first_item = final_items[0]
    return ParsedInput(
        no_subdir=no_subdir,
        share=first_item.share,
        code=first_item.code,
        shares=final_items,
    )
