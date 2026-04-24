#!/usr/bin/env python3
import argparse
from typing import List, Optional, Set, Tuple

SSR_S_FIELD_NAMES = {'targetaddress', 'mode-s address', 'mode s address', 'ssr-s', 'mode_s_address'}
CALLSIGN_FIELD_NAMES = {'aircraftidentification', 'flightidentification', 'flightid', 'callsign', 'targetidentification', 'call_sign'}


def normalize_int_list(value: Optional[str]) -> List[int]:
    if not value:
        return []
    return [int(item.strip(), 0) for item in value.split(',') if item.strip()]


def normalize_text_list(value: Optional[str]) -> List[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(',') if item.strip()]


def normalize_ssrs_code(value: str) -> str:
    raw = value.strip()
    if raw.lower().startswith('0x'):
        raw = raw[2:]
    raw = ''.join(ch for ch in raw if ch.isalnum()).upper()
    if not raw:
        raise argparse.ArgumentTypeError('SSR-S code cannot be empty')
    try:
        numeric = int(raw, 0)
        return f'{numeric:06X}'
    except ValueError:
        return raw


def normalize_callsign(value: str) -> str:
    return value.strip().upper()


def parse_offset_range(value: str) -> Tuple[int, int]:
    if '-' not in value:
        raise argparse.ArgumentTypeError('Offset ranges must use start-end format')
    start_str, end_str = value.split('-', 1)
    try:
        start = int(start_str, 0)
        end = int(end_str, 0)
    except ValueError:
        raise argparse.ArgumentTypeError('Offset range must contain integers or hex values')
    if start < 0 or end <= start:
        raise argparse.ArgumentTypeError('Offset range must be start < end')
    return start, end


def _field_matches_ssrs_code(field: 'DecodedField', code: str) -> bool:
    field_name = field.name.replace(' ', '').replace('-', '').lower()
    if field.id == 6 or field_name in SSR_S_FIELD_NAMES:
        hex_value = field.value.hex().upper()
        if len(hex_value) == 6:
            return hex_value == code
        return hex_value.endswith(code)
    return False


def _bytes_to_text(value: bytes) -> str:
    try:
        return value.decode('ascii', errors='ignore').strip().upper()
    except Exception:
        return ''


def _field_matches_callsign(field: 'DecodedField', callsign: str) -> bool:
    field_name = field.name.replace(' ', '').replace('-', '').lower()
    if field_name in CALLSIGN_FIELD_NAMES or field.id == 10:
        text = _bytes_to_text(field.value)
        return callsign in text
    return False


def has_ssrs_code(message: 'DecodedMessage', codes: List[str]) -> bool:
    if not codes:
        return True
    for field in message.fields:
        for code in codes:
            if _field_matches_ssrs_code(field, code):
                return True
    return False


def has_callsign(message: 'DecodedMessage', callsigns: List[str]) -> bool:
    if not callsigns:
        return True
    for field in message.fields:
        for callsign in callsigns:
            if _field_matches_callsign(field, callsign):
                return True
    return False


def is_within_saudi_arabia(message: 'DecodedMessage') -> bool:
    position = message.get_position_wgs84() if hasattr(message, 'get_position_wgs84') else None
    if position is None:
        return False
    lat, lon = position
    return 15.0 <= lat <= 32.0 and 34.0 <= lon <= 56.0


def redact_callsign_prefixes(message: 'DecodedMessage', prefixes: List[str]) -> bool:
    if not prefixes:
        return False
    text = message.get_field_text('AircraftIdentification') if hasattr(message, 'get_field_text') else None
    if not text:
        return False
    text_up = text.upper()
    for prefix in prefixes:
        if text_up.startswith(prefix.upper()):
            return message.redact_field('AircraftIdentification')
    return False


def should_keep_packet(
    category: int,
    keep_categories: Optional[Set[int]],
    drop_categories: Set[int],
    keep_ssrs_codes: List[str],
    drop_ssrs_codes: List[str],
    keep_callsigns: List[str],
    drop_callsigns: List[str],
    message: 'DecodedMessage',
) -> bool:
    if keep_categories is not None and category not in keep_categories:
        return False
    if category in drop_categories:
        return False
    if keep_ssrs_codes and not has_ssrs_code(message, keep_ssrs_codes):
        return False
    if drop_ssrs_codes and has_ssrs_code(message, drop_ssrs_codes):
        return False
    if keep_callsigns and not has_callsign(message, keep_callsigns):
        return False
    if drop_callsigns and has_callsign(message, drop_callsigns):
        return False
    return True


def apply_redactions(
    message: 'DecodedMessage',
    redact_fields: List[str],
    redact_offsets: List[Tuple[int, int]],
    full_mask: bool = False,
) -> bool:
    if full_mask:
        return message.redact_all_data()

    redacted = False
    for field_name in redact_fields:
        if message.redact_field(field_name):
            redacted = True
    for start, end in redact_offsets:
        if message.redact_offset(start, end):
            redacted = True
    return redacted
