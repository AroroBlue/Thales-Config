#!/usr/bin/env python3
import logging
import struct
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

try:
    from coatialtd.asterix import AsterixDecoder as CoatialtdAsterixDecoder
except ImportError:
    CoatialtdAsterixDecoder = None


# =============================================================================
# Field Parser Architecture
# =============================================================================

class FieldParser(ABC):
    """Base class for ASTERIX field parsers."""
    
    def __init__(self, field_id: int, name: str):
        self.field_id = field_id
        self.name = name
    
    @abstractmethod
    def parse(self, data: bytes, offset: int, remaining_length: int) -> Tuple[bytes, int]:
        """
        Parse field from packet data.
        
        Args:
            data: Full packet bytes
            offset: Current position in packet
            remaining_length: Bytes remaining in packet
            
        Returns:
            Tuple of (field_value, bytes_consumed)
        """
        pass
    
    def get_fixed_length(self) -> Optional[int]:
        """Return fixed length if known, None for variable-length fields."""
        return None


class FixedLengthParser(FieldParser):
    """Parser for fixed-length fields."""
    
    def __init__(self, field_id: int, name: str, length: int):
        super().__init__(field_id, name)
        self.length = length
    
    def parse(self, data: bytes, offset: int, remaining_length: int) -> Tuple[bytes, int]:
        length = min(self.length, remaining_length)
        return data[offset:offset + length], length
    
    def get_fixed_length(self) -> Optional[int]:
        return self.length


class VariableLengthParser(FieldParser):
    """Parser for variable-length fields (length determined at runtime)."""
    
    def __init__(self, field_id: int, name: str, length_calculator: callable = None):
        super().__init__(field_id, name)
        self.length_calculator = length_calculator
    
    def parse(self, data: bytes, offset: int, remaining_length: int) -> Tuple[bytes, int]:
        if self.length_calculator:
            length = self.length_calculator(data, offset, remaining_length)
        else:
            # Default: consume all remaining
            length = remaining_length
        return data[offset:offset + length], length


class RepetitiveParser(FieldParser):
    """Parser for repetitive fields (FXP/REP format)."""
    
    def __init__(self, field_id: int, name: str, item_parser: FieldParser):
        super().__init__(field_id, name)
        self.item_parser = item_parser
    
    def parse(self, data: bytes, offset: int, remaining_length: int) -> Tuple[bytes, int]:
        if remaining_length < 1:
            return b'', 0
        count = data[offset]
        offset += 1
        total_consumed = 1
        items = []
        for _ in range(count):
            item_data, consumed = self.item_parser.parse(data, offset, remaining_length - total_consumed)
            if consumed == 0:
                break
            items.append(item_data)
            offset += consumed
            total_consumed += consumed
        return bytes([count]) + b''.join(items), total_consumed


class FXExtensionParser(FieldParser):
    """Parser for FX-extended fields."""
    
    def __init__(self, field_id: int, name: str, primary: FieldParser, extension: FieldParser):
        super().__init__(field_id, name)
        self.primary = primary
        self.extension = extension
    
    def parse(self, data: bytes, offset: int, remaining_length: int) -> Tuple[bytes, int]:
        primary_value, primary_consumed = self.primary.parse(data, offset, remaining_length)
        total = primary_consumed
        # Check if FX bit is set in last byte of primary
        if primary_value and (primary_value[-1] & 0x01):
            ext_value, ext_consumed = self.extension.parse(data, offset + total, remaining_length - total)
            primary_value += ext_value
            total += ext_consumed
        return primary_value, total


# =============================================================================
# Decoded Data Classes
# =============================================================================
class DecodedField:
    id: int
    name: str
    offset: int
    length: int
    value: bytes
    redacted: bool = False


@dataclass
class DecodedMessage:
    category: int
    length: int
    raw: bytes
    fields: List[DecodedField] = field(default_factory=list)
    redacted_bytes: bytearray = field(init=False)

    def __post_init__(self):
        self.redacted_bytes = bytearray(self.raw)

    def redact_field(self, field_name: str) -> bool:
        matched = False
        for field in self.fields:
            if field.name.lower() == field_name.lower():
                logging.debug('Redacting field %s offset=%d length=%d', field.name, field.offset, field.length)
                for i in range(field.offset, min(field.offset + field.length, len(self.redacted_bytes))):
                    self.redacted_bytes[i] = 0
                field.redacted = True
                matched = True
        return matched

    def redact_offset(self, start: int, end: int) -> bool:
        if start < 0 or end > len(self.redacted_bytes) or start >= end:
            return False
        logging.debug('Redacting raw byte range %d..%d', start, end)
        for i in range(start, end):
            self.redacted_bytes[i] = 0
        return True

    def redact_all_data(self) -> bool:
        if len(self.redacted_bytes) <= 3:
            return False
        logging.debug('Redacting all payload bytes after ASTERIX header')
        for i in range(3, len(self.redacted_bytes)):
            self.redacted_bytes[i] = 0
        for field in self.fields:
            field.redacted = True
        return True

    def get_position_wgs84(self) -> Optional[Tuple[float, float]]:
        for field in self.fields:
            if field.name.lower() == 'positioninwgs84' and len(field.value) == 6:
                lat_raw = _decode_signed24(field.value[:3])
                lon_raw = _decode_signed24(field.value[3:6])
                lat = lat_raw * 90.0 / float(1 << 23)
                lon = lon_raw * 180.0 / float(1 << 23)
                return lat, lon
        return None

    def get_field_text(self, field_name: str) -> Optional[str]:
        normalized = field_name.replace(' ', '').replace('-', '').lower()
        for field in self.fields:
            if field.name.replace(' ', '').replace('-', '').lower() == normalized:
                try:
                    return field.value.decode('ascii', errors='ignore').strip()
                except Exception:
                    return None
        return None

    def to_bytes(self) -> bytes:
        return bytes(self.redacted_bytes)


FIELD_DEFINITIONS: Dict[int, List[Tuple[int, str, Optional[int]]]] = {
    10: [
        (1, 'DataSourceIdentifier', 2),
        (2, 'TargetReportDescriptor', 2),
        (3, 'TimeOfDay', 3),
        (4, 'PositionInWGS84', 6),
        (5, 'CalculatedTrackVelocity', 4),
        (6, 'TrackNumber', 2),
        (7, 'TrackStatus', 1),
        (8, 'Mode3ACodeInOctal', 2),
        (9, 'TargetAddress', 3),
        (10, 'GeometricHeight', 2),
        (11, 'FlightLevel', 2),
        (12, 'MeasuredHeight', 2),
        (15, 'AircraftIdentification', 6),
        (18, 'FinalStateSelectedAltitude', 2),
    ],
    21: [
        (1, 'DataSourceIdentifier', 2),
        (2, 'TimeOfDay', 3),
        (3, 'TargetReportDescriptor', 2),
        (5, 'PositionInWGS84', 6),
        (6, 'CalculatedTrackVelocity', 4),
        (7, 'TrackNumber', 2),
        (8, 'TrackStatus', 1),
        (9, 'Mode3ACodeInOctal', 2),
        (10, 'TargetAddress', 3),
        (15, 'AircraftIdentification', 6),
    ],
    62: [
        (1, 'DataSourceIdentifier', 2),
        (2, 'TrackNumber', 2),
        (3, 'TrackStatus', 1),
        (4, 'MeasuredPosition', 6),
        (5, 'Mode3ACodeInOctal', 2),
        (6, 'TargetAddress', 3),
        (7, 'FlightLevel', 2),
        (8, 'MeasuredHeight', 2),
        (9, 'TrackVelocity', 4),
    ],
    48: [
        (1, 'DataSourceIdentifier', 2),
        (2, 'TargetReportDescriptor', 2),
        (3, 'TimeOfDay', 3),
        (4, 'PositionInWGS84', 6),
        (5, 'Mode3ACodeInOctal', 2),
        (6, 'TargetAddress', 3),
        (7, 'FlightLevel', 2),
        (8, 'MeasuredHeight', 2),
        (9, 'TrackVelocity', 4),
        (10, 'ServiceManagementMessage', None),
    ],
}


# =============================================================================
# Parser Registry (New Architecture)
# =============================================================================

class CategoryParser:
    """Parser registry for a specific ASTERIX category."""
    
    def __init__(self, category: int):
        self.category = category
        self.field_parsers: Dict[int, FieldParser] = {}
    
    def register(self, field_id: int, parser: FieldParser) -> None:
        self.field_parsers[field_id] = parser
    
    def get(self, field_id: int) -> Optional[FieldParser]:
        return self.field_parsers.get(field_id)
    
    def parse_field(self, field_id: int, data: bytes, offset: int, remaining: int) -> Optional[Tuple[bytes, int]]:
        parser = self.get(field_id)
        if parser:
            return parser.parse(data, offset, remaining)
        return None


# Example: Category 21 with variable-length support
def create_category21_parser() -> CategoryParser:
    parser = CategoryParser(21)
    # Fixed-length fields
    parser.register(1, FixedLengthParser(1, 'DataSourceIdentifier', 2))
    parser.register(2, FixedLengthParser(2, 'TimeOfDay', 3))
    parser.register(3, FixedLengthParser(3, 'TargetReportDescriptor', 2))
    parser.register(5, FixedLengthParser(5, 'PositionInWGS84', 6))
    parser.register(6, FixedLengthParser(6, 'CalculatedTrackVelocity', 4))
    parser.register(7, FixedLengthParser(7, 'TrackNumber', 2))
    parser.register(8, FixedLengthParser(8, 'TrackStatus', 1))
    parser.register(9, FixedLengthParser(9, 'Mode3ACodeInOctal', 2))
    parser.register(10, FixedLengthParser(10, 'TargetAddress', 3))
    # Variable-length: Aircraft Identification (up to 8 chars)
    parser.register(15, VariableLengthParser(15, 'AircraftIdentification'))
    return parser


# Parser registry for all categories
PARSER_REGISTRY: Dict[int, CategoryParser] = {
    21: create_category21_parser(),
    # Add more categories as needed
}


def get_category_parser(category: int) -> Optional[CategoryParser]:
    """Get parser for a specific category."""
    return PARSER_REGISTRY.get(category)


# =============================================================================
# Legacy Support Functions
# =============================================================================
    for name in names:
        if hasattr(source, name):
            return getattr(source, name)
    return default


def _parse_fspec(frame: bytes, offset: int) -> Tuple[List[int], int]:
    fspec = []
    while offset < len(frame):
        octet = frame[offset]
        fspec.append(octet)
        offset += 1
        if not (octet & 0x01):
            break
    return fspec, offset


def _fspec_bits(fspec: List[int]) -> List[int]:
    bits = []
    for octet_index, octet in enumerate(fspec):
        for bit_index in range(1, 8):
            if octet & (1 << (8 - bit_index)):
                bits.append(octet_index * 7 + bit_index)
    return bits


def _decode_signed24(data: bytes) -> int:
    if len(data) != 3:
        raise ValueError('Signed 24-bit data must be 3 bytes long')
    raw = int.from_bytes(data, byteorder='big', signed=False)
    if raw & 0x800000:
        raw -= 1 << 24
    return raw


def _decode_with_fallback(packet: bytes) -> DecodedMessage:
    if len(packet) < 3:
        raise ValueError('ASTERIX packet too short')
    category = packet[0]
    length = struct.unpack('!H', packet[1:3])[0]
    if len(packet) < length:
        raise ValueError('Packet length mismatch')
    fspec, offset = _parse_fspec(packet, 3)
    message = DecodedMessage(category=category, length=length, raw=packet[:length])
    if category in FIELD_DEFINITIONS:
        field_defs = {field_id: (name, size) for field_id, name, size in FIELD_DEFINITIONS[category]}
        for field_id in _fspec_bits(fspec):
            if field_id not in field_defs:
                break
            name, size = field_defs[field_id]
            if size is None:
                size = max(0, length - offset)
            if offset + size > length:
                size = max(0, length - offset)
            value = packet[offset:offset + size]
            message.fields.append(DecodedField(id=field_id, name=name, offset=offset, length=size, value=value))
            offset += size
    return message


def _decode_with_coatialtd(packet: bytes) -> DecodedMessage:
    if CoatialtdAsterixDecoder is None:
        raise ImportError('coatialtd ASTERIX decoder is not installed')
    decoder = CoatialtdAsterixDecoder()
    decoded = decoder.decode(packet) if hasattr(decoder, 'decode') else decoder(packet)
    category = _resolve_attribute(decoded, ['category', 'cat', 'category_id'], packet[0])
    length = _resolve_attribute(decoded, ['length', 'packet_length'], len(packet))
    raw = packet[:length]
    fields = []
    decoded_fields = _resolve_attribute(decoded, ['fields', 'field_list', 'items'], []) or []
    for item in decoded_fields:
        field_id = _resolve_attribute(item, ['id', 'field_id', 'fid'], 0)
        name = _resolve_attribute(item, ['name', 'field_name', 'label'], f'field_{field_id}')
        offset = _resolve_attribute(item, ['offset', 'start', 'position'], 0)
        length_value = _resolve_attribute(item, ['length', 'size'], None)
        value = _resolve_attribute(item, ['raw', 'value', 'data'], b'') or b''
        if length_value is None:
            length_value = len(value)
        fields.append(DecodedField(id=field_id, name=name, offset=offset, length=length_value, value=value))
    return DecodedMessage(category=category, length=length, raw=raw, fields=fields)


def decode_packet(packet: bytes, use_coatialtd: bool = True) -> DecodedMessage:
    if use_coatialtd and CoatialtdAsterixDecoder is not None:
        try:
            return _decode_with_coatialtd(packet)
        except Exception as exc:
            logging.warning('coatialtd decode failed: %s; falling back to internal parser', exc)
    return _decode_with_fallback(packet)
