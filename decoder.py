#!/usr/bin/env python3
import logging
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

try:
    from coatialtd.asterix import AsterixDecoder as CoatialtdAsterixDecoder
except ImportError:
    CoatialtdAsterixDecoder = None


@dataclass
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


def _resolve_attribute(source: Any, names: List[str], default: Any = None) -> Any:
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
