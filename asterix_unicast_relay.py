#!/usr/bin/env python3
import argparse
import logging
import socket
import struct
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class AsterixField:
    field_id: int
    name: str
    offset: int
    length: int
    raw_value: bytes
    redacted: bool = False


@dataclass
class AsterixMessage:
    category: int
    length: int
    raw: bytes
    fspec: List[int]
    fields: List[AsterixField] = field(default_factory=list)
    redacted_bytes: bytearray = field(default_factory=bytearray)

    def __post_init__(self):
        self.redacted_bytes = bytearray(self.raw)

    def redact_field(self, field_name: str) -> bool:
        matched = False
        for field in self.fields:
            if field.name.lower() == field_name.lower():
                logging.debug('Redacting field %s at %d..%d', field.name, field.offset, field.offset + field.length)
                for i in range(field.offset, field.offset + field.length):
                    self.redacted_bytes[i] = 0
                field.redacted = True
                matched = True
        return matched

    def redact_offset(self, start: int, end: int) -> bool:
        if start < 0 or end > len(self.raw) or start >= end:
            return False
        logging.debug('Redacting offset range %d..%d', start, end)
        for i in range(start, end):
            self.redacted_bytes[i] = 0
        return True

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
}


def parse_fspec(frame: bytes, offset: int) -> Tuple[List[int], int]:
    fspec = []
    while offset < len(frame):
        octet = frame[offset]
        fspec.append(octet)
        offset += 1
        if not (octet & 0x01):
            break
    return fspec, offset


def fspec_bits(fspec: List[int]) -> List[int]:
    bits = []
    for octet_index, octet in enumerate(fspec):
        for bit_index in range(1, 8):
            if octet & (1 << (8 - bit_index)):
                bits.append(octet_index * 7 + bit_index)
    return bits


def parse_asterix_frame(frame: bytes) -> AsterixMessage:
    if len(frame) < 3:
        raise ValueError('ASTERIX frame too short: must contain category and length')

    category = frame[0]
    length = struct.unpack('!H', frame[1:3])[0]
    if len(frame) < length:
        raise ValueError(f'Frame length mismatch: expected {length}, got {len(frame)}')

    fspec, offset = parse_fspec(frame, 3)
    message = AsterixMessage(category=category, length=length, raw=frame[:length], fspec=fspec)
    bits = fspec_bits(fspec)

    if category in FIELD_DEFINITIONS:
        field_defs = {field_id: (name, size) for field_id, name, size in FIELD_DEFINITIONS[category]}
        for field_id in bits:
            if field_id not in field_defs:
                logging.debug('Unknown field %d for category %d; stopping parse at offset %d', field_id, category, offset)
                break
            name, size = field_defs[field_id]
            if size is None:
                logging.debug('Variable or unsupported size for field %s; stopping parse', name)
                break
            if offset + size > length:
                logging.warning('Declared field extends past packet length; truncating parse')
                size = max(0, length - offset)
            raw_value = frame[offset:offset + size]
            message.fields.append(AsterixField(field_id=field_id, name=name, offset=offset, length=size, raw_value=raw_value))
            offset += size
    else:
        logging.debug('Category %d not supported for field parsing', category)

    return message


def create_multicast_socket(group: str, port: int, interface: str = '0.0.0.0') -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((interface, port))
    except Exception as exc:
        logging.error('Failed to bind multicast socket: %s', exc)
        raise
    mreq = struct.pack('4s4s', socket.inet_aton(group), socket.inet_aton(interface))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    return sock


def create_unicast_socket() -> socket.socket:
    return socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def normalize_int_list(value: str) -> List[str]:
    return [item.strip() for item in value.split(',') if item.strip()]


def parse_offset_range(value: str) -> Tuple[int, int]:
    if '-' not in value:
        raise argparse.ArgumentTypeError('Offset ranges must use start-end format')
    parts = value.split('-', 1)
    try:
        start = int(parts[0], 0)
        end = int(parts[1], 0)
    except ValueError:
        raise argparse.ArgumentTypeError('Offset range must contain integers')
    if start < 0 or end <= start:
        raise argparse.ArgumentTypeError('Offset range must be start < end')
    return start, end


def main() -> int:
    parser = argparse.ArgumentParser(description='ASTERIX multicast -> filtered unicast relay')
    parser.add_argument('--mcast-group', required=True, help='Multicast IPv4 group to join')
    parser.add_argument('--mcast-port', required=True, type=int, help='Source multicast UDP port')
    parser.add_argument('--dest-host', required=True, help='Destination unicast host')
    parser.add_argument('--dest-port', required=True, type=int, help='Destination unicast UDP port')
    parser.add_argument('--bind-interface', default='0.0.0.0', help='Interface to bind for multicast receive')
    parser.add_argument('--keep-category', help='Comma-separated ASTERIX categories to keep; other categories are dropped')
    parser.add_argument('--drop-category', help='Comma-separated ASTERIX categories to drop')
    parser.add_argument('--redact-field', action='append', default=[], help='Field name to redact from supported categories; can be repeated')
    parser.add_argument('--redact-offset', action='append', default=[], help='Byte range to redact inside each packet using start-end (decimal or hex)')
    parser.add_argument('--dump', action='store_true', help='Print parsed packet metadata to stdout')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

    keep_categories = set(int(item, 0) for item in normalize_int_list(args.keep_category)) if args.keep_category else None
    drop_categories = set(int(item, 0) for item in normalize_int_list(args.drop_category)) if args.drop_category else set()
    offset_ranges = [parse_offset_range(value) for value in args.redact_offset]

    logging.info('Listening for multicast %s:%d', args.mcast_group, args.mcast_port)
    logging.info('Forwarding filtered packets to %s:%d', args.dest_host, args.dest_port)

    recv_sock = create_multicast_socket(args.mcast_group, args.mcast_port, args.bind_interface)
    send_sock = create_unicast_socket()

    try:
        while True:
            packet, src = recv_sock.recvfrom(65536)
            try:
                message = parse_asterix_frame(packet)
            except Exception as exc:
                logging.warning('Failed to parse ASTERIX from %s: %s', src, exc)
                continue

            if keep_categories is not None and message.category not in keep_categories:
                logging.debug('Dropping category %d because it is not in keep list', message.category)
                continue
            if message.category in drop_categories:
                logging.debug('Dropping category %d because it is in drop list', message.category)
                continue

            redacted = False
            for field_name in args.redact_field:
                if message.redact_field(field_name):
                    redacted = True
                else:
                    logging.debug('No matching field %s for category %d', field_name, message.category)
            for start, end in offset_ranges:
                if message.redact_offset(start, end):
                    redacted = True
                else:
                    logging.warning('Invalid redact offset range %d-%d for message length %d', start, end, len(message.raw))

            if args.dump:
                print('--- ASTERIX packet ---')
                print(f' Category: {message.category}')
                print(f' Length: {message.length}')
                print(f' FSPEC bytes: {[hex(value) for value in message.fspec]}')
                if message.fields:
                    for field in message.fields:
                        print(f' Field: {field.name} (id={field.field_id}, offset={field.offset}, length={field.length}, redacted={field.redacted})')
                else:
                    print(' Fields: unsupported category or no parsed fields')
                if redacted:
                    print(' Redaction applied')
                print('-----------------------')

            output = message.to_bytes()
            send_sock.sendto(output, (args.dest_host, args.dest_port))
            logging.info('Forwarded ASTERIX category %d size %d to %s:%d%s', message.category, len(output), args.dest_host, args.dest_port, ' (redacted)' if redacted else '')
    except KeyboardInterrupt:
        logging.info('Stopped by user')
    finally:
        recv_sock.close()
        send_sock.close()

    return 0


if __name__ == '__main__':
    sys.exit(main())
