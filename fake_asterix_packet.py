#!/usr/bin/env python3
import argparse
import socket
import struct
from typing import Tuple


def _encode_signed24(value: int) -> bytes:
    if not -(1 << 23) <= value < (1 << 23):
        raise ValueError('Value out of signed 24-bit range')
    if value < 0:
        value += 1 << 24
    return value.to_bytes(3, byteorder='big', signed=False)


def build_cat10_packet(callsign: str, latitude: float, longitude: float) -> bytes:
    """Build a simple fake CAT010 ASTERIX packet for testing."""
    category = 10
    # FSPEC with fields 1-10 present, extension bit set on first octet.
    fspec = bytes([0xFF, 0xE0])

    lat_raw = int(round(latitude / 90.0 * float(1 << 23)))
    lon_raw = int(round(longitude / 180.0 * float(1 << 23)))

    data_items = bytearray()
    data_items.extend(b'\x01\x01')              # Data Source Identifier
    data_items.extend(b'\x80\x00')              # Target Report Descriptor
    data_items.extend(b'\x12\x34\x56')          # Time Of Day
    data_items.extend(_encode_signed24(lat_raw) + _encode_signed24(lon_raw))  # Position In WGS-84 (lat/lon)
    data_items.extend(b'\x10\x00\x80\x00')      # Calculated Track Velocity
    data_items.extend(b'\x00\x01')              # Track Number
    data_items.extend(b'\x01')                    # Track Status
    data_items.extend(b'\x21\x12')              # Mode 3/A Code in Octal
    data_items.extend(b'\x41\x42\x43')          # Target Address (SSR-S)
    data_items.extend(callsign.encode('ascii', errors='ignore'))  # Aircraft Identification

    length = 3 + len(fspec) + len(data_items)
    header = struct.pack('!B H', category, length)
    packet = header + fspec + data_items
    return packet


def send_multicast(packet: bytes, group: str, port: int, interface: str = '0.0.0.0') -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        ttl = struct.pack('b', 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
        sock.sendto(packet, (group, port))
    finally:
        sock.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Build and optionally send a fake ASTERIX radar packet')
    parser.add_argument('--group', default='239.255.0.1', help='Multicast group to send to')
    parser.add_argument('--port', default=30001, type=int, help='Multicast port to send to')
    parser.add_argument('--interface', default='0.0.0.0', help='Local interface for multicast send')
    parser.add_argument('--callsign', default='SVTEST', help='Fake aircraft callsign')
    parser.add_argument('--latitude', default=24.5, type=float, help='Fake latitude in degrees')
    parser.add_argument('--longitude', default=46.5, type=float, help='Fake longitude in degrees')
    parser.add_argument('--no-send', action='store_true', help='Do not send the packet; only print the bytes')
    parser.add_argument('--hex', action='store_true', help='Print the packet as hex bytes')
    parser.add_argument('--file', help='Write the packet to a file')
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    packet = build_cat10_packet(args.callsign, args.latitude, args.longitude)

    if args.hex:
        print('Packet hex:')
        print(packet.hex(' ', 1).upper())
    else:
        print(f'Built ASTERIX CAT010 packet of length {len(packet)} bytes')
        print(packet)

    if args.file:
        with open(args.file, 'wb') as output_file:
            output_file.write(packet)
        print(f'Wrote packet to {args.file}')

    if not args.no_send:
        print(f'Sending packet to {args.group}:{args.port}')
        send_multicast(packet, args.group, args.port, args.interface)
        print('Send complete')

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
