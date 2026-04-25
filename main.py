#!/usr/bin/env python3
import argparse
import logging
import sys
from decoder import decode_packet
from filters import (
    apply_redactions,
    is_within_saudi_arabia,
    normalize_int_list,
    normalize_ssrs_code,
    normalize_text_list,
    parse_offset_range,
    redact_callsign_prefixes,
    should_keep_packet,
)
from receiver import MulticastReceiver
from sender import UnicastSender


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description='ASTERIX multicast receiver -> filtered unicast sender')
    parser.add_argument('--mcast-group', required=True, help='Multicast IPv4 group to join')
    parser.add_argument('--mcast-port', required=True, type=int, help='Source multicast UDP port')
    parser.add_argument('--dest-host', required=True, help='Destination unicast host')
    parser.add_argument('--dest-port', required=True, type=int, help='Destination unicast UDP port')
    parser.add_argument('--bind-interface', default='0.0.0.0', help='Local interface to bind for multicast receive')
    parser.add_argument('--recv-timeout', type=float, default=None, help='Socket receive timeout in seconds')
    parser.add_argument('--keep-category', help='Comma-separated ASTERIX categories to keep; all others are dropped')
    parser.add_argument('--drop-category', help='Comma-separated ASTERIX categories to drop')
    parser.add_argument('--keep-ssrs-code', help='Comma-separated SSR-S codes to keep; all others are dropped when this option is set')
    parser.add_argument('--drop-ssrs-code', help='Comma-separated SSR-S codes to drop')
    parser.add_argument('--keep-callsign', help='Comma-separated call signs to keep; all others are dropped when this option is set')
    parser.add_argument('--drop-callsign', help='Comma-separated call signs to drop')
    parser.add_argument('--redact-callsign-prefix', help='Comma-separated call sign prefixes to redact when matched')
    parser.add_argument('--mask-full', action='store_true', help='Mask the whole packet payload after ASTERIX header instead of only selected fields')
    parser.add_argument('--mask-full-saudi', action='store_true', help='Mask the whole packet when the position is inside Saudi Arabia')
    parser.add_argument('--redact-field', action='append', default=[], help='Field name to redact from supported categories; repeatable')
    parser.add_argument('--redact-offset', action='append', default=[], help='Byte range to redact using start-end format')
    parser.add_argument('--dump', action='store_true', help='Print packet metadata to stdout')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    return parser


def print_packet_metadata(message, source, redacted):
    print('--- ASTERIX packet ---')
    print(f' Source: {source}')
    print(f' Category: {message.category}')
    print(f' Length: {message.length}')
    print(f' Fields: {len(message.fields)}')
    for field in message.fields:
        print(f'  - {field.name} id={field.id} offset={field.offset} length={field.length} redacted={field.redacted}')
    print(f' Redacted: {redacted}')
    print('-----------------------')


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

    keep_categories = set(normalize_int_list(args.keep_category)) if args.keep_category else None
    drop_categories = set(normalize_int_list(args.drop_category)) if args.drop_category else set()
    keep_ssrs_codes = [normalize_ssrs_code(item) for item in normalize_text_list(args.keep_ssrs_code)]
    drop_ssrs_codes = [normalize_ssrs_code(item) for item in normalize_text_list(args.drop_ssrs_code)]
    keep_callsigns = [item.upper() for item in normalize_text_list(args.keep_callsign)]
    drop_callsigns = [item.upper() for item in normalize_text_list(args.drop_callsign)]
    redact_callsign_prefixes = [item.upper() for item in normalize_text_list(args.redact_callsign_prefix)]
    redact_ranges = [parse_offset_range(item) for item in args.redact_offset]

    receiver = MulticastReceiver(args.mcast_group, args.mcast_port, args.bind_interface, args.recv_timeout)
    sender = UnicastSender(args.dest_host, args.dest_port)

    logging.info('Multicast receiver listening on %s:%d', args.mcast_group, args.mcast_port)
    logging.info('Unicast sender forwarding to %s:%d', args.dest_host, args.dest_port)

    try:
        while True:
            packet, source = receiver.receive()
            try:
                message = decode_packet(packet)
            except Exception as exc:
                logging.warning('Failed to decode packet from %s: %s', source, exc)
                continue

            if not should_keep_packet(
                message.category,
                keep_categories,
                drop_categories,
                keep_ssrs_codes,
                drop_ssrs_codes,
                keep_callsigns,
                drop_callsigns,
                message,
            ):
                logging.debug('Dropping category %d', message.category)
                continue

            full_mask_by_saudi = args.mask_full_saudi and is_within_saudi_arabia(message)
            redacted_callsign = redact_callsign_prefixes(message, redact_callsign_prefix_list)
            redacted = False
            if full_mask_by_saudi:
                redacted = message.redact_all_data()
            elif args.mask_full:
                redacted = apply_redactions(message, args.redact_field, redact_ranges, full_mask=True)
            else:
                redacted = apply_redactions(message, args.redact_field, redact_ranges)

            redacted = redacted or redacted_callsign

            if args.dump:
                print_packet_metadata(message, source, redacted)

            output = message.to_bytes()
            sender.send(output)
            logging.info('Forwarded category %d size %d from %s to %s:%d%s', message.category, len(output), source, args.dest_host, args.dest_port, ' (redacted)' if redacted else '')
    except KeyboardInterrupt:
        logging.info('Interrupted by user')
    finally:
        receiver.close()
        sender.close()

    return 0


if __name__ == '__main__':
    sys.exit(main())