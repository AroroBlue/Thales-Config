# ASTERIX Multicast to Unicast Relay

A modular Python relay that receives ASTERIX packets from a multicast source, applies filtering and redaction rules, and forwards the packets over unicast UDP.

## Project structure

- `main.py` — entrypoint and CLI orchestration
- `receiver.py` — multicast receiver implementation
- `sender.py` — unicast sender implementation
- `decoder.py` — ASTERIX decoding via `coatialtd` when available, with fallback parsing
- `filters.py` — packet selection and redaction logic

## Requirements

- Python 3.8+
- `coatialtd` ASTERIX decoder package if you want the external decoder functionality

> If `coatialtd` is not installed, the project still runs with an internal fallback parser for basic packet header and some supported fields.

## Usage

```bash
python3 main.py \
  --mcast-group 239.255.0.1 \
  --mcast-port 30001 \
  --dest-host 10.0.0.10 \
  --dest-port 40001 \
  --keep-category 10,21 \
  --redact-field AircraftIdentification \
  --dump
```

### CLI options

- `--mcast-group`: Multicast IPv4 group to join.
- `--mcast-port`: Multicast UDP port to listen on.
- `--dest-host`: Destination unicast host.
- `--dest-port`: Destination unicast port.
- `--bind-interface`: Local interface for multicast receive (default `0.0.0.0`).
- `--keep-category`: Comma-separated ASTERIX categories to keep.
- `--drop-category`: Comma-separated ASTERIX categories to drop.
- `--keep-ssrs-code`: Comma-separated SSR-S codes to keep; use hex or decimal notation.
- `--drop-ssrs-code`: Comma-separated SSR-S codes to drop.
- `--keep-callsign`: Comma-separated call signs to keep.
- `--drop-callsign`: Comma-separated call signs to drop.
- `--mask-full`: Mask the full packet payload after the ASTERIX header rather than only selective fields.
- `--redact-field`: Field name to redact from supported categories; may be repeated.
- `--redact-offset`: Byte range to redact using `start-end` syntax.
- `--dump`: Print decoded packet metadata to stdout.
- `--debug`: Enable debug logging.

## Notes

- This tool currently supports parsing field-level metadata for ASTERIX categories `10`, `21`, `62`, and `48`.
- When a field is redacted, the bytes for that field are zeroed, preserving packet length and overall ASTERIX framing.
- `--mask-full` zeros the payload after the first 3 ASTERIX header bytes, masking the full record content while preserving the packet header length.
- Use raw offset redaction when the category is unsupported or when you need to remove bytes without field-level parsing.

## Example

Forward multicast ASTERIX packets, keep only category `10`, and redact the `AircraftIdentification` field:

```bash
python3 main.py \
  --mcast-group 239.255.0.1 \
  --mcast-port 30001 \
  --dest-host 10.0.0.10 \
  --dest-port 40001 \
  --keep-category 10 \
  --redact-field AircraftIdentification
```
