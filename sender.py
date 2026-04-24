#!/usr/bin/env python3
import socket
from typing import Tuple


class UnicastSender:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def send(self, packet: bytes) -> int:
        return self.sock.sendto(packet, (self.host, self.port))

    def close(self) -> None:
        self.sock.close()