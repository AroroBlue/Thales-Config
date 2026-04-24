#!/usr/bin/env python3
import logging
import socket
import struct
from typing import Tuple


class MulticastReceiver:
    def __init__(self, group: str, port: int, interface: str = '0.0.0.0', timeout: float = None):
        self.group = group
        self.port = port
        self.interface = interface
        self.timeout = timeout
        self.sock = self._create_socket()

    def _create_socket(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except OSError:
            pass
        
        # Tune receive buffer size for high-throughput multicast
        buf_size = 8 * 1024 * 1024  # 8MB receive buffer
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, buf_size)
        actual_buf_size = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        logging.debug('Socket receive buffer: requested=%d, actual=%d', buf_size, actual_buf_size)
        
        sock.bind((self.interface, self.port))
        mreq = struct.pack('4s4s', socket.inet_aton(self.group), socket.inet_aton(self.interface))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        logging.debug('Joined multicast group %s:%d on interface %s', self.group, self.port, self.interface)
        
        # Set socket timeout if specified
        if self.timeout is not None:
            self.sock.settimeout(self.timeout)
            logging.debug('Socket timeout set to %.2f seconds', self.timeout)
        
        return sock

    def receive(self, bufsize: int = 65536) -> Tuple[bytes, Tuple[str, int]]:
        return self.sock.recvfrom(bufsize)

    def close(self) -> None:
        self.sock.close()
