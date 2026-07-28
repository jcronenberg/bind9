# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0.  If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

import os
import socket
import struct
from typing import Tuple

import dns.message

import isctest


def _tcp_query_with_wire_len(
    msg: dns.message.Message, ip: str, source: str
) -> Tuple[dns.message.Message, int]:
    """
    Send a TCP query and return (response_message, response_wire_length).

    Captures the raw response bytes directly, since Message.wire requires
    dnspython >= 2.7.0 and Message.to_wire() would re-compress names itself
    instead of reflecting what the server actually sent.
    """
    port = int(os.environ["PORT"])
    wire = msg.to_wire()
    with socket.create_connection((ip, port), source_address=(source, 0)) as sock:
        sock.sendall(struct.pack("!H", len(wire)) + wire)
        length = struct.unpack("!H", _recvall(sock, 2))[0]
        response_wire = _recvall(sock, length)
    return dns.message.from_wire(response_wire), len(response_wire)


def _recvall(sock: socket.socket, count: int) -> bytes:
    chunks = []
    while count > 0:
        chunk = sock.recv(count)
        if not chunk:
            raise EOFError("connection closed before all data was received")
        chunks.append(chunk)
        count -= len(chunk)
    return b"".join(chunks)


# The query answer sent with compression disabled should have a size that is
# about twice as large as the answer with compression enabled, while
# maintaining identical content.
def test_names():
    msg = isctest.query.create("example.", "MX")
    # Getting message size with compression enabled
    res_enabled, len_enabled = _tcp_query_with_wire_len(
        msg, ip="10.53.0.1", source="10.53.0.1"
    )
    # Getting message size with compression disabled
    res_disabled, len_disabled = _tcp_query_with_wire_len(
        msg, ip="10.53.0.1", source="10.53.0.2"
    )
    # Checking if responses are identical content-wise
    isctest.check.rrsets_equal(res_enabled.answer, res_disabled.answer)
    # Checking if message with compression disabled is significantly (say 70%) larger
    assert len_disabled > len_enabled * 1.7
