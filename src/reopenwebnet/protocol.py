# -*- coding: utf-8 -*-
import asyncio
from re import A
import time
import hmac
import hashlib
import base64
from logging import getLogger

from reopenwebnet import messages
from reopenwebnet.password import calculate_open_password

_LOGGER = getLogger(__name__)


class State:
    NOT_CONNECTED = "NOT_CONNECTED"
    CONNECTED = "CONNECTED"
    SESSION_REQUESTED = "SESSION_REQUESTED"
    SAM_HANDSHAKE = "SAM_HANDSHAKE" 
    HMAC_SENT = "HMAC_SENT"
    SESSION_ACTIVE = "SESSION_ACTIVE"
    ERROR = "ERROR"


class OpenWebNetProtocol(asyncio.Protocol):
    def __init__(self, session_type, password, on_session_start, event_listener, on_connection_lost,
                 name="opwenwebnet"):
        self.session_type = session_type
        self.password = password
        self.write_delay = 0.1
        self.on_session_start = on_session_start
        self.event_listener = event_listener
        self.on_connection_lost = on_connection_lost
        self.name = name
        self.sha_type = None

        self.state = States.NOT_CONNECTED
        self.buffer = ""
        self.transport = None
        self.next_message = 0

    def connection_made(self, transport):
        self.state = States.CONNECTED
        self.transport = transport

    def data_received(self, data):
        print("State:",self.state)
        data = data.decode('utf-8')
        self.buffer += data

        msgs, remainder = messages.parse_messages(self.buffer)
        self.buffer = "" if remainder is None else remainder
        print(msgs[0])

        if self.state == States.ERROR:
            _LOGGER.error("got data in error state:", data)

        elif self.state == States.CONNECTED:
            if msgs[0] == messages.ACK:
                self._send_message(self.session_type)
                self.state = States.SESSION_REQUESTED
            else:
                _LOGGER.error('Did not get initial ack on connect')
                self.state = States.ERROR

        elif self.state == States.SESSION_REQUESTED:
            if msgs[-1] == messages.NACK:
                self.state = States.ERROR
            # TODO: handle case where server simply sends 'ack' (i.e. no authentication)
            # TODO: handle case where server sends an 'open password' nonce (e.g. Bticino F455 Basic gateway)
            elif msgs[0] == messages.SHA1 or msgs[0] == messages.SHA2:
                self.sha_type = int(msgs[0].value[4])
                self._send_message(messages.ACK)
                self.state = States.SAM_HANDSHAKE
            else:
                _LOGGER.error('Did not get NACK or nonce or HMAC auth type from server')
                self.state = States.ERROR

        elif self.state == States.SAM_HANDSHAKE:
            if msgs[-1] == messages.NACK:
                self.state = States.ERROR
            else:
                Ra_wire = msgs[0]
                Ra_hex = wire_to_hex(Ra_wire)
                if self.sha_type == 1:
                    self.Rb_hex = random_hexstring(20)
                    hmac = hmac_sha1(Ra_hex, self.Rb_hex, self.password)
                else:
                    self.Rb_hex = random_hexstring(32)
                    hmac = hmac_sha2(Ra_hex, self.Rb_hex, self.password)

                self._send_message(messages.TagsMessage(["#" + hex_to_wire(self.Rb_hex), hex_to_wire(hmac)]))
                self.state = States.HMAC_SENT

        elif self.state == States.HMAC_SENT:
            if msgs[-1] == messages.NACK:
                self.state = States.ERROR
            else:
                self._send_message(messages.ACK)
                self.state = States.SESSION_ACTIVE
                if self.on_session_start:
                    self.on_session_start.set_result(True)

        elif self.state == States.SESSION_ACTIVE:
            _LOGGER.debug("sending messages to event listener %s", msgs)
            if self.event_listener is not None:
                self.event_listener(msgs)

    def _send_message(self, message):
        now = time.time()
        if now < self.next_message:
            time.sleep(self.next_message - now)
        self.next_message = now + self.write_delay
        self.transport.write(str(message).encode('utf-8'))

    def send_message(self, message):
        if self.state != States.SESSION_ACTIVE:
            _LOGGER.error("Not sending message - session not active yet")
            # TODO: use an event to indicate when session is active
            return
        self._send_message(message)

    def connection_lost(self, exc):
        _LOGGER.debug("[%s] in protocol.connection_lost: %s", self.name, exc)
        self.state = States.NOT_CONNECTED
        self.transport = None
        self.on_connection_lost.set_result(False)
