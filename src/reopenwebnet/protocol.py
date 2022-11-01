# -*- coding: utf-8 -*-
import asyncio
from re import A
import time
import hmac
import hashlib
import base64
from logging import getLogger

from reopenwebnet import messages
from reopenwebnet.password import calculate_password

_LOGGER = getLogger(__name__)


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

        self.state = 'NOT_CONNECTED'
        self.buffer = ""
        self.transport = None
        self.next_message = 0

    def connection_made(self, transport):
        self.state = 'CONNECTED'
        self.transport = transport

    def data_received(self, data):
        print(self.state)
        data = data.decode('utf-8')
        self.buffer += data

        msgs, remainder = messages.parse_messages(self.buffer)
        self.buffer = "" if remainder is None else remainder
        print(msgs[0])

        if self.state == 'ERROR':
            _LOGGER.error("got data in error state:", data)

        elif self.state == 'CONNECTED':
            if msgs[0] == messages.ACK:
                self._send_message(self.session_type)
                self.state = 'SESSION_REQUESTED'
            else:
                _LOGGER.error('Did not get initial ack on connect')
                self.state = 'ERROR'

        elif self.state == 'SESSION_REQUESTED':
            if msgs[-1] == messages.NACK:
                self.state = 'ERROR'
            elif msgs[0] == messages.SHA1 or msgs[0] == messages.SHA2:
                self.sha_type = int(msgs[0].value[4])
                self._send_message(messages.ACK)
                self.state = 'SAM_HANDSHAKE'
            else:
                _LOGGER.error('Did not get SHAx from server')
                self.state = 'ERROR'

        elif self.state == 'SAM_HANDSHAKE':
            if msgs[-1] == messages.NACK:
                self.state = 'ERROR'
            else:
                Ra_64key = f""
                Rb_64key = f""
                Rb_128key = f""
                for x in range (1,65):
                    Ra_64key = Ra_64key + format(int(msgs[0].value[2*x:2*x+2]),'01x')
                A_key = f"736F70653E"
                B_key = f"636F70653E"               
                if self.sha_type == 2:
                    Rb_64key = f"0000000000000000000000000000000000000000000000000000000000000000"
                    Rb_128key = f"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
                
                Kab_key = hashlib.sha256(self.password.encode()).hexdigest()
                tempHMAC=Ra_64key+Rb_64key+A_key+B_key+Kab_key
                HMAC_message = hashlib.sha256(tempHMAC.encode()).hexdigest()
                h1 = f""
                for x in range (0,64):
                    h1 = h1 + str(int(HMAC_message[x],16)).zfill(2)

                self._send_message(messages.FixedMessage(f"*#{Rb_128key}*{h1}##", messages.TYPE_OTHER))
                self.state = 'HMAC_SENT'

        elif self.state == 'HMAC_SENT':
            if msgs[-1] == messages.NACK:
                self.state = 'ERROR'
            else:
                self._send_message(messages.ACK)
                self.state = 'EVENT_SESSION_ACTIVE'
                if self.on_session_start:
                    self.on_session_start.set_result(True)


#        elif self.state == 'END_SAM':
#            if msgs[-1] == messages.ACK:
#                if self.on_session_start:
#                    self.on_session_start.set_result(True)
#                self.state = 'EVENT_SESSION_ACTIVE'
#            else:
#                _LOGGER.error('Failed to establish event session')
#                self.state = 'ERROR'

        elif self.state == 'EVENT_SESSION_ACTIVE':
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
        if self.state != 'EVENT_SESSION_ACTIVE':
            _LOGGER.error("Not sending message - session not active yet")
            # TODO: use an event to indicate when session is active
            return
        self._send_message(message)

    def connection_lost(self, exc):
        _LOGGER.debug("[%s] in protocol.connection_lost: %s", self.name, exc)
        self.state = 'NOT_CONNECTED'
        self.transport = None
        self.on_connection_lost.set_result(False)
