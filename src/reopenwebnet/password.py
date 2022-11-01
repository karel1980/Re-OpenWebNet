from hashlib import sha1, sha256

import random

def calculate_open_password(password, nonce):
    m_1 = 0xFFFFFFFF
    m_8 = 0xFFFFFFF8
    m_16 = 0xFFFFFFF0
    m_128 = 0xFFFFFF80
    m_16777216 = 0XFF000000
    flag = True
    num1 = 0
    num2 = 0
    password = int(password)

    for c in nonce:
        num1 = num1 & m_1
        num2 = num2 & m_1
        if c == '1':
            length = not flag
            if not length:
                num2 = password
            num1 = num2 & m_128
            num1 = num1 >> 7
            num2 = num2 << 25
            num1 = num1 + num2
            flag = False
        elif c == '2':
            length = not flag
            if not length:
                num2 = password
            num1 = num2 & m_16
            num1 = num1 >> 4
            num2 = num2 << 28
            num1 = num1 + num2
            flag = False
        elif c == '3':
            length = not flag
            if not length:
                num2 = password
            num1 = num2 & m_8
            num1 = num1 >> 3
            num2 = num2 << 29
            num1 = num1 + num2
            flag = False
        elif c == '4':
            length = not flag

            if not length:
                num2 = password
            num1 = num2 << 1
            num2 = num2 >> 31
            num1 = num1 + num2
            flag = False
        elif c == '5':
            length = not flag
            if not length:
                num2 = password
            num1 = num2 << 5
            num2 = num2 >> 27
            num1 = num1 + num2
            flag = False
        elif c == '6':
            length = not flag
            if not length:
                num2 = password
            num1 = num2 << 12
            num2 = num2 >> 20
            num1 = num1 + num2
            flag = False
        elif c == '7':
            length = not flag
            if not length:
                num2 = password
            num1 = num2 & 0xFF00
            num1 = num1 + ((num2 & 0xFF) << 24)
            num1 = num1 + ((num2 & 0xFF0000) >> 16)
            num2 = (num2 & m_16777216) >> 8
            num1 = num1 + num2
            flag = False
        elif c == '8':
            length = not flag
            if not length:
                num2 = password
            num1 = num2 & 0xFFFF
            num1 = num1 << 16
            num1 = num1 + (num2 >> 24)
            num2 = num2 & 0xFF0000
            num2 = num2 >> 8
            num1 = num1 + num2
            flag = False
        elif c == '9':
            length = not flag
            if not length:
                num2 = password
            num1 = ~num2
            flag = False
        else:
            num1 = num2
        num2 = num1
    return num1 & m_1

def hmac_sha1(Ra_hexstring, Rb_hexstring, password):
    Kab_hexstring = sha1(password.encode()).hexdigest()

    # Client identity
    A='736F70653E'
    # Server identity
    B='636F70653E'

    return sha1((Ra_hexstring + Rb_hexstring + A + B + Kab_hexstring).encode()).hexdigest()

def hmac_sha2(Ra_hexstring, Rb_hexstring, password):
    Kab_hexstring = sha256(password.encode()).hexdigest()

    # Client identity
    A='736F70653E'
    # Server identity
    B='636F70653E'

    return sha256((Ra_hexstring + Rb_hexstring + A + B + Kab_hexstring).encode()).hexdigest()

def hex_to_wire(hexstring):
    wire=''
    for c in hexstring:
        wire += str(int(c,16)).zfill(2)

    return wire

def wire_to_hex(wire):
    result = ''
    for idx in range(0, len(wire), 2):
        pair = wire[idx:idx + 2]
        result += hex(int(pair))[2:]

    return result

def random_hexstring(length):
    return ("%%0%dx"%(length)) % random.randrange(16**length)
