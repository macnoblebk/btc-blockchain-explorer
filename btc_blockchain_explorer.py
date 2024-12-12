import hashlib
import random
import time
import socket
import sys
from time import strftime, gmtime


BUFFER_SIZE = 4096
BTC_HOST = '3.65.33.103'
BTC_PORT = 8333
BTC_PEER_ADDRESS = (BTC_HOST, BTC_PORT)
BTC_SOCKET = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
MAX_BLOCKS = 500
GENESIS_BLOCK = bytes.fromhex('000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f')
VERSION = 70015
START_STRING = bytearray.fromhex('f9beb4d9')
HDR_SZ = 24
BLOCK_NUMBER = 1234567 % 10_000
COMMAND_SIZE = 12
EMPTY_STRING = ''.encode()
LOCALHOST = '127.0.0.1'
PREFIX = '  '
SATOSHIS_PER_BTC = 100_000_000


def construct_message(command, payload):
    return message_header(command, payload) + payload


def message_header(command, payload):
    magic = START_STRING
    command_name = command.encode('ascii')
    while len(command_name) < COMMAND_SIZE:
        command_name += b'\0'
    payload_size = uint32_t(len(payload))
    csum = checksum(payload)
    return b''.join([magic, command_name, payload_size, csum])


def checksum(payload: bytes):
    return hash(payload)[:4]


def hash(payload: bytes):
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()


def version_message():
    version = int32_t(VERSION)
    services = uint64_t(0)
    timestamp = uint64_t(int(time.time()))
    addr_recv_services = uint64_t(1)
    addr_recv_ip_address = ipv6_from_ipv4(BTC_HOST)
    addr_recv_port = uint16_t(BTC_PORT)
    addr_trans_services = uint64_t(0)
    addr_trans_ip_address = ipv6_from_ipv4(LOCALHOST)
    addr_trans_port = uint16_t(BTC_PORT)
    nonce = uint64_t(0)
    user_agent_bytes = compactsize_t(0)
    start_height = uint32_t(0)
    relay = bool_t(False)

    return b''.join([version + services + timestamp + addr_recv_services + addr_recv_ip_address +
                     addr_recv_port + addr_trans_services + addr_trans_ip_address + addr_trans_port +
                     nonce + user_agent_bytes + start_height + relay])


def getdata_message(tx_type, header_hash):
    count = compactsize_t(1)
    entry_type = uint32_t(tx_type)
    entry_hash = bytes.fromhex(header_hash.hex())
    return count + entry_type + entry_hash


def getblocks_message(header_hash):
    version = uint32_t(VERSION)
    hash_count = compactsize_t(1)
    block_header_hash = bytes.fromhex(header_hash.hex())
    end_hash = b'\0' * 32
    return b''.join([version + hash_count + block_header_hash + end_hash])


def ping_message():
    return uint64_t(random.getrandbits(64))


def sat_to_btc(sat):
    return sat / SATOSHIS_PER_BTC


def btc_to_sat(btc):
    return int(btc * SATOSHIS_PER_BTC)

def compactsize_t(n):
    if n < 252:
        return uint8_t(n)
    if n < 0xffff:
        return uint8_t(0xfd) + uint16_t(n)
    if n < 0xffffffff:
        return uint8_t(0xfe) + uint32_t(n)
    return uint8_t(0xff) + uint64_t(n)


def unmarshal_compactsize(b):
    key = b[0]
    if key == 0xff:
        return b[0:9], unmarshal_uint(b[1:9])
    if key == 0xfe:
        return b[0:5], unmarshal_uint(b[1:5])
    if key == 0xfd:
        return b[0:3], unmarshal_uint(b[1:3])
    return b[0:1], unmarshal_uint(b[0:1])


def bool_t(flag):
    return uint8_t(1 if flag else 0)


def ipv6_from_ipv4(ipv4_str):
    pchIPv4 = bytearray([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff])
    return pchIPv4 + bytearray((int(x) for x in ipv4_str.split('.')))


def ipv6_to_ipv4(ipv6):
    return '.'.join([str(b) for b in ipv6[12:]])


def uint8_t(n):
    return int(n).to_bytes(1, byteorder='little', signed=False)


def uint16_t(n, byteorder='little'):
    return int(n).to_bytes(2, byteorder=byteorder, signed=False)


def int32_t(n):
    return int(n).to_bytes(4, byteorder='little', signed=True)


def uint32_t(n):
    return int(n).to_bytes(4, byteorder='little', signed=False)


def int64_t(n):
    return int(n).to_bytes(8, byteorder='little', signed=True)


def uint64_t(n):
    return int(n).to_bytes(8, byteorder='little', signed=False)


def unmarshal_int(b):
    return int.from_bytes(b, byteorder='little', signed=True)


def unmarshal_uint(b, byteorder='little'):
    return int.from_bytes(b, byteorder=byteorder, signed=False)


def swap_endian(b: bytes):
    swapped = bytearray.fromhex(b.hex())
    swapped.reverse()
    return swapped


def print_message(msg, text=None, height=None):
    """
    Prints the details of a Bitcoin message, including its header and payload.

    Args:
        msg (bytes): The complete Bitcoin protocol message.
        text (str, optional): A label for the message (e.g., 'send', 'receive').
        height (int, optional): The block height associated with the message.

    Returns:
        str: The command name of the message (e.g., 'version', 'ping').
    """
    print('\n{}MESSAGE'.format('' if text is None else (text + ' ')))
    print('({}) {}'.format(len(msg), msg[:60].hex() + ('' if len(msg) < 60 else '...')))
    payload = msg[HDR_SZ:]
    command = print_header(msg[:HDR_SZ], checksum(payload))

    if payload:
        header_hash = swap_endian(hash(payload[:80])).hex() if command == 'block' else ''
        print('{}{} {}'.format(PREFIX, command.upper(), header_hash))
        print(PREFIX + '-' * 56)

    elif command == 'version':
        print_version_msg(payload)
    elif command == 'addr':
        print_addr_message(payload)
    elif command == 'feefilter':
        print_feefilter_message(payload)
    elif command == 'getblocks':
        print_getblocks_message(payload)
    elif command == 'sendcmpct':
        print_sendcmpct_message(payload)
    elif command == 'ping' or command == 'pong':
        print_ping_pong_message(payload)
    elif command == 'inv' or command == 'getdata' or command == 'notfound':
        print_inv_message(payload, height)
    elif command == 'block':
        print_block_message(payload)
    return command


def print_inv_message(payload, height):
    count_bytes, count = unmarshal_compactsize(payload)
    i = len(count_bytes)
    inventory = []
    for _ in range(count):
        inv_entry = payload[i: i+4], payload[i+4: i+36]
        inventory.append(inv_entry)
        i += 36

    prefix = PREFIX * 2
    print('{}{:32} count: {}'.format(prefix, count_bytes.hex(), count))
    for i, (tx_type, tx_hash) in enumerate(inventory, start=height if height else 1):
        print('\n{}{:32} type: {}\n{}-'
              .format(prefix, tx_type.hex(), unmarshal_uint(tx_type), prefix))
        block_hash = swap_endian(tx_hash).hex()
        print('{}{:32}\n{}{:32} block {} hash'.format(prefix, block_hash[:32], prefix, block_hash[32:], i))


def print_getblocks_message(payload):
    version = payload[:4]
    hash_count_bytes, hash_count = unmarshal_compactsize(payload[4:])
    i = 4 + len(hash_count_bytes)
    block_header_hashes = []
    for _ in range(hash_count):
        block_header_hashes.append(payload[i: i+32])
        i += 32
    stop_hash = payload[i:]

    prefix = PREFIX * 2
    print('{}{:32} version: {}'.format(prefix, version.hex(), unmarshal_uint(version)))
    print('{}{:32} hash count: {}'.format(prefix, hash_count_bytes.hex(), hash_count))
    for hash in block_header_hashes:
        hash_hex = swap_endian(hash).hex()
        print('\n{}{:32}\n{}{:32} block header hash # {}: {}'
              .format(prefix, hash_hex[:32], prefix, hash_hex[32:], 1, unmarshal_uint(hash)))
        stop_hash_hex = stop_hash.hex()
        print('\n{}{:32}\n{}{:32} stop hash: {}'
              .format(prefix, stop_hash_hex[:32], prefix, stop_hash_hex[32:], unmarshal_uint(stop_hash)))


def print_version_msg(b):
    """
    Report the contents of the given bitcoin version message (sans the header)
    :param payload: version message contents
    """
    # pull out fields
    version, my_services, epoch_time, your_services = b[:4], b[4:12], b[12:20], b[20:28]
    rec_host, rec_port, my_services2, my_host, my_port = b[28:44], b[44:46], b[46:54], b[54:70], b[70:72]
    nonce = b[72:80]
    user_agent_size, uasz = unmarshal_compactsize(b[80:])
    i = 80 + len(user_agent_size)
    user_agent = b[i:i + uasz]
    i += uasz
    start_height, relay = b[i:i + 4], b[i + 4:i + 5]
    extra = b[i + 5:]

    # print report
    prefix = '  '
    print(prefix + 'VERSION')
    print(prefix + '-' * 56)
    prefix *= 2
    print('{}{:32} version {}'.format(prefix, version.hex(), unmarshal_int(version)))
    print('{}{:32} my services'.format(prefix, my_services.hex()))
    time_str = strftime("%a, %d %b %Y %H:%M:%S GMT", gmtime(unmarshal_int(epoch_time)))
    print('{}{:32} epoch time {}'.format(prefix, epoch_time.hex(), time_str))
    print('{}{:32} your services'.format(prefix, your_services.hex()))
    print('{}{:32} your host {}'.format(prefix, rec_host.hex(), ipv6_to_ipv4(rec_host)))
    print('{}{:32} your port {}'.format(prefix, rec_port.hex(), unmarshal_uint(rec_port, 'big')))
    print('{}{:32} my services (again)'.format(prefix, my_services2.hex()))
    print('{}{:32} my host {}'.format(prefix, my_host.hex(), ipv6_to_ipv4(my_host)))
    print('{}{:32} my port {}'.format(prefix, my_port.hex(), unmarshal_uint(my_port, 'big')))
    print('{}{:32} nonce'.format(prefix, nonce.hex()))
    print('{}{:32} user agent size {}'.format(prefix, user_agent_size.hex(), uasz))
    print('{}{:32} user agent \'{}\''.format(prefix, user_agent.hex(), str(user_agent, encoding='utf-8')))
    print('{}{:32} start height {}'.format(prefix, start_height.hex(), unmarshal_uint(start_height)))
    print('{}{:32} relay {}'.format(prefix, relay.hex(), bytes(relay) != b'\0'))
    if len(extra) > 0:
        print('{}{:32} EXTRA!!'.format(prefix, extra.hex()))


def print_header(header, expected_cksum=None):
    """
    Report the contents of the given bitcoin message header
    :param header: bitcoin message header (bytes or bytearray)
    :param expected_cksum: the expected checksum for this version message, if known
    :return: message type
    """
    magic, command_hex, payload_size, cksum = header[:4], header[4:16], header[16:20], header[20:]
    command = str(bytearray([b for b in command_hex if b != 0]), encoding='utf-8')
    psz = unmarshal_uint(payload_size)
    if expected_cksum is None:
        verified = ''
    elif expected_cksum == cksum:
        verified = '(verified)'
    else:
        verified = '(WRONG!! ' + expected_cksum.hex() + ')'
    prefix = '  '
    print(prefix + 'HEADER')
    print(prefix + '-' * 56)
    prefix *= 2
    print('{}{:32} magic'.format(prefix, magic.hex()))
    print('{}{:32} command: {}'.format(prefix, command_hex.hex(), command))
    print('{}{:32} payload size: {}'.format(prefix, payload_size.hex(), psz))
    print('{}{:32} checksum {}'.format(prefix, cksum.hex(), verified))
    return command