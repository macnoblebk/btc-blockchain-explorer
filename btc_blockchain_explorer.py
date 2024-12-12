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


def print_feefilter_message(feerate):
    prefix = PREFIX * 2
    print('{}{:32} count: {}'.format(prefix, feerate.hex(), unmarshal_uint(feerate)))


def print_addr_message(payload):
    ip_count_bytes, ip_addr_count = unmarshal_compactsize(payload)
    i = len(ip_count_bytes)
    epoch_time, services, ip_addr, port = (payload[i: i + 4], payload[i+4: i+12],
                                           payload[i + 12:i + 28], payload[i + 28:])
    prefix = PREFIX * 2
    print('{}{:32} count: {}'.format(prefix, ip_count_bytes.hex(), ip_addr_count))
    time_str = strftime("%a, %d %b %Y %H:%M:%S GMT", gmtime(unmarshal_int(epoch_time)))
    print('{}{:32} epoch time: {}'.format(prefix, epoch_time.hex(), time_str))
    print('{}{:32} services: {}'.format(prefix, services.hex(), unmarshal_uint(services)))
    print('{}{:32} host: {}'.format(prefix, ip_addr.hex(), ipv6_to_ipv4(ip_addr)))
    print('{}{:32} port: {}'.format(prefix, port.hex(), unmarshal_uint(port)))


def print_ping_pong_message(nonce):
    prefix = PREFIX * 2
    print('{}{:32} nonce: {}'.format(prefix, nonce.hex(), unmarshal_uint(nonce)))


def print_sendcmpct_message(payload):
    announce, version = payload[:1], payload[1:]
    prefix = PREFIX * 2
    print('{}{:32} announce: {}'.format(prefix, announce.hex(), bytes(announce) != b'\0'))
    print('{}{:32} version: {}'.format(prefix, version.hex(), unmarshal_uint(version)))


def print_block_message(payload):
    version, previous_block, merkle_root, epoch_time, bits, nonce = (payload[:4], payload[4:36],
                                                                     payload[36:68], payload[68:72],
                                                                     payload[72:76], payload[76:80])

    txn_count_bytes,  txn_count = unmarshal_compactsize(payload[80:])
    txns = payload[80 + len(txn_count_bytes):]

    prefix = PREFIX * 2
    print('{}{:32} version: {}\n{}-'
          .format(prefix, version.hex(), unmarshal_int(version), prefix))
    previous_hash = swap_endian(previous_block)
    print('{}{:32}\n{}{:32} previous block hash\n{}-'
          .format(prefix, previous_hash.hex()[:32], prefix, previous_hash.hex()[32:], prefix))
    merkle_hash = swap_endian(merkle_root)
    print('{}{:32}\n{}{:32} merkle root hash\n{}-'
          .format(prefix, merkle_hash.hex()[:32], prefix, merkle_hash.hex()[32:], prefix))
    time_str = strftime("%a, %d %b %Y %H:%M:%S GMT", gmtime(unmarshal_int(epoch_time)))
    print('{}{:32} epoch time: {}'.format(prefix, epoch_time.hex(), time_str))
    print('{}{:32} bits: {}'.format(prefix, bits.hex(), unmarshal_uint(bits)))
    print('{}{:32} nonce: {}'.format(prefix, nonce.hex(), unmarshal_uint(nonce)))
    print('{}{:32} transaction count: {}'.format(prefix, txn_count_bytes.hex(), txn_count))
    print_transaction(txns)


def print_transaction(txn_bytes):
    version = txn_bytes[:4]
    tx_in_count_bytes, tx_in_count = unmarshal_compactsize(txn_bytes[4:])
    i = 4 + len(tx_in_count_bytes)

    cb_txn, cb_script_bytes_count = parse_coinbase(txn_bytes[i:], version)
    tx_in_list = [cb_txn, cb_script_bytes_count]
    i += len(b''.join(cb_txn))

    for _ in range(1, tx_in_count):
        tx_in, script_bytes_count = parse_tx_in(txn_bytes[i:])
        tx_in_list.append((tx_in, script_bytes_count))
        i += len(b''.join(tx_in))

    tx_out_count_bytes, tx_out_count = unmarshal_compactsize(txn_bytes[i:])
    tx_out_list = []
    i += len(tx_out_count_bytes)

    for _ in range(tx_out_count):
        tx_out, pk_script_bytes_count = parse_tx_out(txn_bytes[i:])
        tx_out_list.append((tx_out, pk_script_bytes_count))
        i += len(b''.join(tx_out))

    lock_time = txn_bytes[i: i+4]

    prefix = PREFIX * 2
    print('{}{:32} version: {}'.format(prefix, version.hex(), unmarshal_uint(version)))

    print('\n{}Transaction Inputs:'.format(prefix))
    print(prefix + '-' * 32)
    print('{}{:32} input txn count: {}'.format(prefix, tx_in_count_bytes.hex(), tx_in_count))
    print_transaction_inputs(tx_in_list)

    print('\n{}Transaction Outputs:'.format(prefix))
    print(prefix + '-' * 32)
    print('{}{:32} output txn count: {}'.format(prefix, tx_out_count_bytes.hex(), tx_out_count))
    print_transaction_outputs(tx_out_list)

    print('{}{:32} lock time: {}'.format(prefix, lock_time.hex(), unmarshal_uint(lock_time)))
    if txn_bytes[i + 4:]:
        print('EXTRA: {}'.format(txn_bytes[i + 4:].hex()))


def print_transaction_inputs(tx_in_list):
    prefix = PREFIX * 2
    for i, tx_in in enumerate(tx_in_list, start=1):
        print('\n{} Transaction {}{}:'.format(prefix, i, ' (Coinbase)' if i == 1 else ''))
        print(prefix + '*' * 32)
        hash, index, script_bytes, sig_script, seq = tx_in[0]
        script_bytes_count = tx_in[1]
        print('{}{:32}\n{}{:32} hash\n{}-'.format(prefix, hash.hex()[:32], prefix, hash.hex()[32:], prefix))
        print('{}{:32} index: {}'.format(prefix, index.hex(), unmarshal_uint(index)))
        print('{}{:32} script bytes: {}'.format(prefix, script_bytes.hex(), script_bytes_count))
        print('{}{:32} {} script'.format(prefix, sig_script.hex(), 'coinbase ' if i == 1 else ''))
        print('{}{:32} sequence number'.format(prefix, seq.hex()))


def print_transaction_outputs(tx_out_list):
    prefix = PREFIX * 2
    for i, tx_out in enumerate(tx_out_list, start=1):
        print('\n{} Transaction {}:'.format(prefix, i))
        print(prefix + '*' * 32)
        value, pk_script_bytes, pk_script = tx_out[0]
        pk_script_bytes_count = tx_out[1]
        satoshis = unmarshal_uint(value)
        btc = sat_to_btc(satoshis)
        print('{}{:32} value: {} satoshis = {} BTC'.format(prefix, value.hex(), satoshis, btc))
        print('{}{:32} public key script length: {}\n{}-'
              .format(prefix, pk_script_bytes.hex(), pk_script_bytes_count, prefix))
        for j in range(0, pk_script_bytes_count * 2, 32):
            print('{}{:32}{}'.format(prefix, pk_script.hex()[j:j + 32],
                                     ' public key script\n{}-'.format(prefix)
                                     if j + 32 > pk_script_bytes_count * 2 else ''))


def parse_coinbase(cb_bytes, version):
    hash_null = cb_bytes[:32]
    index = cb_bytes[32:36]
    script_bytes, script_bytes_count = unmarshal_compactsize(cb_bytes[36:])
    i = 36 + len(script_bytes)

    height = None
    if unmarshal_uint(version) > 1:
        height = cb_bytes[i:i+4]
        i += 4

    cb_script = cb_bytes[i:i + script_bytes_count]
    sequence = cb_bytes[i + script_bytes_count: i + script_bytes_count + 4]

    if height:
        return [hash_null, index, script_bytes, height, cb_script, sequence], script_bytes_count
    else:
        return [hash_null, index, script_bytes, cb_script, sequence], script_bytes_count


def parse_tx_out(tx_out_bytes):
    value = tx_out_bytes[:8]
    pk_script_bytes, pk_script_bytes_count = unmarshal_compactsize(tx_out_bytes[8:])
    i = 8 + len(pk_script_bytes)
    pk_script = tx_out_bytes[i:i + pk_script_bytes_count]
    return [value, pk_script_bytes, pk_script], pk_script_bytes_count


def parse_tx_in(tx_in_bytes):
    hash = tx_in_bytes[:32]
    index = tx_in_bytes[32:36]
    script_bytes, script_bytes_count = unmarshal_compactsize(tx_in_bytes[36:])
    i = 36 + len(script_bytes)
    sig_script = tx_in_bytes[i:i + script_bytes_count]
    sequence = tx_in_bytes[i + script_bytes_count:]
    return [hash, index, script_bytes, sig_script, sequence], script_bytes_count


def split_message(peer_msg_bytes):
    msg_list = []
    while peer_msg_bytes:
        payload_size = unmarshal_uint(peer_msg_bytes[16:20])
        msg_size = HDR_SZ + payload_size
        msg_list.append(peer_msg_bytes[:msg_size])
        peer_msg_bytes = peer_msg_bytes[msg_size:]
    return msg_list


def get_last_block_hash(inv_bytes):
    return inv_bytes[len(inv_bytes) - 32:]


def update_current_height(block_list, current_height):
    header_size = 36
    offset = 27
    new_blocks = (len(block_list[-1]) - offset) // header_size
    return current_height + new_blocks


def exchange_messages(bytes_to_send, expected_bytes=None, height=None, wait=False):
    print_message(bytes_to_send, 'send', height=height)
    BTC_SOCKET.settimeout(0.5)
    bytes_received = b''

    try:
        BTC_SOCKET.sendall(bytes_to_send)

        if expected_bytes:
            while len(bytes_received) < expected_bytes:
                bytes_received += BTC_SOCKET.recv(BUFFER_SIZE)
        elif wait:
            while True:
                bytes_received += BTC_SOCKET.recv(BUFFER_SIZE)

    except Exception as e:
        print('\nNo bytes left to receive from {}: {}'.format(BTC_PEER_ADDRESS, str(e)))

    finally:
        print('\n****** Received {} bytes from BTC node {} ******'
              .format(len(bytes_received), BTC_PEER_ADDRESS))
        peer_msg_list = split_message(bytes_received)
        for msg in peer_msg_list:
            print_message(msg, 'receive', height)
        return peer_msg_list


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