'''
Bit Peers

Usage:
  bitpeers --file=<filepath> [options]
  bitpeers -h | --help

Options:
  --output=FORMAT           Output file format: json or txt [default: json]
  -a --addresses-only     Only output addresses
  -h --help                 Show this screen.
'''


import hashlib
import sys
import socket
import json

from base64 import b32encode
from docopt import docopt

'''
Peers.dat organization
- Header
    - Message bytes (magic)
    - Version
    - KeySize
    - NKey
    - New Addresses (count)
    - Tried Addresses (count)
    - New Buckets (count)
- Data
    - Repeated
        - Peer (see class definition below)
    - Repeated
        - Bucket (see class definition below)
- Checksum
'''

#############
# CONSTANTS #
#############

# docs say it should be this but p2p network seems end b"\x00" x2
# IPV4_PREFIX = b"\x00" * 10 + b"\xff" * 2
IPV4_PREFIX = b"\x00" * 10 + b"\x00" * 2
ONION_PREFIX = b"\xFD\x87\xD8\x7E\xEB\x43"  # ipv6 prefix for .onion address
HEADER_SIZE_IN_BYTES = 50
PEER_SIZE_IN_BYTES = 62
CHECKSUM_SIZE_IN_BYTES = 32


###########
# CLASSES #
###########


# Represents an address
class Address:
    def __init__(self, serialization_version, time, service_flags, ip, port):
        self.serialization_version = serialization_version
        self.time = time
        self.service_flags = service_flags
        self.ip = ip
        self.port = port  # big_endian

    def __repr__(self):
        return f"Ser. Version: 0x{self.serialization_version.hex()} time: {self.time} "\
            + f"service_flags: {self.service_flags}, ip: {self.ip}, port: {self.port}"

    def to_dict(self):
        return {
            "serialization_version": self.serialization_version.hex(),
            "time": self.time,
            "service_flags": self.service_flags,
            "ip": self.ip,
            "port": self.port
        }


# Represents a peer - an address and some additional metadata
class Peer:
    def __init__(self, address, source, last_success, attempts):
        self.address = address
        self.source = source
        self.last_success = last_success
        self.attempts = attempts

    def __repr__(self):
        return f"{self.address}, source: {self.source}, last_success: {self.last_success}, attempts: {self.attempts}\n"

    def to_dict(self):
        address_dict = self.address.to_dict()
        address_dict['source'] = self.source
        address_dict['last_success'] = self.last_success
        address_dict['attempts'] = self.attempts
        return address_dict

    @classmethod
    def deserialize(cls, peer_data):
        serialization_version = peer_data[0:4]
        time = int.from_bytes(peer_data[4:8], 'little')
        service_flags = int.from_bytes(peer_data[8:16], 'little')
        ip = bytes_to_ip(peer_data[16:32])
        port = int.from_bytes(peer_data[32:34], 'big')
        source = bytes_to_ip(peer_data[34:50])
        last_success = int.from_bytes(peer_data[50:58], 'little')
        attempts = int.from_bytes(peer_data[58:PEER_SIZE_IN_BYTES], 'little')
        address = Address(serialization_version, time,
                          service_flags, ip, port)
        return cls(address, source, last_success, attempts)


# Represents a bucket - a list of peers
class Bucket:
    def __init__(self, size, peer_id_list=[]):
        self.size = size
        self.peer_id_list = peer_id_list

    def __repr__(self):
        return f"size: {self.size}, peers: {self.peer_id_list}\n"

    def to_dict(self):
        return {
            "size": self.size,
            "peer_id_list": self.peer_id_list
        }

    @classmethod
    def deserialize(cls, bucket_size, bytes):
        peer_index_list = []
        for i in range(bucket_size):
            chunk = bytes[i*4:(i+1)*4]
            peer_index_list.append(int.from_bytes(chunk, 'little'))
        return cls(bucket_size, peer_index_list)


# Represents the entire peers.dat file
class PeersDB:
    def __init__(self, path, message_bytes, version, key_size, new_address_count, tried_address_count, new_bucket_count):
        self.path = path
        self.message_bytes = message_bytes
        self.version = version
        self.key_size = key_size
        self.new_address_count = new_address_count
        self.tried_address_count = tried_address_count
        self.new_addresses = []
        self.tried_addresses = []
        self.new_bucket_count = new_bucket_count
        self.new_buckets = []

    def verify_address_counts(self):
        try:
            assert len(
                self.new_addresses) == self.new_address_count, "new address count differs"
            assert len(
                self.tried_addresses) == self.tried_address_count, "tried address count differs"
        except Exception:
            sys.exit("Address counts differ from read and actual")

    def summary(self):
        return f"PeersDB Summary:\n"\
            + f"Path: {self.path}\n" + f"Message Bytes (hex): {self.message_bytes.hex()}\n" + f"Version: {self.version}\n"\
            + f"Key Size: {self.key_size}\n"\
            + f"New Addresses (in header, actual): {self.new_address_count}, {len(self.new_addresses)} \n"\
            + f"Tried Addresses (in header, actual): {self.tried_address_count}, {len(self.tried_addresses)}\n"\
            + f"New Buckets (in header, actual): {self.new_bucket_count}, {len(self.new_buckets)}\n"

    def __repr__(self):
        summary = self.summary()
        summary += "\nNew addresses:\n"
        for peers in self.new_addresses:
            summary += str(peers)
        summary += "\nTried addresses:\n"
        for peers in self.tried_addresses:
            summary += str(peers)
        summary += "\nNew Buckets:\n"
        for bucket in self.new_buckets:
            summary += str(bucket)
        return summary

    def to_dict(self, addresses_only):
        addresses = {
            "new_addresses": [peer.to_dict() for peer in self.new_addresses],
            "tried_addresses": [peer.to_dict() for peer in self.tried_addresses],
        }
        if addresses_only:
            return addresses
        return {
            "path": self.path,
            "message_bytes": self.message_bytes.hex(),
            "version": self.version,
            "key_size": self.key_size,
            "new_addr_count": self.new_address_count,
            "tried_addr_count": self.tried_address_count,
            "new_bucket_count": self.new_bucket_count,
            **addresses,
            "new_buckets": [bucket.to_dict() for bucket in self.new_buckets]
        }

    ############################################
    # Class Methods - useful for deserializing #
    ############################################
    @classmethod
    def verify_serialized_data_integrity(cls, raw_data):
        try:
            # verify checksum
            read_checksum = raw_data[-CHECKSUM_SIZE_IN_BYTES:]
            calculated_checksum = hashlib.sha256(
                hashlib.sha256(raw_data[:-CHECKSUM_SIZE_IN_BYTES]).digest()).digest()
            assert read_checksum == calculated_checksum, "File checksum failed"

            # Verify file size is at least as long as the counts listed in header
            assert (len(raw_data)-HEADER_SIZE_IN_BYTES -
                    CHECKSUM_SIZE_IN_BYTES) % PEER_SIZE_IN_BYTES >= 0, "File length invalid"
        except Exception:
            sys.exit('File verification failed, exiting')

    # Reads header bytes and creates a PeerDB object
    @classmethod
    def deserialize_header_data(cls, filename, data):
        message_bytes = data[:4]  # magic bytes
        version = data[4]  # always 1
        key_size = data[5]  # always 32
        next_marker = 6+32
        # TODO: figure out why this is needed or used
        #nkey = data[6:next_marker]
        new_address_count = int.from_bytes(
            data[next_marker:next_marker+4], 'little')
        tried_address_count = int.from_bytes(
            data[next_marker+4:next_marker+8], 'little')
        buckets = int.from_bytes(
            data[next_marker+8:next_marker+12], 'little') ^ (1 << 30)
        try:
            assert message_bytes == b'\xf9\xbe\xb4\xd9'
            assert version == 1
            assert key_size == 32
        except Exception as e:
            sys.exit(f"Invalid header {str(e)}, exiting")
        return cls(path=filename, message_bytes=message_bytes, version=version,
                   key_size=key_size, new_address_count=new_address_count, tried_address_count=tried_address_count,
                   new_bucket_count=buckets)

    # Reads raw bytes of list of peers and returns the list with Peer objects
    @classmethod
    def deserialize_peer_list(cls, peer_count, peer_list_data):
        return [Peer.deserialize(peer_list_data[i*PEER_SIZE_IN_BYTES:(i+1)*PEER_SIZE_IN_BYTES]) for i in range(peer_count)]

    # Takes in bucket data and creates buckets
    @classmethod
    def deserialize_buckets(cls, bucket_count_expected, data):
        buckets = []
        marker = 0
        bucket_count_actual = 0
        while marker < len(data):
            num = data[marker:4+marker]
            bucket_size = int.from_bytes(num, 'little')
            if (bucket_size > 0):
                bucket = Bucket.deserialize(
                    bucket_size, data[4+marker:4+marker+4*bucket_size])
                marker += bucket_size*4
            else:
                bucket = Bucket(0)
            buckets.append(bucket)
            bucket_count_actual += 1
            marker += 4
        try:
            assert bucket_count_actual == bucket_count_expected
            return buckets
        except Exception:
            print("Bucket counts not matching, discarding all bucket data")
            return []

    # Takes in raw bytes from a peers.dat and returns a completed PeersDB object
    @classmethod
    def deserialize(cls, filename, raw_data):
        # Verify checksum matches
        cls.verify_serialized_data_integrity(raw_data)

        # create peerdb instance with header data
        peers_db = cls.deserialize_header_data(filename, raw_data)

        # import new addresses
        new_address_count = peers_db.new_address_count
        peers_db.new_addresses = cls.deserialize_peer_list(
            new_address_count, raw_data[HEADER_SIZE_IN_BYTES:])

        # import tried addresses
        peers_db.tried_addresses = cls.deserialize_peer_list(
            peers_db.tried_address_count, raw_data[HEADER_SIZE_IN_BYTES+(PEER_SIZE_IN_BYTES*new_address_count):])

        # Verify address counts
        peers_db.verify_address_counts()

        # read and create buckets
        total_peers = peers_db.new_address_count + peers_db.tried_address_count
        bucket_data_start = HEADER_SIZE_IN_BYTES + total_peers*PEER_SIZE_IN_BYTES
        bucket_data = raw_data[bucket_data_start:-CHECKSUM_SIZE_IN_BYTES]
        peers_db.new_buckets = cls.deserialize_buckets(
            peers_db.new_bucket_count, bucket_data)
        return peers_db


###########
# HELPERS #
###########
# Convert 16 bytes to ipv4, v6 or onion address
def bytes_to_ip(b):
    if b[:6] == ONION_PREFIX:
        return b32encode(b[6:]).lower().decode("ascii") + ".onion"
    elif b[0:12] == IPV4_PREFIX:  # IPv4
        return socket.inet_ntop(socket.AF_INET, b[12:16])
    else:  # IPv6
        return socket.inet_ntop(socket.AF_INET6, b)


# Reads a file
def read_file(filename):
    print(f"\nReading file: {filename}")
    with open(filename, 'rb') as p:
        filedata = p.read()
    print(f"File loaded: {len(filedata)} bytes\n")
    return filedata


########
# Main #
########
def bitpeers(filename, output, addresses_only):
    print("Starting...")

    # ingest file
    raw_data = read_file(filename)

    # deserialize data from file
    peers_db = PeersDB.deserialize(filename, raw_data)

    # Print summary
    print(peers_db.summary())

    # Now figure out output, if any is needed

    if output == 'json':
        output_file = "output.json"
        peers_db_dict = peers_db.to_dict(addresses_only)
        with open(output_file, 'w') as outfile:
            json.dump(peers_db_dict, outfile)
        print(f"Created {output_file}")
    elif output == 'txt':
        output_file = "output.txt"
        peers_db_txt = str(peers_db)
        with open(output_file, 'w') as outfile:
            outfile.write(peers_db_txt)
    else:
        print("output must be json or txt")


if __name__ == "__main__":

    # get commandline arguments
    arguments = docopt(__doc__)
    filename = arguments['--file']

    if '--output' in arguments:
        output = arguments['--output']
    else:
        output = None

    addresses_only = arguments['--addresses-only']

    # Call main function
    bitpeers(filename, output, addresses_only)
