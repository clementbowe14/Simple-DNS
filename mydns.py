from ast import parse
from cProfile import label
import sys
from socket import socket, AF_INET, SOCK_DGRAM

found = False


# create DNS query message
class DNSRecord:
    def __init__(self, domain='', type=0, class_type=0, ttl=0, rd_length=0, ip='', name=''):
        self.domain = domain
        self.ttl = ttl
        self.rd_length = rd_length
        self.class_type = class_type
        self.type = type
        self.ip = ip
        self.name = name

    def print_record(self, record_type='A'):
        if len(self.domain) > 0:
            print(f'Name: {self.name}\t Name Server: {self.domain}')
        else:
            print(f'Name: {self.name}\t IP: {self.ip}')


def create_query(id, domain_name):
    # query header [RFC 4.1.1. Header section format]
    #                                 1  1  1  1  1  1
    #   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                      ID                       |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                    QDCOUNT                    |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                    ANCOUNT                    |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                    NSCOUNT                    |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                    ARCOUNT                    |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    first_row = (id).to_bytes(2, byteorder='big')
    second_row = (0).to_bytes(2, byteorder='big')
    qdcount = (1).to_bytes(2, byteorder='big')
    ancount = (0).to_bytes(2, byteorder='big')
    nscount = (0).to_bytes(2, byteorder='big')
    arcount = (0).to_bytes(2, byteorder='big')
    header = first_row + second_row + qdcount + ancount + nscount + arcount

    # question section [RFC 4.1.2. Question section format]
    #                                 1  1  1  1  1  1
    #   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                                               |
    # /                     QNAME                     /
    # /                                               /
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                     QTYPE                     |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                     QCLASS                    |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

    # initialize qname as empty bytes
    qname = b''

    # split domain name into labels
    labels = domain_name.split('.')
    for label in labels:
        qname += len(label).to_bytes(1, byteorder='big')  # length byte
        qname += bytes(label, 'utf-8')  # label bytes
    qname += (0).to_bytes(1, byteorder='big')  # zero length byte as end of qname

    qtype = (1).to_bytes(2, byteorder='big')
    qclass = (1).to_bytes(2, byteorder='big')
    question = qname + qtype + qclass

    return header + question


# parse byte_length bytes from index as unsigned integer


def parse_int(index, byte_length, response, signed=False):
    num = int.from_bytes(
        response[index: index + byte_length], "big", signed=signed)
    return num, index + byte_length


# response is the raw binary response received from server

def get_word(index, size, response):
    return response[index + 1: index + size + 1].decode('utf-8'), index + size + 1


def parse_domain(index, response, cache, address=False):
    domain = ''
    start = True
    label_size = response[index]

    print(f'Parsing domain starting from the index {index}')
    while label_size != 0:
        print(f'Current index: {index}\t Current label size: {label_size}')
        start_index = index
        if start == False:
            domain += '.'

        if label_size == 192:
            # convert binary string to a pointer removing first two bits
            start_location = response[index + 1]
            print(f'A pointer has been found with the starting location {start_location}')
            index += 1
            sub_domain, _ = parse_domain(start_location, response, cache)
            domain += sub_domain
            label_size = 0
        else:
            word, index = get_word(index, label_size, response)
            print(f'Word parsed from response: {word}')
            domain += word
            label_size = response[index]
            if address:
                label_size = 0

        print(f'Next label size {label_size}')
        start = False

    print(f'Resulting domain {domain}')

    return domain, index + 1


def parse_ip_address(index, response):
    start = index
    vals = []
    while start < index + 4:
        vals.append(str(response[start]))
        start += 1
    ip_address_number = '.'.join(vals)
    print(f'Resulting ip address {ip_address_number}')
    return ip_address_number, index + 4


def get_dns_record(index, response, cache, address=False):
    record = DNSRecord()
    # name
    record.name, index = parse_domain(index, response, cache)
    print(f'Record name {record.name}')
    # type
    record.type, index = parse_int(index, 2, response)
    print(f'Record type {record.type}')
    # class
    record.class_type, index = parse_int(index, 2, response)
    print(f'Record class {record.class_type}')

    # ttl
    record.ttl, index = parse_int(index, 4, response, True)
    print(f'Record Time to live {record.ttl}')

    record.rd_length, index = parse_int(index, 2, response)
    print(f'Record Data Length {record.rd_length}')
    if not address:
        record.domain, index = parse_domain(index, response, cache)
    else:
        record.ip, index = parse_ip_address(index, response)

    return record, index


def parse_response(response, answer_results, name_server_results, additional_results):
    print('----- parse response -----')
    # current byte index
    index = 0
    cache = {}
    # query header [RFC 4.1.1. Header section format]
    #                                 1  1  1  1  1  1
    #   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                      ID                       |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                    QDCOUNT                    |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                    ANCOUNT                    |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                    NSCOUNT                    |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                    ARCOUNT                    |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

    num, index = parse_int(index, 2, response)
    print(f'ID: {num}')

    # skip the next 2 bytes, i.e., second row
    index += 2

    qd_count, index = parse_int(index, 2, response)
    print(f'QDCOUNT: {qd_count}')

    ans_count, index = parse_int(index, 2, response)

    print(f'{ans_count} Answers.')

    ns_count, index = parse_int(index, 2, response)
    print(f'{ns_count} Immediate name servers')

    ar_count, index = parse_int(index, 2, response)
    print(f'{ar_count} Additional Information Records')

    query_name, index = parse_domain(index, response, cache)
    print(f'Query Domain: {query_name}')

    query_type, index = parse_int(index, 2, response, False)
    print(f'Query type: {query_type}')
    query_class, index = parse_int(index, 2, response)
    print(f'Query class: {query_class}')

    print("Answer section:")
    while (ans_count > 0):
        dns_response, index = get_dns_record(index, response, cache, address=True)
        answer_results.append(dns_response)
        ans_count -= 1

    print('Authority Section')
    while (ns_count > 0):
        dns_response, index = get_dns_record(index, response, cache)
        name_server_results.append(dns_response)
        ns_count -= 1

    print('Additional Infomation')
    while (ar_count > 0):
        dns_response, index = get_dns_record(index, response, cache, address=True)
        additional_results.append(dns_response)
        ar_count -= 1


# get domain-name and root-dns-ip from command line
if len(sys.argv) != 3:
    print('Usage: mydns domain-name root-dns-ip')
    sys.exit()
domain_name = sys.argv[1]
root_dns_ip = sys.argv[2]

# create UDP socket for DNS client
socket = socket(AF_INET, SOCK_DGRAM)

# send DNS query

'''
convert the code below into a loop that continues until the answer results > 0

After the query responses are added to the lists
set the next ip_address to one of the ip addresses in the additional_results list
'''
name_server_results = []
answer_results = []
additional_results = []
while len(answer_results) <= 0:
    query = create_query(1, domain_name)
    print(f'DNS server to query: {domain_name}')
    socket.sendto(query, (root_dns_ip, 53))
    response, server_address = socket.recvfrom(2048)

    parse_response(response, answer_results, name_server_results, additional_results)

    print("Answer section:")
    if len(answer_results) > 0:
        for server in answer_results:
            server.print_record()

    print('Authority Section:')
    if len(name_server_results) > 0:
        for server in name_server_results:
            server.print_record()

    if len(additional_results) > 0:
        for server in additional_results:
            server.print_record()

    root_dns_ip = additional_results[0].ip
    name_server_results = []
    additional_results = []
