import collections
import os
import re
import zlib

from scapy.all import rdpcap
from scapy.layers.http import HTTPRequest
from scapy.layers.inet import TCP

OUTDIR = './recapper'
PCAPS = './'
Response = collections.namedtuple('Response', ['header', 'payload'])

username_re = re.compile(r'uname=([^&]+)')
password_re = re.compile(r'pass=([^&]+)')


def get_header(payload):
    try:
        header_raw = payload[:payload.index(b'\r\n\r\n') + 2]
        header = dict(re.findall(r'(?P<name>.*?): (?P<value>.*?)\r\n', header_raw.decode()))
        if 'Content-Type' not in header:
            return None
        return header
    except ValueError:
        return None


def extract_content(response, content_name='image'):
    content, content_type = None, None
    if content_name in response.header['Content-Type']:
        content_type = response.header['Content-Type'].split('/')[1]
        content = response.payload[response.payload.index(b'\r\n\r\n') + 4:]
        if 'Content-Encoding' in response.header:
            if response.header['Content-Encoding'] == "gzip":
                content = zlib.decompress(content, zlib.MAX_WBITS | 32)
            elif response.header['Content-Encoding'] == "deflate":
                content = zlib.decompress(content)
    return content, content_type


def get_payload(session):
    payload = b''
    for packet in session:
        if packet.haslayer(TCP):
            payload += bytes(packet[TCP].payload)
    return payload


def get_session_data(session) -> tuple[str | None, str | None, str | None]:
    method = route = host = None
    for packet in session:
        if packet.haslayer(HTTPRequest):
            http_layer = packet[HTTPRequest]
            method = http_layer.Method.decode() if http_layer.Method else None
            route = http_layer.Path.decode() if http_layer.Path else None
            host = http_layer.Host.decode() if http_layer.Host else None
    return method, host, route


def extract_credentials(payload):
    decoded_payload = payload.decode('utf-8', errors='ignore')
    requests = re.split(r'(HEAD|GET|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH) ', decoded_payload)

    # Process each request
    for i in range(1, len(requests), 2):  # Starting from 1 to skip the initial part before the first method
        http_method = requests[i]
        http_body = requests[i + 1].split('\r\n\r\n', 1)[1] if '\r\n\r\n' in requests[i + 1] else requests[i + 1]

        if http_method == 'POST':
            # Search for username and password in the POST request body
            username_match = username_re.search(http_body)
            password_match = password_re.search(http_body)

            if username_match and password_match:
                return username_match.group(1), password_match.group(1)

    return None, None


class Recapper:
    def __init__(self, fname):
        self.sessions = rdpcap(fname).sessions()
        self.responses = []

    def process_sessions(self):
        for session in self.sessions.values():
            payload = get_payload(session)
            method, host, route = get_session_data(session)
            header = get_header(payload)
            if header:
                self.responses.append(Response(header=header, payload=payload))
            username, password = extract_credentials(payload)
            if username or password:
                print(f"Discovered credentials: username: {username},"
                      f" password: {password}"
                      f" request type: {method},"
                      f" route: {host}{route}\n")

    def write(self, content_name='image'):
        for i, response in enumerate(self.responses):
            content, content_type = extract_content(response, content_name)
            if content and content_type:
                fname = os.path.join(OUTDIR, f'ex_{i}.{content_type}')
                print(f'Writing {fname}')
                with open(fname, 'wb') as f:
                    f.write(content)


if __name__ == '__main__':
    pfile = os.path.join(PCAPS, 'target_pcap.pcap')
    recapper = Recapper(pfile)
    recapper.process_sessions()
    recapper.write()
