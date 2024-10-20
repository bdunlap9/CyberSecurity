import logging, sys
from scapy.all import *

# Logging Scapy Errors
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)

class PortScanner:
    def __init__(self, target, startport, endport):
        self.target = target
        self.startport = startport
        self.endport = endport
        self.open_ports = []

    def scan_ports(self):
        print(f'''
            Scanning {self.target} for open TCP Ports
            Port Range: {self.startport} - {self.endport}
        ''')
        
        for port in range(self.startport, self.endport):
            pkt = IP(dst=self.target) / TCP(dport=port, flags='S')  # Create a SYN packet
            resp = sr1(pkt, timeout=1, verbose=0)

            if resp is None:
                continue
            elif resp.haslayer(TCP):
                if resp[TCP].flags == 0x12:  # SYN-ACK
                    self.open_ports.append(port)
                    rst_pkt = IP(dst=self.target) / TCP(dport=port, flags='R')
                    send(rst_pkt, verbose=0)
                    print(f'Port {port}: Open')
                elif resp[TCP].flags == 0x14:  # RST
                    # print(f'Port {port}: Closed')
                    continue

    def report_open_ports(self):
        if self.open_ports:
            print(f'\nOpen ports: {", ".join(map(str, self.open_ports))}')
        else:
            print('No open ports found.')

def main():
    print('''Port Scanner v1.0''')

    if len(sys.argv) != 4:  # port_scanner.py 127.0.0.1 1 65535
        print('Invalid arguments given!')
        print('Usage: %s target startport endport' % (sys.argv[0]))
        sys.exit(1)

    target = str(sys.argv[1])
    startport = int(sys.argv[2])
    endport = int(sys.argv[3])

    if startport == endport:
        endport += 1

    scanner = PortScanner(target, startport, endport)
    scanner.scan_ports()
    scanner.report_open_ports()

if __name__ == '__main__':
    main()
