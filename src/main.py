#! /usr/bin/python3

import nmap

scanner = nmap.PortScanner()

print("""
    =======================================================================
    | Pymap - Nmap automation tool by VMLinuxPr0gramm3r written in Python |
    | https://github.com/VMLinuxPr0gramm3r                                |
    =======================================================================
""")

def main():
    ip_addr = input("Enter the ip adress of the machine you want to scan: ")
    print("using target ip adress: "+ip_addr)

    resp = input(""" \n Enter the type of scan you want to perform
                    1) SYN ACK Scan
                    2) UDP Scan
                    3) Comprehensive Scan
                    4) Agressive Scan
                    5) Operating System Scan\n""")

    print("option selected: "+resp)

    if resp == "1":
        print("Nmap Version: ",scanner.nmap_version())
        scanner.scan(ip_addr, "1-1024", "-v -sS")
        print(scanner.scaninfo())
        print("IP status: ", scanner[ip_addr].state())
        print(scanner[ip_addr].all_protocols())
        print("Open ports: ", scanner[ip_addr]['mode: tcp'].keys())
    elif resp == '2':
        print("Nmap Version: ",scanner.nmap_version())
        scanner.scan(ip_addr, "1-1024", "-v -sU")
        print(scanner.scaninfo())
        print("IP status: ", scanner[ip_addr].state())
        print(scanner[ip_addr].all_protocols())
        print("Open ports: ", scanner[ip_addr]['mode: udp'].keys())
    elif reps == '3':
        print("Nmap Version: ",scanner.nmap_version())
        scanner.scan(ip_addr, "1-1024", "-v -sS -sV -sC -O")
        print(scanner.scaninfo())
        print("IP status: ", scanner[ip_addr].state())
        print(scanner[ip_addr].all_protocols())
        print("Open ports: ", scanner[ip_addr]['mode: agressive'].keys())
    elif resp == '4':
        print("Nmap Version: ",scanner.nmap_version())
        scanner.scan(ip_addr, "1-1024", "-v -A")
        print(scanner.scaninfo())
        print("IP status: ", scanner[ip_addr].state())
        print(scanner[ip_addr].all_protocols())
        print("Open ports: ", scanner[ip_addr]['mode: agressive'].keys())
    elif resp == '5':
        print("Nmap Version: ",scanner.nmap_version())
        scanner.scan(ip_addr, "1-1024", "-v -O")
        print(scanner.scaninfo())
        print("IP status: ", scanner[ip_addr].state())
        print(scanner[ip_addr].all_protocols())
        print("Open ports: ", scanner[ip_addr]['mode: os-detection'].keys())
    else:
        print("Option out of range")

if __name__ == '__main__':
    main()
