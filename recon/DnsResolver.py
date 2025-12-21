import os
import socket
import subprocess

def IpConvertor(File):
    ResolvedIp = []  
    
    with open(File, 'r') as f:
        
        SubDomainList = [line.strip() for line in f if line.strip()]

    for SubDomain in SubDomainList:
        try:
            cmd = f"nslookup {SubDomain} | grep 'Address:' | tail -1 | awk '{{print $2}}'"
            results = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=10
            )

            if results.returncode == 0 and results.stdout.strip():
                ip = results.stdout.strip()  
                print(f"{SubDomain} --> {ip}")
                ResolvedIp.append(ip)  
            else:
                print(f"No IP found for {SubDomain}")

        except subprocess.TimeoutExpired:
            print(f"Timeout resolving {SubDomain}")
        except Exception as e:
            print(f"Error resolving {SubDomain}: {e}")

    return ResolvedIp  

def IpConvertorSocket(File):
    ResolvedIp = []

    with open(File, 'r') as f:
        SubDomainList = [line.strip() for line in f if line.strip()]

    for SubDomain in SubDomainList:
        try:
            ip = socket.gethostbyname(SubDomain)
            print(f"{SubDomain} --> {ip}")
            ResolvedIp.append(ip)
        except socket.gaierror:
            print(f"Couldn't resolve {SubDomain}")
        except Exception as e:
            print(f"Error with {SubDomain}: {e}")

    return ResolvedIp
