from subdomain import GetSubDomain
from IpExtraction import Extraction
from Domain import DomainHandler
from IpHandler import IpHandler

print(f"""
    ╔══════════════════════════════════════════════╗
    ║         FSOCIETY RECON PIPELINE              ║
    ║           v1.0 - Automated Recon             ║
    ╚══════════════════════════════════════════════╝""")

print("\n\n")
print("""
	If you have a domain name press: 1
	if you have an ip press: 2
	""")

choice = input("Enter Your choice: ")

# Handle Domain
if choice == '1':
	domain = input("Enter Domain name: ")
	print(domain)
	DomainHandler(domain) # pass to our function


# Ip Handling
elif choice == '2':
	print("\nIP Entry Options:")
	print("1. Single IP address")
	print("2. Multiple IP addresses (comma-separated)")
    
	ip_choice = input("Choose option (1-3): ")
    
	if ip_choice == '1':
		ip = input("Enter IP address: ").strip()
		ips = [ip]
    
	elif ip_choice == '2':
		ip_input = input("Enter IP addresses (comma-separated): ").strip()
		ips = [ip.strip() for ip in ip_input.split(',')]
	else:
		print(" Enter a Valid Choice")
		exit(1)

	IpHandler(ips) # our Further Ip Operation Handler

# Invalid Input Handling
else:
	print("Enter a valid choice")
	exit

