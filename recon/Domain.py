from subdomain import GetSubDomain
from IpExtraction import Extraction
from utility import FileGenarator,Create_Domain_Directory
from DnsResolver import IpConvertor,IpConvertorSocket
from IpHandler import IpHandler
import os

def DomainHandler(domain, project_name=None):
	# Decouple target from output directory
	target = domain
	output_dir_name = project_name if project_name else domain

	print("----Domain Selected" ,target,"Starting Domain Flow---------")
	print(f"----Project Directory: results/{output_dir_name}---------")
	
	Data = GetSubDomain(target)
	SubDomains= []
	ResolvedIp = []
	print(Data)
	# getting all subdomains
	for SubDomain in Data.get('SubDomain',[]):
		for l in SubDomain :
			if l not in SubDomains:
				SubDomains.append(l)
	
	# For IP
	for IPs in Data.get('IP',[]):
		for ip in IPs:
			if ip not in ResolvedIp:
				ResolvedIp.append(ip)
	print(ResolvedIp)
	
	# Creating a result+Domain Directory based on project_name
	Domain_Dir = Create_Domain_Directory(output_dir_name)
	
	print(f"---------Creating a FIle for SubDomain Report in {Domain_Dir}-------------------")
	# Creating a File For SubDomain
	Name = target + 'SubDomain' + 'Report'
	SubDomain_File = os.path.join(Domain_Dir,FileGenarator(Name))
	with open(SubDomain_File, 'w')  as f:
		for subdomain in SubDomains:
			f.write(subdomain)


	print(f"-------------File Saved at {SubDomain_File}----------------------")

	print(f'-----------Starting Ip Extraction------------------------')
	SubDomain_IP= IpConvertor(SubDomain_File)
	SubDomain_IP.extend(IpConvertorSocket(SubDomain_File))
	# Extracting Unique Ip
	All_ResolvedIp = list(set(ResolvedIp + SubDomain_IP))
	
	# Create a File for Final IP
	Name = target + 'IPs' + 'Report'
	IP_File = os.path.join(Domain_Dir,FileGenarator(Name))
	
	with open(IP_File, 'w') as f:
		for ip in All_ResolvedIp:
			f.write(ip+ '\n')
	

		


    
	# Pass project_name to IpHandler
	IpHandler(All_ResolvedIp, domain=target, Subdomain_File=SubDomain_File, project_name=output_dir_name)
    
