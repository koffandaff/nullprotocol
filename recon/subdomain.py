import os
from utility import FileGenarator
from IpExtraction import Extraction
from SubDomainExtraction import SubDomainExtraction
from rich.progress import (
    Progress,
    BarColumn,
    TextColumn,
    TimeRemainingColumn,
    TimeElapsedColumn,
    SpinnerColumn,
    TaskProgressColumn
)
import time

# Custom progress bar with multiple columns
progress = Progress(
    SpinnerColumn(),
    TextColumn("[progress.description]{task.description}"),
    BarColumn(),
    TaskProgressColumn(),
    TextColumn("•"),
    TimeRemainingColumn(),
    TextColumn("•"),
    TimeElapsedColumn(),
)




# Class to automate tasks for each ip of the list
class SubDomain():
	def __init__(self,domain):
		self.domain = domain
		self.SubDomains = [] # Initialzing All subdomain list
		self.IP = [] # Intializing Ip
		
		# Calling functions that extract subdomain
		self.Dnsrecon()
		self.FindDomain()
		
	# DnsRecon to list all Subdomain
	def Dnsrecon(self):
		print("----------------Trying Dnsrecon-------------------")
		FileName = FileGenarator(self.domain) # utility function that creates Unique File name
		os.system(f"dnsrecon -d {self.domain} -j {FileName}")

			
		self.DnsreconFile = FileName
		self.SubDomains.append(SubDomainExtraction(FileName))  # cleaning and accessing the list of SubDomain
		self.IP.append(Extraction(FileName)) # Extracting Ip
		os.system(f'rm {FileName}')
			

	def FindDomain(self):
		print(f"----------Trying FindDoman---------------------")
		FileName = FileGenarator(self.domain) # Utility
		os.system(f"findomain -t {self.domain} -u {FileName}")

		self.SubDomains.append(SubDomainExtraction(FileName)) # same as aove dumbass
		self.FindDomainFile = FileName 
		os.system(f'rm {FileName}') # Remove Files after task done

def GetSubDomain(domain):
	print(f"-------Starting Subdomain Finding for {domain}-----------")
	if '://' in domain:
		print("Invalid Domain name")
		return
	obj = SubDomain(domain) # object calling default contructor
	print(obj.SubDomains)
	print(obj.IP)
	return {'SubDomain':obj.SubDomains,'IP':obj.IP} # returns subdomain and ips
