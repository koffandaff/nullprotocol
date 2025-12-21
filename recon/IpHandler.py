import os
import json
from utility import Validate_Ip, FileGenarator, Create_Domain_Directory
import IpNmapHandler
import os

def IpMasscan(Ip,domain):
	ips = {}
	for i in Ip:
		Dir = Create_Domain_Directory(domain,'Ip')
		
		Name = FileGenarator(i)
		File = os.path.join(Dir,Name)
		print(File)
	
		
		print(f"---------Scanning {i} ----------------")
		os.system(f'sudo masscan --top-ports 1000 {i} --open --rate=25000 --wait 0 -oJ {File}.json')
		print(f'---------------- Saved File: {i}.json------------------')
		if(f'{File}.json'):
			with open(f'{File}.json','r') as f:
				data = f.read()
				print(data)
				ips[i] = data
				#ips[file] = f'{File}.json'
		#os.chdir(f'{Dir}')
		#os.system(f"find -name '{Name}.json' -type f -empty -delete")
		#os.chdir('~/projects/fsociety/recon')
		os.system(f"find '{Dir}' -name '*.json' -type f -empty -delete 2>/dev/null")
	print(ips)
	return {'ip':ips,'dir': Dir}

def IpHandler(Ip,domain, Subdomain_File):
    import ReconEnhancer
    
    ip = Validate_Ip(Ip)
    IpData = IpMasscan(ip,domain)
    Nmap_Result = IpNmapHandler.main(IpData['ip'],IpData['dir'])
    print(Nmap_Result['File_Location'])
    with open(Subdomain_File, 'r') as f:
        print(f.read())

    print(IpData['ip'],"="*70,IpData['dir'])
    ReconEnhancer.main(domain,Subdomain_File,Nmap_Result['File_Location'],IpData['ip'])
    
