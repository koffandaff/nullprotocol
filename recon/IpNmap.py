import os
import NmapXmlCleaner
def Nmap_Port_Service_Discovery(Ip,Dir):
	print("\n\n\n----------- Staring Service Discovery -----------\n\n\n")
	dirs = os.path.join(Dir,'Nmap','Serive_Discovery')
	os.makedirs(dirs, exist_ok=True)
	Files = []
	for i in Ip:
		File = os.path.join(dirs,i)
		os.system(f'nmap -sS --top-ports 100 -T4 -v {i} -oX {File}.xml')
		Files.append(File+'.xml')
	return { 'FilesList': Files, 'FileDirectory': dirs}
	

def Nmap_OS_Discovery(Ip,Dir):
	print("\n\n\n --------------Starting Os Discovery -------- \n\n\n")
	dirs= os.path.join(Dir,'Nmap','OS_Discovery')
	os.makedirs(dirs, exist_ok=True)
	Files = []
	for i in Ip:
		File = os.path.join(dirs,i)
		os.system(f'nmap -sS -O {i} -oX {File}.xml')
		Files.append(File+'.xml')
		
		
	return {'FileList': Files, 'Dir': dirs}


def main(Ip,Dir):
	Service_Scan_Data = Nmap_Port_Service_Discovery(Ip,Dir)
	NmapXmlCleaner.main(Service_Scan_Data['FilesList'], Service_Scan_Data['FileDirectory'])
	
	# OS_Discovery:
	OS_Discovery_Data = Nmap_OS_Discovery(Ip,Dir)
	print('see this blind nigga0------------------------: ',OS_Discovery_Data)
	NmapXmlCleaner.OS_Discovery_Cleaner(OS_Discovery_Data['FileList'])
	os.chdir(OS_Discovery_Data['Dir'])
	os.system('rm *.xml')
