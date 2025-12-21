import json
from utility import FileType


def SubDomainExtraction(File):
    print(File)
    type = FileType(File)
    Subdomains = []
    Ports = []

    if 'json' in type:
        with open(File, 'r') as f:
            data = json.load(f)
            
            for i in data:
                for j in i:
                    if j == 'name' or j == 'domain' or j == 'host' and j not in SubDomains:
                        Subdomains.append(i[j])

                    if j.lower() == 'port':
                        Ports.append(i[j])

    elif 'txt' in type or 'text' in type:
        with open(File, 'r') as f:
            lines = f.readlines()
            for line in lines:
                if line not in Subdomains:
                            
                            
                	Subdomains.append(line)
                    
                        

    else:
        print(f"The file of Type : {type} is not available yet")
    
    print("Subdomains:", Subdomains)
    print("Ports:", Ports)
    return Subdomains
