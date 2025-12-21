import sys
import os
import json
import mimetypes
import magic
import datetime


def FileType(FileName):
    extension = os.path.splitext(FileName)[1].lower()

    if extension == ".json":
        try:
            with open(FileName, "r") as f:
                json.load(f)
            return "json"
        except Exception:
            # JSON extension but invalid content → fallback
            pass

    elif extension == ".txt":
        return "txt"

    # Try mimetypes first
    mime_type, _ = mimetypes.guess_type(FileName)
    if mime_type:
        return mime_type

    # Fallback to libmagic
    try:
        type_detector = magic.Magic(mime=True)
        return type_detector.from_file(FileName)
    except Exception:
        return "unknown"


def FileGenarator(domain):
	time = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
	return domain+"_"+time


def Create_Domain_Directory(domain, subfolder=''):
    if subfolder:
        dir_path = os.path.join('results', domain, subfolder)
    else:
        dir_path = os.path.join('results', domain)
    
    os.makedirs(dir_path, exist_ok=True)
    return dir_path

import re

def Validate_Ip(ip_list):
    valid_ips = []
    
    for ip in ip_list:
        ip = str(ip).strip()
        
        ip = ip.split('#')[0].split(':')[0]
        
        if '.' in ip:
            parts = ip.split('.')
            if len(parts) == 4:
                valid = True
                for part in parts:
                    if not part.isdigit() or not 0 <= int(part) <= 255:
                        valid = False
                        break
                if valid:
                    valid_ips.append(ip)
                    continue
        
        elif ':' in ip:
            parts = ip.split(':')
            if 2 <= len(parts) <= 8:
                valid = True
                for part in parts:
                    if part:  
                        try:
                            int(part, 16)  
                        except ValueError:
                            valid = False
                            break
                if valid:
                    valid_ips.append(ip)
                    continue
    
    return valid_ips

if __name__ == "__main__":
    filename = sys.argv[1]
    print(FileType(filename))
