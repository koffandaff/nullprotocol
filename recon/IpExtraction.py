from utility import FileType
import json


def Extraction(File):
	# Checking File Type
	type = FileType(File)
	print(f"File Type: {type}")
	IP = []
	if 'json' in type:
		with open(File, 'r') as f:
			data = json.load(f)
			print(data)
		for i in data:
			for j in i:
				if j == 'address':
					IP.append(i[j])
	return IP


if __name__ == '__main__':
	pass
