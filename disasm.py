#!/usr/bin/python
import os
import pickle

def disasm_init(filename):
	pkl_file_name=".{0}.pkl".format(os.path.basename(filename))
	
	inst=[]
	if os.path.isfile(pkl_file_name) is False:
		print ("[+] disasm_init(): disassembling {0}...".format(filename))
		dis_txt=".{0}.dis".format(os.path.basename(filename))
		cmd="objdump -D {0} > {1}".format(filename, dis_txt)
		os.system(cmd)

		prologue="Disassembly of section .text:"
		epilogue="Disassembly of section .fini:"
		with open(dis_txt, 'rb') as f:
			in_text=False
			for line in f:
				if prologue in line:
					in_text=True
				elif epilogue in line:
					break
				elif in_text is True:
					ll=map(lambda x:x.strip(),line.replace(':','').split('\t'))
					i={}
					try:
						i['addr']=int(ll[0],16)
						i['opcode']=ll[1]
						i_str=ll[2]
						i_str=i_str[0:i_str.find('<')].strip()
						i_str=i_str[0:i_str.find('#')].strip()
						i['str']=i_str
						inst.append(i)
					except ValueError:
						pass
					except IndexError:
						pass
		with open(pkl_file_name,'wb') as pkl_file:
			pickle.dump(inst, pkl_file)

	with open(pkl_file_name,'rb') as pkl_file:
		inst=pickle.load(pkl_file)

	return inst

if __name__ == '__main__':
	inst=disasm_init ("./libcrypto.so.1.0.0")
	for i in inst:
		if "call" in i['str']:
			try:
				op=i['str'].split()[1]
				int(op,16)
			except ValueError:
				if len(i['opcode'])==5:
					print ("{0:x} {1}\t{2}({3})".format(i['addr'],op, i['opcode'], len(i['opcode'])))
		
