#!/usr/bin/python

import os
import sys
import struct
import hexdump
import binascii
import myelffile
from myelffile import SHF, PF, ET, PT
from capstone import *
from capstone.x86 import *
from peachpy.x86_64 import *
from elfconst import *

def str2reg (regname):
	if regname == "eax":
		return eax
	elif regname == "ecx":
		return ecx
	elif regname == "edx":
		return edx
	elif regname == "ebx":
		return ebx
	elif regname == "esp":
		return esp
	elif regname == "ebp":
		return ebp
	elif regname == "esi":
		return esi
	elif regname == "edi":
		return edi
	elif regname == "r8d":
		return r8d
	elif regname == "r9d":
		return r9d
	elif regname == "r10d":
		return r10d
	elif regname == "r11d":
		return r11d
	elif regname == "r12d":
		return r12d
	elif regname == "r13d":
		return r13d
	elif regname == "r14d":
		return r14d
	elif regname == "r15d":
		return r15d
	elif regname == "rax":
		return rax
	elif regname == "rcx":
		return rcx
	elif regname == "rdx":
		return rdx
	elif regname == "rbx":
		return rbx
	elif regname == "rsp":
		return rsp
	elif regname == "rbp":
		return rbp
	elif regname == "rsi":
		return rsi
	elif regname == "rdi":
		return rdi
	elif regname == "r8":
		return r8
	elif regname == "r9":
		return r9
	elif regname == "r10":
		return r10
	elif regname == "r11":
		return r11
	elif regname == "r12":
		return r12
	elif regname == "r13":
		return r13
	elif regname == "r14":
		return r14
	elif regname == "r15":
		return r15

# return type : ElfSectionHeader32l
def getSection (eo, section_name):
	indx=0
	for sh in eo.sectionHeaders:
		if section_name == sh.name:
			return indx, sh
		indx+=1
	return None, None

def get_last_exec_section (eo):
	c=0
	es=None
	indx=0
	for sh in eo.sectionHeaders:
		if (sh.flags & SHF.byname['SHF_EXECINSTR'].code) and (sh.flags & SHF.byname['SHF_ALLOC'].code):
			es=sh
			indx=c
		c+=1

	if es is not None:
		print ("[+] last section found : {0}, {1}".format(es.name, indx))
	return indx, es

def get_base_address (input_elf):
	eo=myelffile.open(name=input_elf)
	base_address=0x0

	if eo.fileHeader.type == ET.byname['ET_REL'].code:
		# get text setcion
		indx, text_section = getSection (eo, ".text")
		base_address = text_section.addr+text_section.section_size
	elif eo.fileHeader.type == ET.byname['ET_EXEC'].code:
		indx, text_section=get_last_exec_section (eo)
		if text_section is not None:
			base_address=text_section.addr+text_section.section_size
		else:
			text_segment = eo.programHeaders[0]
			base_address=text_segment.vaddr+text_segment.memsz
	else:
		print ("[-] (get_base_address) unknown input_elf type")
		return 0

	print ("[+] base_address : 0x{0:x}".format(base_address))
	return base_address


def patch_one_instruction (content, offset, newinst):
	inst_len=len(newinst)
	prefix=content[0:offset]
	postfix=content[offset+inst_len:]
	#hexdump.hexdump (prefix)
	#hexdump.hexdump (postfix)
	return prefix+newinst+postfix

def patch_instructions (content, base_addr, patch_list):
	start_addr=base_addr
	for addr, inst in patch_list:
		pos=int(addr-start_addr)
		print ("[+] patching call instruction at 0x{0:x} (file offset:{1:x}, inst:{2})".format(addr, pos, binascii.hexlify(inst)))
		content=patch_one_instruction (content, pos, inst)
	return content

def split2len (s,n):
	def _f(s,n):
		while s:
			yield s[:n]
			s=s[n:]
	return list (_f(s,n))


def modify_relo_section_entry (content, target_offset):
	relocations=split2len (content, 8)
	prev_r=None
	count=0
	for r in relocations:
		o, i = struct.unpack ("<II", r)
		if target_offset == o:
			print ("[+] modifying relocation entry (offset={0:x}, info={1:x})".format(o, i))
			pos=count*8
			prefix=content[0:pos]
			postfix=content[pos+8:]
			#new_content=prefix+prev_r+postfix
			#new_content=prefix+'\0'*8+postfix
			new_content=prefix+postfix
			#hexdump.hexdump(new_content)
			return new_content
		count+=1
		prev_r=r
	return content

def modify_relo_section_content (content, patch_list):
	#hexdump.hexdump (content)
	for pos, inst in patch_list:
		offset = pos+1
		content=modify_relo_section_entry (content, offset)

	return content


def get_text_segment (eo):
	indx = -1
	for ph in eo.programHeaders:
		indx+=1
		if ph.type == PT.byname['PT_LOAD'].code and (ph.flags & PF.byname['PF_X'].code) :
			return indx
	return indx


def adjust_dynamic_section (content, new_size):
	new_content=''
	ll = split2len(content, 16)
	for entry in ll:
		tag, value = struct.unpack ("<QQ", entry)
		print ("[+] adjust_dynamic_section(): {0:x} {1:x}".format(tag,value))
		if tag in DT_ptr_types:
			#print ("[+] adjust_dynamic_section(): {0:x} {1:x}".format(tag,value))
			value += new_size
		#if value >= 0x400000:
		#	print ("[+] adjust_dynamic_section(2): {0:x} {1:x}\n".format(tag,value))
		#	value += new_size
		new_content+=struct.pack ("<QQ", tag, value)
	#hexdump.hexdump (new_content)
	return new_content

def adjust_relo_section (content, new_size):
	new_content=''
	ll = split2len(content, 24)
	for entry in ll:
		offset, info, value = struct.unpack ("<QQQ", entry)
		#print ("[+] audjst_relo_section(): {0:x}, {1:x}, {2:x}".format(offset, info ,value))
		offset += new_size
		if value != 0:
			value += new_size
		new_content+=struct.pack ("<QQQ",offset,info, value)
	#hexdump.hexdump (new_content)
	return new_content
	#return content

def adjust_symtab_section (content, new_size):
	new_content=''
	ll = split2len(content, 24)
	for entry in ll:
		name, value, etc= struct.unpack ("<QQQ", entry)
		#print ("{0:x}, {1:x}, {2:x}".format(name, value, etc))
		if value != 0:
			value += new_size
		new_content+=struct.pack ("<QQQ",name ,value, etc)
	#hexdump.hexdump (new_content)
	return new_content
	#return content

def adjust_plt_section (content, new_size):
	new_content=''
	ll = split2len(content, 8)
	for entry in ll:
		#hexdump.hexdump (entry)
		value = struct.unpack ("<Q", entry)[0]
		#print ("{0:x}".format(value))
		if value != 0:
			value += new_size
		new_content+=struct.pack ("<Q",value )
	#hexdump.hexdump (new_content)
	return new_content
	#return content

def adjust_init_array_section (content, new_size):
	new_content=''
	ll = split2len(content, 8)
	for entry in ll:
		#hexdump.hexdump (entry)
		value = struct.unpack ("<Q", entry)[0]
		#print ("{0:x}".format(value))
		if value != 0:
			value += new_size
		new_content+=struct.pack ("<Q",value )
	#hexdump.hexdump (new_content)
	return new_content
	#return content

def optype2str (optype):
	if optype == X86_OP_REG:
		return "X86_OP_REG"
	elif optype == X86_OP_IMM:
		return "X86_OP_IMM"
	elif optype == X86_OP_FP:
		return "X86_OP_FP"
	elif optype == X86_OP_MEM:
		return "X86_OP_MEM"
	return "None"

def in_text_section(eo, immediate):
	indx, _section = getSection(eo, ".text")
	size = len(_section.content)
	#print ("vaddr={0:x}, size={1}, imm={2:x}".format(_section.addr, size, immediate))
	vaddr_start=0x400000
	#vaddr_start=_section.addr
	vaddr_end = vaddr_start + 0x200000
	if immediate >= vaddr_start and immediate <= vaddr_end:
		return True
	return False


def modify_instruction (eo, inst, new_size):
	new_opcode =''
	if inst.mnemonic != "mov":
		return new_opcode

	op1 = inst.operands[0]
	op2 = inst.operands[1]
	if op2.type == X86_OP_IMM and in_text_section(eo, op2.imm) and op1.type == X86_OP_REG:
			print ("0x%x:\t%s\t%s (op1.type:%d)" %(inst.address, inst.mnemonic, inst.op_str, op1.type))
			#print ("%s"%inst.reg_name(op1.reg))
			imm = op2.imm+new_size
			new_opcode=MOV (str2reg(inst.reg_name(op1.reg)), imm).encode()
			#print binascii.hexlify(new_opcode)
			#print binascii.hexlify(opcode)
			
	return new_opcode


def adjust_text_section (eo, content, new_size):
	new_content=''
	md=Cs(CS_ARCH_X86, CS_MODE_64)
	md.detail = True
	for inst in md.disasm (content, 0):
		#print ("0x%x:\t%s\t%s" %(inst.address, inst.mnemonic, inst.op_str))
		new_opcode = modify_instruction (eo, inst, new_size)
		if new_opcode != '':
			opcode=new_opcode
		else:
			opcode=content[inst.address: inst.address+inst.size]
		#	print optype2str(op.type)
		
		new_content+=opcode
		#print ("%s" % binascii.hexlify(opcode))

	return new_content

def patch_file (input_elf, output_elf, displacement=64):
	eo = myelffile.open (name=input_elf)
	
	# change entry point
	fh = eo.fileHeader
	fh.entry += displacement 
	print ("[+] new entry point : {0:x}".format(fh.entry))

	# get basis section
	# displacment of addresses will be performed for all sections 
	# following the basis section 
	#basis_section_name = ".note.ABI-tag"
	basis_section_name = ".note.gnu.build-id"
	indx, basis_section = getSection(eo, basis_section_name)

	if basis_section is not None:
		print ("[+] basis section found (indx={0})".format(indx))
		basis_section.size+=displacement
		basis_section.content+='\0'*displacement
		print ("[+] adding bindata ({0} bytes) to prev section (0x{1:x})".format(displacement,basis_section.addr))


	# apply displacement for the following sections
	for sh in eo.sectionHeaders[indx+1:]:
		sh.offset += displacement 
		if sh.addr > 0:
			sh.addr += displacement 
			#print ("addr:{0:x}".format(sh.addr))

	# adjust dynamic section
	indx, _section = getSection(eo, ".dynamic")
	if _section is not None:
		_section.content=adjust_dynamic_section (_section.content, displacement)

	# adjust .rela.dyn section
	indx, _section = getSection(eo, ".rela.dyn")
	if _section is not None:
		print "[+] adjusting section : .rela.dyn ({0} bytes)".format(len(_section.content))
		_section.content=adjust_relo_section (_section.content, displacement)

	# adjust .rela.plt section
	indx, _section = getSection(eo, ".rela.plt")
	if _section is not None:
		_section.content=adjust_relo_section (_section.content, displacement)

	# adjust .dynsym section
	indx, _section = getSection(eo, ".dynsym")
	if _section is not None:
		_section.content=adjust_symtab_section (_section.content, displacement)

	# adjust .symtabl section
	indx, _section = getSection(eo, ".symtab")
	if _section is not None:
		_section.content=adjust_symtab_section (_section.content, displacement)

	# adjust .got.plt section
	indx, _section = getSection(eo, ".got.plt")
	if _section is not None:
		_section.content=adjust_plt_section (_section.content, displacement)

	# adjust .init_array section
	indx, _section = getSection(eo, ".init_array")
	if _section is not None:
		_section.content=adjust_init_array_section (_section.content, displacement)

	# adjust .text section
	indx, _section = getSection(eo, ".text")
	if _section is not None:
		_section.content=adjust_text_section(eo, _section.content, displacement)
	
	indx=get_text_segment (eo)
	if indx < 0:
		print "[-] text segment not found"
		return
	else:
		print "[+] text segment found ({0})".format(indx)

	try:
		# adjust text segment
		load1=eo.programHeaders[indx]
		load1.filesz+=displacement
		load1.memsz+=displacement

		# adjust offsets of other segments
		for ph in eo.programHeaders[indx+1:]:
			ph.offset += displacement
			ph.vaddr += displacement
	except IndexError:
		#print ("[+] no program headers found")	
		pass
	  
	with open(output_elf,"wb") as f: f.write(eo.pack())
	print ("[+] patched executable sucessfully written to {0}".format (output_elf))




if __name__ == "__main__":
	if len(sys.argv) !=3:
		print ("Usage: {0} [input elf] [displacement]".format(sys.argv[0]))
		sys.exit(0)
	else:
		input_elf=sys.argv[1]
		displacement=int(sys.argv[2])
		ff=os.path.basename(input_elf).split('.')
		ff[0]+="2"
		output_elf=".".join(ff)

	print ("[+] input={0}, displacement={1}".format(input_elf, displacement))

	# for test
	#patch_file ("./show_user","./a.out","asrvm.tail","show_user2")
	#patch_file ("./test","./test2", 64)
	patch_file (input_elf, output_elf, displacement)
	#patch_file ("./gpg","./gpg2", 64)
