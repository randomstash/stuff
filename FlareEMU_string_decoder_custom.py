# -*- coding: utf-8 -*-
"""
Created on Tue Sep 27 11:56:34 2022
Sample: 0A64C336D4CFCEB9D2A56FA5D7A856D8.mal_
"""

from __future__ import print_function
import flare_emu
import idc
import idaapi
import binascii
from capstone import *
import binascii
import idautils

def get_bytes_delim(ea, delim):
    extracted_bytes = []
    curr_loc = ea
    while True:
        tmp_byte = get_wide_byte(curr_loc)
        if tmp_byte == delim:
            return extracted_bytes
        extracted_bytes.append(tmp_byte)
        curr_loc += 1
        if len(extracted_bytes) > 100:
            print("Max size exceeded on get_bytes_delim!")
            return extracted_bytes

def get_bytes_size(ea, size):
    extracted_bytes = []
    curr_loc = ea
    while True:
        tmp_byte = get_wide_byte(curr_loc)
        extracted_bytes.append(tmp_byte)
        curr_loc += 1
        if  len(extracted_bytes) >= size:
            return extracted_bytes

def instr_hook(uc, address, size, userData):
    print("Unicorn trace 0x%x:\t%s" % (address, idc.generate_disasm_line(address, 0)))
    #Capstone disassembler:
    # instruction = uc.mem_read(address, size)
    # md = Cs(CS_ARCH_X86, CS_MODE_64)
    # for i in md.disasm(instruction, 0x20):
    #     print("Unicorn trace 0x%x:\t%s\t%s" %(address, i.mnemonic, i.op_str))

#int snprintf(char *const Buffer, const size_t BufferCount, const char *const Format...)
#Cheap implementation, only works for %s format
def my_snprintf(eh, address, argv, funcName, userData):
    #print("my_snprintf called!")
    #print("string: %s" % eh.getEmuString(argv[3]))
    eh.copyEmuMem(argv[0], argv[3], argv[1], userData)
    

#_WORD *__fastcall decode2(_WORD *a1)
def decrypt2(decryption_func_addr, argv, cyphertext):
    decrypt_emu = flare_emu.EmuHelper()
    print("Decryption func addr used: [0x%08x]" % decryption_func_addr)
    cyphertext_emu = decrypt_emu.loadBytes(cyphertext)
    try:
        decrypt_emu.emulateRange(decryption_func_addr,
                          registers = {"rcx":cyphertext_emu},
                          #stack = [0, plaintext_emu, argv[1], cyphertext_emu],
                          skipCalls=False, hookApis=True)
        result = decrypt_emu.getEmuWideString(cyphertext_emu)
        print(result)
    except:
        print("Oops!", sys.exc_info()[0], "occurred.")
    return result


def iterateCallback2(eh, address, argv, userData):
    print("iterateCallback callback on 0x%x" %address)
    global decryption_counter
    if userData["callback_limit"] > 0: 
        userData["callback_limit"] -= 1
        decryption_counter += 1
        #print(binascii.hexlify((eh.getEmuBytes(argv[0], 200))))
        cyphertext = eh.getEmuBytes(argv[0], 200)+b'\xFF'
        plaintext = decrypt2(userData["decryption_func_addr"], argv, cyphertext).decode("utf-16")
        print("[0x%08x] adding comment: %s" % (address, plaintext))
        idc.set_cmt(address, plaintext, False)

class search_type:
    fwd, bck = range(2)
    
def find_reg_write(ea, reg, direction, max_instr_dist = 5):
    #print(" debug: find_reg_write from [0x%08x] %s" % (ea, idc.generate_disasm_line(ea, 0)))
    curr_loc = ea
    instr_distance = 0
    while (instr_distance < max_instr_dist):
       if direction is search_type.fwd: curr_loc = ida_search.find_code(curr_loc, idc.SEARCH_DOWN)
       else: curr_loc = ida_search.find_code(curr_loc, idc.SEARCH_UP)
       instr_distance += 1
       #print(" debug: [0x%08x] %s" % (curr_loc, idc.generate_disasm_line(curr_loc, 0)))
       if print_operand(curr_loc, 0) == reg:
           return curr_loc
    return 0


def find_reg_mem_write(ea, reg, direction, max_instr_dist = 5):
    #print(" debug: find_reg_write from [0x%08x] %s" % (ea, idc.generate_disasm_line(ea, 0)))
    curr_loc = ea
    instr_distance = 0
    while (instr_distance < max_instr_dist):
       if direction is search_type.fwd: curr_loc = ida_search.find_code(curr_loc, idc.SEARCH_DOWN)
       else: curr_loc = ida_search.find_code(curr_loc, idc.SEARCH_UP)
       instr_distance += 1
       #print(" debug: [0x%08x] %s" % (curr_loc, idc.generate_disasm_line(curr_loc, 0)))
       if '['+reg+']' in print_operand(curr_loc, 0):
           return curr_loc
    return 0

def decrypt_inlined(decrypt_func_addr):
    for xref in idautils.XrefsTo(decrypt_func_addr, ida_xref.XREF_FAR):
        #Find what reg holds the pointer that gets passed to ecx before the call
        prev_addr = prev_head(xref.frm, xref.frm - 10)
        reg = print_operand(prev_addr, 1)
        reg = re.search('.*\[(.+?)\]', reg).group(1)
        
        #Find what reg gets moved to our target reg
        reg_prev_addr = find_reg_write(prev_addr, reg, search_type.bck, 10)
        reg_prev = print_operand(reg_prev_addr, 1)

        #Find where cyphertext starts to get written into mem pointed to by reg_prev
        reg_mem_write_addr = find_reg_mem_write(reg_prev_addr, reg_prev, search_type.bck, 5)
        if not reg_mem_write_addr:
            reg_mem_write_addr = find_reg_mem_write(reg_prev_addr, reg_prev, search_type.fwd, 5)
        if not reg_mem_write_addr:
            print("Could not find reg_mem_write address!")
            continue
    
        emu_start = min(reg_prev_addr, reg_mem_write_addr)
        emu_end = xref.frm
        #Move emu_end past the inlined loop
        for i in range(1,6):
            emu_end = next_head(emu_end, emu_end + 10)
    
        print("Emulating from [0x%08x] to [0x%08x]" % (emu_start, emu_end))
        eh = flare_emu.EmuHelper()
        cryptext_buffer = eh.allocEmuMem(100)
        uc = eh.emulateRange(emu_start, emu_end, registers = {reg_prev:cryptext_buffer}, skipCalls=False, hookApis=True)
        print("Decrypted string: %s" % eh.getEmuString(cryptext_buffer).decode("latin1")[:-1])

    
'''
====================================================================================================
Automatic discovery of decryption funcs baset on pattern search
====================================================================================================
'''
decryption_counter = 0
if __name__ == '__main__':
    decrypt_inlined(idc.get_name_ea_simple("decode1"))

    eh = flare_emu.EmuHelper()
    userData = {}
    userData["callback_limit"] = 2
    userData["decryption_func_addr"] = eh.analysisHelper.getNameAddr("decode2")
    eh.iterate(userData["decryption_func_addr"] , iterateCallback2, hookData=userData)



'''
====================================================================================================
Manual testing
====================================================================================================
'''

BASE = 0x40000
eh = flare_emu.EmuHelper()
my_buffer = eh.allocEmuMem(50, addr=BASE)

encoded_string = bytearray([0x76, 0x4F, 0x7A, 0x36, 0x6C, 0x43, 0x44, 0x72, 0x70, 0x4F, 0x79, 0x79, 0x00])
encoded_string_ptr = eh.loadBytes(encoded_string)

my_stack= [0, my_buffer, 50, encoded_string_ptr]
eh.addApiHook("_snprintf", my_snprintf)
#uc = eh.emulateRange(eh.analysisHelper.getNameAddr("decode1"), stack = my_stack, instructionHook=instr_hook, skipCalls=False, hookApis=True)
#uc = eh.emulateRange(eh.analysisHelper.getNameAddr("decode1"), stack = my_stack, skipCalls=False, hookApis=True)

cryptext_buffer = eh.allocEmuMem(100)
uc = eh.emulateRange(0x180003c40, 0x180003cac, registers = {"rbx":cryptext_buffer}, skipCalls=False, hookApis=True)
print("Decrypted string: %s" % eh.getEmuString(cryptext_buffer).decode("latin1")[:-1])

print("Decrypted string: %s" % eh.getEmuString(my_stack[1]))
print(binascii.hexlify(eh.getEmuString(my_stack[1])))


from unicorn import *
from unicorn.x86_const import *
print(hex(uc.reg_read(UC_X86_REG_EIP)))
print(hex(uc.reg_read(UC_X86_REG_ESP)))
print(hex(uc.reg_read(UC_X86_REG_EBP)))
registers={"rbp": BASE, "rsp": BASE}
 