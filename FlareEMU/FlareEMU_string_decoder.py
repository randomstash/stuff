# -*- coding: utf-8 -*-
"""
Created on Tue Sep 27 11:56:34 2022
Sample: DC1D1AB51852E893EEB4F0E88CC30EAE.mal_
"""

from __future__ import print_function
import flare_emu
import idc
import idaapi
import binascii
from capstone import *

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
    

#char *__cdecl decode1(char *plaintext, size_t BufferCount, const char *cyphertext)
def decrypt(decryption_func_addr, argv):
    decrypt_emu = flare_emu.EmuHelper()
    plaintext_emu = decrypt_emu.allocEmuMem(100)
    #cyphertext = get_strlit_contents(argv[2], argv[1], idc.STRTYPE_C)
    print("Decryption func addr used: [0x%08x]" % decryption_func_addr)
    cyphertext = bytearray(get_bytes_delim(argv[2], 0x00))
    cyphertext_emu = decrypt_emu.loadBytes(cyphertext)
    decrypt_emu.addApiHook("_snprintf", my_snprintf)
    try:
        decrypt_emu.emulateRange(decryption_func_addr,
                          #registers = {"arg1":argv[0], "arg2":argv[1], "arg3":argv[2], "arg4":argv[3]})
                          stack = [0, plaintext_emu, argv[1], cyphertext_emu],
                          skipCalls=False, hookApis=True)
        result = decrypt_emu.getEmuString(plaintext_emu)
    except:
        print("Oops!", sys.exc_info()[0], "occurred.")
        exit(-1)
    #result = "aaa"
    return result

def iterateCallback(eh, address, argv, userData):
    #print("iterateCallback callback on 0x%x" %address)
    global decryption_counter
    if userData["callback_limit"] > 0: 
        userData["callback_limit"] -= 1
        decryption_counter += 1
        plaintext = decrypt(userData["decryption_func_addr"], argv).decode("latin1")
        print("[0x%08x] adding comment: %s" % (address, plaintext))
        idc.set_cmt(address, plaintext, False)

'''
====================================================================================================
Automatic discovery of decryption funcs baset on pattern search
====================================================================================================
'''
decryption_counter = 0
if __name__ == '__main__':
    segment_list = []
    entry_point_num = ida_entry.get_entry_qty()
    while (entry_point_num >= 1):
        seg_start = get_segm_start(ida_entry.get_entry(entry_point_num))
        seg_end = get_segm_end(ida_entry.get_entry(entry_point_num))
        if seg_start != ida_idaapi.BADADDR and (seg_start, seg_end) not in segment_list:
            segment_list.append((seg_start, seg_end))
        entry_point_num -= 1
    for seg in segment_list:
        curr_loc = seg[0]
        while True:
            hit_addr = idc.find_binary(curr_loc, idc.SEARCH_DOWN, "68 24 E3 02 10 51 56 C6")
            if hit_addr == ida_idaapi.BADADDR: break
            print("[0x%08x] decryption function: %s " % (hit_addr, idc.get_func_name(hit_addr)))
            curr_loc = hit_addr + 1
            #Decrypt strings:
            eh = flare_emu.EmuHelper()
            userData = {}
            userData["callback_limit"] = 10000
            userData["decryption_func_addr"] = get_func_attr(hit_addr, FUNCATTR_START)
            eh.iterate(get_func_attr(hit_addr, FUNCATTR_START), iterateCallback, hookData=userData)
    print("Decrypted %d strings" % decryption_counter)
    


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
uc = eh.emulateRange(eh.analysisHelper.getNameAddr("decode1"), stack = my_stack, skipCalls=False, hookApis=True)
print("Decrypted string: %s" % eh.getEmuString(my_stack[1]))
print(binascii.hexlify(eh.getEmuString(my_stack[1])))


from unicorn import *
from unicorn.x86_const import *
print(hex(uc.reg_read(UC_X86_REG_EIP)))
print(hex(uc.reg_read(UC_X86_REG_ESP)))
print(hex(uc.reg_read(UC_X86_REG_EBP)))
registers={"rbp": BASE, "rsp": BASE}
 