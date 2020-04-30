import idautils, idaapi, idc, ida_search, ida_ua, ida_name
import string

idaapi.require("maze_functions")
idaapi.require("maze_function_analysis")
idaapi.require("maze_deobf_utils")

#
#   Registers, if needed
#
gp_registers = {0:'eax',1:'ecx',2:'edx',3:'ebx',4:'esp',5:'ebp',6:'esi',7:'edi'}


def CheckIsASCII(Ascii_ea):
    '''
        @brief  Do a quick to see if an ASCII string is present.

        @return  length
    '''
    length = 0

    byte = -1
    iter_ea = Ascii_ea
    while byte != 0:
        byte = get_wide_byte(iter_ea)
        if chr(c) not in string.printable:
            break
        length += 1
        iter_ea += 1
    
    return length

def ZeroOutInstruction(Targ_insn):
    '''
        @brief Replace instruction with NULL bytes.

        @detail Currently, this function replaces opcode bytes with NULL bytes, but this 
                 may get switched to 0xCC. I don't know which one messes with the bytes around it less.
    '''

    #print "reached"
    if type(Targ_insn) == ida_ua.insn_t:
        idx = 0
        insn_ea = Targ_insn.ea
        #print "Type ok: ", hex(insn_ea), hex(Targ_insn.ip)
        while idx < Targ_insn.size:
            #print "Patching: ", hex(insn_ea)
            patch_byte(insn_ea,0x00)
            
            insn_ea += 1
            idx += 1

def GetModuleName(Strlit_ea):
    '''
        @brief Get the module name, this was already checked by the IsValidName from
                a previous call, so it's knownt that it is the module name. 
        
        @return BOOL
    '''

    start_ea = Strlit_ea
    module_name = ""
    char = get_wide_byte(start_ea)

    while ida_name.is_strlit_cp(char):
        module_name += chr(char)    
        start_ea += 1
        char = get_wide_byte(start_ea)
    
    if get_wide_byte(start_ea) !=  0x00:
        #
        #   Final char in ASCII string should be a NULL byte
        #

        module_name = ""
    
    return module_name

def CleanupPatchArea(Start_ea, Size):
    '''
        @brief Delete instructuions that may exist where a patched instruction is 
                going to exist.
    '''

    for idx in range(Size):
        del_items(Start_ea+idx,1)

    plan_and_wait(Start_ea,Size)

def CheckJCCSameEdge(jcc_ea1, jcc_ea2):
    '''
        @brief Check if both edges of a JCC instruction are the same.

        @return BOOL
    '''

    return get_operand_value(jcc_ea1,0) == get_operand_value(jcc_ea2,0)

def IdentifyFunctionEpilogue(EpligueStartIns):
    '''
        @detail  Start with the initial instruction and build a basic block. Determine
                    if the final instruction of the block is either a return instruction
                    or an equivelant.

                    Anything jumping to the value stored in [ESP-4] is suspect, and likely an 
                    attempt to return to the caller after cleanuping esp by incremented the stack
                    pointer in some manner.
    '''

    terminators = ["jmp", "retn"]


def FindCallTypeOneCFGObfuscation():
    '''
           @detail  Find all of the CFG Obfuscations that match the following pattern (Type One):
        
               68 E8 52 44 6E      push    offset loc_6E4452E8
               FF E7               jmp     edi                   ; or any register
           
           The jump destination for both is the same.
    '''

    opcodes = "68 ? ? ? ? FF"

    end_ea = ida_ida.cvar.inf.max_ea

    addr_list = set()
    cfg1_ea = ida_search.find_binary(0, end_ea, opcodes, 0, SEARCH_DOWN | SEARCH_CASE)

 

    while cfg1_ea != idc.BADADDR:
        #
        #   Iterate over all found addresses and add to list
        #

        

        push_instr_ea = cfg1_ea
        push_insn = ida_ua.insn_t()
        ida_ua.decode_insn(push_insn, push_instr_ea)
        push_insn_target_ea = maze_deobf_utils.GetInstuctionTargetAddress(push_insn)

        #print "Find Type One 1: 0x%08x, target 0x%08x" % (cfg1_ea, push_insn_target_ea)
        
        if maze_deobf_utils.CheckValidTargettingInstr(push_insn, "push"):
            #print "Find Type One 2: 0x%08x" % cfg1_ea

            jmp_instr_ea = push_instr_ea + push_insn.size
            jmp_dism = generate_disasm_line(jmp_instr_ea,1)

            if 'jmp' in jmp_dism[:3]:
                #
                #   Ensure mnemonic is correct
                #

                jmp_insn = ida_ua.insn_t()
                ida_ua.decode_insn(jmp_insn, jmp_instr_ea)

                jmp_operand = jmp_insn.ops[0]

                #print "Find Type One 3: 0x%08x %d" % (cfg1_ea, jmp_operand.type)

                if jmp_operand.type in [1, 3, 4]:
                    addr_list.add(push_instr_ea)


        
        cfg1_ea =ida_search.find_binary(cfg1_ea+4, end_ea,  opcodes, 0, SEARCH_DOWN | SEARCH_CASE)

    return addr_list


def PatchCallTypeOneCFGObfuscation(instr_ea):
    '''
        @detail  The patch for type one is to reorder the instructions, place the patched CALL instruction
                  where the PUSH instruction starts, and place the patched JMP instruction after the new CALL
                  instruction, overwriting the JMP <register> that is currently in place. 

                    68 E8 52 44 6E      push    <return address>
                    FF E7               jmp     edi                     ; or any register

                Patch:

                    FF D7               call    edi                     ; or any register
                    <5 bytes>           JMP     <return address>  
                
                The second opcode, the 'E7' in the original JMP is decreased by 0x10, making it a call statement.
                The call and jmp instructions should always be the same size, but the second opcode is decreased by
                0x10. 
    '''
    
    push_instr_ea = instr_ea

    #
    #   Get push instruction data
    #
    push_insn = ida_ua.insn_t()
    ida_ua.decode_insn(push_insn, push_instr_ea)
    push_insn_target = maze_deobf_utils.GetInstuctionTargetAddress(push_insn)

    #
    #   Get JMP instruction data
    #
    jmp_insn_ea = push_instr_ea +  push_insn.size
    jmp_insn = ida_ua.insn_t()
    ida_ua.decode_insn(jmp_insn, jmp_insn_ea)

    #
    #   Get address for patched JMP and CALL instructions
    #
    patch_jmp_ea = push_instr_ea + jmp_insn.size
    patch_call_ea = push_instr_ea

    #
    #   Calculate the offset for the address that was pushed to the 
    #    stack by the push instruction and will now be used by the JMP
    #
    #       offset = target_address - address_of_insn_after_CALL
    #
    patch_jmp_target_ea = push_insn_target
    patch_jmp_dest_offset = (patch_jmp_target_ea - (patch_jmp_ea + 5)) & 0xFFFFFFFF

    #
    #   Patch opcode from JMP to CALL
    #
    idx = 0
    del_items(patch_call_ea,1)
    for idx in range(jmp_insn.size):
        byte = get_wide_byte(jmp_insn_ea+idx)
        if idx == 1:
            patch_byte(patch_call_ea+idx, byte-0x10)
        else:
            patch_byte(patch_call_ea+idx, byte)
        idx += 1    
    create_insn(patch_call_ea)

    #
    #   Create JMP from PUSH instruction
    #
    CleanupPatchArea(patch_jmp_ea,5)
    patch_byte(patch_jmp_ea, 0xE9)
    patch_dword(patch_jmp_ea+1,patch_jmp_dest_offset)
    create_insn(patch_jmp_ea)
    plan_and_wait(patch_jmp_ea,patch_jmp_ea+5)
    

    
    plan_and_wait(patch_call_ea, patch_call_ea+jmp_insn.size)

    #
    #   Make JMP destination code
    #
    del_items(patch_jmp_target_ea,1)
    jmp_target_insn = ida_ua.insn_t()
    ida_ua.decode_insn(jmp_target_insn, patch_jmp_target_ea)
    create_insn(patch_jmp_target_ea)
    plan_and_wait(patch_jmp_target_ea, patch_jmp_target_ea+jmp_target_insn.size)


def FindCallTypeTwoCFGObfuscation():
    '''
    @detail  Find all of the CFG Obfuscations that match the following pattern (Type Two):

                push    <return address>
                JZ      xxxxxxxxxx
                JNZ     xxxxxxxxxx
            
            The jump destination for both is the same.
    '''

    opcodes = "68 ? ? ? ? 0f 84 ? ? ? ? 0F 85"

    end_ea = ida_ida.cvar.inf.max_ea

    addr_list = set()
    cfg2_ea = ida_search.find_binary(0, end_ea, opcodes, 0, SEARCH_DOWN | SEARCH_CASE)

    #
    #   useful for identifying what was filtered out and why
    #
    all_found_from_search = set()
    found_pushes = set()
    missing_pushes = set()
    found_jzjnz_mnems = set()
    missing_jzjnz_mnems = set()
    found_different_edge = set()
    

    while cfg2_ea != idc.BADADDR:
        #
        #   Iterate over all found addresses and add to list
        #

        push_instr_ea = cfg2_ea
       
        push_insn = ida_ua.insn_t()
        ida_ua.decode_insn(push_insn, push_instr_ea)
        if maze_deobf_utils.CheckValidTargettingInstr(push_insn, "push"):
            
            push_op = push_insn.ops[0]

            jz_ea = push_instr_ea + push_insn.size
            jz_insn = ida_ua.insn_t()
            ida_ua.decode_insn(jz_insn, jz_ea)

            if maze_deobf_utils.CheckValidTargettingInstr(jz_insn, "jz"):
                jz_op = jz_insn.ops[0]

                #
                #   Get the target address for the JZ
                #   
                jz_target = 0
                if jz_op.type == 5: 
                    jz_target = jz_op.value
                elif jz_op.type == 6 or jz_op.type == 7:
                    jz_target = jz_op.addr

                jnz_ea = jz_ea + jz_insn.size
                jnz_insn = ida_ua.insn_t()
                ida_ua.decode_insn(jnz_insn, jnz_ea)

                if maze_deobf_utils.CheckValidTargettingInstr(jnz_insn, "jnz"):
                    jnz_op = jnz_insn.ops[0]

                    #
                    #   Get the target address for the JNZ
                    #   
                    jnz_target = 0
                    if jnz_op.type == 5: 
                        jnz_target = jnz_op.value
                    elif jnz_op.type == 6 or jnz_op.type == 7:
                        jnz_target = jnz_op.addr

                    if jnz_target == jz_target:
                        #
                        #   Destinations for Type Two must be the same
                        #

                        addr_list.add(push_instr_ea)
 
        
        cfg2_ea =ida_search.find_binary(cfg2_ea+4, end_ea,  opcodes, 0, SEARCH_DOWN | SEARCH_CASE)

    return addr_list


def PatchCallTypeTwoCFGObfuscation(instr_ea):
    '''
    @detail  Find all of the CFG Obfuscations that match the following pattern (Type Two):

                68 19 28 45 6E      push    <return address>
                0F 84 05 3C 01 00   JZ      xxxxxxxxxx
                0F 85 FF 3B 01 00   JNZ     xxxxxxxxxx
            
            The jump destination for both is the same. These are going to be patched to look like the
            following:

                90      NOP
                90      NOP
                90      NOP
                90      NOP
                90      NOP
                90      NOP
                CALL   xxxxxxxxxx
                NOP
                <5 bytes> JMP    <return address>
    '''

    push_instr_ea = instr_ea

    push_insn = ida_ua.insn_t()
    ida_ua.decode_insn(push_insn, push_instr_ea)
    push_insn_target = maze_deobf_utils.GetInstuctionTargetAddress(push_insn)

    jz_instr_ea = push_instr_ea+push_insn.size
    jz_insn = ida_ua.insn_t()
    ida_ua.decode_insn(jz_insn, jz_instr_ea)
    jz_insn_target = maze_deobf_utils.GetInstuctionTargetAddress(jz_insn)

    jnz_instr_ea = jz_instr_ea + jz_insn.size
    jnz_insn = ida_ua.insn_t()
    ida_ua.decode_insn(jnz_insn, jnz_instr_ea)

    call_instr_ea = jz_instr_ea + 1
    jmp_instr_ea = jnz_instr_ea + 1

    call_target = jz_insn_target
    jmp_target = push_insn_target

    #
    #   Calculate the offset for the address that was pushed to the 
    #    stack by the push instruction and will now be used by the JMP
    #
    #       offset = target_address - address_of_insn_after_CALL
    #
    jmp_dest_offset = (jmp_target - (jmp_instr_ea + 5)) & 0xFFFFFFFF
    
    #
    #   Calculate the offset for the address that was the target for the 
    #    two JCC instructions and will now be used in a CALL
    #
    #       offset = target_address - address_of_insn_after_CALL
    #
    call_dest_offset = (call_target - (call_instr_ea + 5))  & 0xFFFFFFFF


    #print hex(call_instr_ea), hex(call_instr_ea + 5 + new_call_dest_offset) + hex(new_call_dest_offset)
    
    #
    #   Patch PUSH;JZ;JNZ
    #
    patch_byte(push_instr_ea, 0x90)
    patch_byte(push_instr_ea+1, 0x90)
    patch_byte(push_instr_ea+2, 0x90)
    patch_byte(push_instr_ea+3, 0x90)
    patch_byte(push_instr_ea+4, 0x90)
    patch_byte(call_instr_ea-1, 0x90)
    patch_byte(call_instr_ea, 0xE8)
    patch_dword(call_instr_ea+1, call_dest_offset)
    patch_byte(jmp_instr_ea-1, 0x90)
    patch_byte(jmp_instr_ea, 0xE9)
    patch_dword(jmp_instr_ea+1,jmp_dest_offset)

    #
    #   Delete NOP; CALL; JMP
    #
    del_items(push_instr_ea,1)

    #
    #   cleanup post JMP bytes
    #
    #
    patch_byte(jmp_instr_ea+5, 0x00)
    patch_byte(jmp_instr_ea+6, 0x00)
    patch_byte(jmp_instr_ea+7, 0x00)
    patch_byte(jmp_instr_ea+8, 0x00)
    
    #
    #   Redifine NOP; CALL; JMP
    #
    create_insn(push_instr_ea)
    plan_and_wait(push_instr_ea, push_instr_ea+1)

    #
    #   Make JUMP Target Code
    #
    del_items(jmp_target,1)
    jmp_target_insn = ida_ua.insn_t()
    ida_ua.decode_insn(jmp_target_insn, jmp_target)
    create_insn(jmp_target)
    plan_and_wait(jmp_target, jmp_target+jmp_target_insn.size)

    #
    #   Make Call Target Code
    #
    del_items(call_target,1)
    call_target_insn = ida_ua.insn_t()
    ida_ua.decode_insn(call_target_insn, call_target)
    create_insn(call_target)
    plan_and_wait(call_target, call_target+call_target_insn.size)

def WalkCallTypeThreeControlFlow(CallAddress, StartAddress):
    '''
        @detail Start with the JNZ edge of a JZ/JNZ obfuscation and walk down until the 
                 the JNZ target address matches the Call address. This will handle multiple 
                 JZ/JNZ blocks for Call Type Three Obfuscations. The assumption is that when 
                 a call is obfuscated in this manner it has to always be called. 

                 Unused and can probably be deleted.

    '''

    print "Call Target: %08x, Starting at: %08x" % (CallAddress,StartAddress)
    jnz_call_target_ea = StartAddress

    is_cal_type_three = False

    while jnz_call_target_ea != CallAddress:

        jnz_ea = jnz_call_target_ea
        jnz_insn = ida_ua.insn_t()
        ida_ua.decode_insn(jnz_insn, jnz_ea)

        if not maze_deobf_utils.CheckValidTargettingInstr(jnz_insn, "jnz"):
            '''
                Break out of the loop if the instruction is not a JNZ
            '''
            print "Failed at %08x" % jnz_ea
            break

        jnz_call_target_ea = maze_deobf_utils.GetInstuctionTargetAddress(jnz_insn)

        if jnz_call_target_ea == CallAddress:
            is_cal_type_three = True
        #print "\tnext address: %08x" % jnz_call_target_ea
    
    return is_cal_type_three

def FindCallTypeThreeCFGObfuscation():
    '''
    @detail  Find all of the CFG Obfuscations that match the following pattern (Type Three):

                push    <return address>
                0000    JZ      xxxxxxxx
                0001    JNZ     0010
                ....
                0010    JNZ     xxxxxxxx
                0011    JZ      <address of junk>  ;unreachable

            
            The jump destination for both is the same.
    '''    

    near_opcodes = "68 ? ? ? ? 0f 84 ? ? ? ? 75"
    short_opcodes = "68 ? ? ? ? 74 ? 75"

    end_ea = ida_ida.cvar.inf.max_ea

    addr_list = set()

    obfuscated_list = []
    cfg = ida_search.find_binary(0, end_ea, near_opcodes, 0, SEARCH_DOWN | SEARCH_CASE)
    while cfg != idc.BADADDR:
        
        obfuscated_list.append(cfg)
        cfg =ida_search.find_binary(cfg+4, end_ea,  near_opcodes, 0, SEARCH_DOWN | SEARCH_CASE)
    
    cfg = ida_search.find_binary(0, end_ea, short_opcodes, 0, SEARCH_DOWN | SEARCH_CASE)
    while cfg != idc.BADADDR:
        
        obfuscated_list.append(cfg)
        cfg =ida_search.find_binary(cfg+4, end_ea,  short_opcodes, 0, SEARCH_DOWN | SEARCH_CASE)

    for cfg3_ea in obfuscated_list:
        

        push_instr_ea = cfg3_ea
       
        push_insn = ida_ua.insn_t()
        ida_ua.decode_insn(push_insn, push_instr_ea)
        if maze_deobf_utils.CheckValidTargettingInstr(push_insn, "push"):
            
            push_op = push_insn.ops[0]

            jz_ea = push_instr_ea + push_insn.size
            jz_insn = ida_ua.insn_t()
            ida_ua.decode_insn(jz_insn, jz_ea)

            if maze_deobf_utils.CheckValidTargettingInstr(jz_insn, "jz"):
                #
                #   Get the target address for the first JZ
                #   
                
                jz_calltarget_ea = maze_deobf_utils.GetInstuctionTargetAddress(jz_insn)

                jnz_ea = jz_ea + jz_insn.size
                jnz_insn = ida_ua.insn_t()
                ida_ua.decode_insn(jnz_insn, jnz_ea)

                if maze_deobf_utils.CheckValidTargettingInstr(jnz_insn, "jnz"):

                    jnz_calltarget_ea = maze_deobf_utils.GetInstuctionTargetAddress(jnz_insn)

                    if jnz_calltarget_ea != jz_calltarget_ea:
                        #
                        #   These two values do not match for Call Type 3
                        #

                        addr_list.add(push_instr_ea)
    
    return addr_list


def PatchJZJNZControlFlow(StartAddress, TargetAddress=0):
    """
        @detail This code will zero out a JZ/JNZ code block and undefine the targets for 
                 each instruction.
    """

    #
    #   JNZ Instruction
    #   
    jnz_ea = StartAddress
    jnz_insn = ida_ua.insn_t()
    ida_ua.decode_insn(jnz_insn, jnz_ea)
    jnz_insn_target_ea = maze_deobf_utils.GetInstuctionTargetAddress(jnz_insn)

    #
    #   Handle JZ instruction
    #   
    jz_insn_ea = jnz_ea + jnz_insn.size
    jz_insn = ida_ua.insn_t()
    ida_ua.decode_insn(jz_insn, jz_insn_ea)
    jz_insn_target_ea = maze_deobf_utils.GetInstuctionTargetAddress(jz_insn)


    if maze_deobf_utils.CheckValidTargettingInstr(jnz_ea, "jnz"):
        ZeroOutInstruction(jnz_insn)

    if maze_deobf_utils.CheckValidTargettingInstr(jz_insn_ea, "jz"):
        ZeroOutInstruction(jz_insn)
    


    del_items(jz_insn_target_ea,1)

    if jnz_insn_target_ea != TargetAddress:
        #
        #   Undefine only if it isn't the address of a call instruction
        #

        del_items(jnz_insn_target_ea,1)
    
    print "[PatchJZJNZControlFlow], JNZ: %08x, JZ: %08x, JNZT: %08x, JZT: %08x" % (jnz_ea, jz_insn_ea, jnz_insn_target_ea, jz_insn_target_ea)


def WalkAndPatchJZJNZControlFlow(TargetAddress, StartAddress):
    """
        @detail Start with the JNZ edge of a JZ/JNZ obfuscation and walk down until the 
                 the JNZ target address matches the Call address. This will handle multiple 
                 JZ/JNZ blocks for Call Type Three Obfuscations. The assumption is that when 
                 a call is obfuscated in this manner it has to always be called. 

    """

    #print "Call Target: %08x, Starting at: %08x" % (CallAddress,StartAddress)
    jnz_call_target_ea = StartAddress


    while jnz_call_target_ea != TargetAddress:

        print "WalkAndPatchJZJNZControlFlow, start: %08x" % jnz_call_target_ea
        jnz_ea = jnz_call_target_ea
        jnz_insn = ida_ua.insn_t()
        ida_ua.decode_insn(jnz_insn, jnz_ea)

        if maze_deobf_utils.CheckValidTargettingInstr(jnz_insn, "jnz"):
            '''
                Current instruction is JNZ with valid target address
            '''

            #
            #   Patch control flow iff the JNZ target is also a JNZ
            #
            jnz_target_ea = maze_deobf_utils.GetInstuctionTargetAddress(jnz_insn)
            if maze_deobf_utils.CheckValidTargettingInstr(jnz_target_ea, "jnz"):
                print "WalkAndPatchJZJNZControlFlow, patch: %08x, Target Address: %08x" % (jnz_calljnz_target_ea_target_ea, TargetAddress)
                PatchJZJNZControlFlow(jnz_target_ea, TargetAddress)
            
            jnz_call_target_ea = jnz_target_ea

def PatchCallTypeThreeCFGObfuscation(Instr_ea):
    """
        @detail  Patch all of the CFG Obfuscations that match the Call Type Three:

                68 19 28 45 6E      push    <return address>
                0F 84 05 3C 01 00   JZ      xxxxxxxx
                75 <size>           JNZ     0010
                ....
                0010    JNZ     xxxxxxxx
                0011    JZ      <address of junk>
            
            There can be a multitude of JNZ/JZ blocks that ultimately end up executing the function address xxxxxxxx. The 
             patch is straightfoward: 

                90      NOP
                90      NOP
                90      NOP
                90      NOP
                90      NOP
                CALL   xxxxxxxx                 (5 bytes)
                JMP    <return address>         (2 bytes)        
    """
   
    #print "Type 3: %08x" % Instr_ea

    #
    #   Handle the push instruction
    #
    push_instr_ea = Instr_ea
    push_insn = ida_ua.insn_t()
    ida_ua.decode_insn(push_insn, push_instr_ea)
    push_insn_target = maze_deobf_utils.GetInstuctionTargetAddress(push_insn)

    deobf_jmp_target_ea = push_insn_target

    #
    #   Handle JZ instruction
    #   
    jz_insn_ea = push_instr_ea + push_insn.size
    jz_insn = ida_ua.insn_t()
    ida_ua.decode_insn(jz_insn, jz_insn_ea)
    jz_insn_target_ea = maze_deobf_utils.GetInstuctionTargetAddress(jz_insn)

    deobf_call_target_ea = jz_insn_target_ea


    #
    #   JNZ Instruction
    #   
    jnz_ea = jz_insn_ea + jz_insn.size
    jnz_insn = ida_ua.insn_t()
    ida_ua.decode_insn(jnz_insn, jnz_ea)
    
    WalkAndPatchJZJNZControlFlow(deobf_call_target_ea, jnz_ea)

    deobf_call_ea = push_instr_ea+1
    deobf_jmp_ea = push_instr_ea+6

    #
    #   Calculate the offset for the relative JMP instruction, the value that
    #    was previously the target for the PUSH instruction
    #
    #       offset = target_address - address_of_insn_after_JMP
    #
    deobf_jmp_dest_offset = (deobf_jmp_target_ea - (deobf_jmp_ea+5))  & 0xFFFFFFFF

    #
    #   Calculate the offset for the relative CALL instruction, the value that
    #    was previously the target for the JZ instruction
    #
    #       offset = target_address - address_of_insn_after_CALL
    #
    deobf_call_dest_offset = (deobf_call_target_ea - (deobf_call_ea + 5))  & 0xFFFFFFFF

    #print "Push instr ea: %08x, Call Instr ea: %08x, Call Instr Offset: %08x" % (push_instr_ea,deobf_call_ea,deobf_call_dest_offset)
    #print "JMP Ea: %08x, Offset %08x" % (deobf_jmp_ea, deobf_jmp_dest_offset)


    #
    #   Cleanup area after JMP instruction
    #
    clenaup_junk_code_ea = deobf_jmp_ea + 5
    patch_byte(clenaup_junk_code_ea, 0x00)
    patch_byte(clenaup_junk_code_ea+1, 0x00)
    patch_byte(clenaup_junk_code_ea+2, 0x00)
    patch_byte(clenaup_junk_code_ea+3, 0x00)

    #
    #   Patch JNZ and JZ w/ Call;JMP
    #   
    patch_byte(push_instr_ea, 0x90)
    patch_byte(deobf_call_ea, 0xE8)
    patch_dword(deobf_call_ea+1,deobf_call_dest_offset)
    patch_byte(deobf_jmp_ea, 0xE9)
    patch_dword(deobf_jmp_ea+1,deobf_jmp_dest_offset)

    del_items(push_instr_ea,1)
   
    #
    #   Make instructions starting with the first NOP (push_instr_ea)
    #
    create_insn(push_instr_ea)
    plan_and_wait(push_instr_ea, push_instr_ea+push_insn.size)

    #
    #   Make JMP destination code
    #
    del_items(deobf_jmp_target_ea,1)
    deobf_jmp_dst_insn = ida_ua.insn_t()
    ida_ua.decode_insn(deobf_jmp_dst_insn, deobf_jmp_target_ea)
    create_insn(deobf_jmp_target_ea)
    plan_and_wait(deobf_jmp_target_ea, deobf_jmp_target_ea+deobf_jmp_dst_insn.size)

    #
    #   Make CALL destination code
    #
    del_items(deobf_call_target_ea,1)
    deobf_call_dst_insn = ida_ua.insn_t()
    ida_ua.decode_insn(deobf_call_dst_insn, deobf_call_target_ea)
    create_insn(deobf_call_target_ea)
    plan_and_wait(deobf_call_target_ea, deobf_call_target_ea+deobf_call_dst_insn.size)

def FindAbsoluteJumps():
    """
        @brief  Locates short JZ, near JZ, and near JNZ obfuscations.

        @detail Locates short JZ, near JZ, and near JNZ obfuscations. For example:

            000: 74 55                        jz      short loc_6E456049
            002: 75 04                        jnz     short loc_008
            004: 0E                           push    cs
            005: 02 00                        add     al, [eax]
            ;-----------------------------------------------------------
            007: 00                           db    0              
            ;-----------------------------------------------------------
            008: 75 0A                        jnz     short loc_6E456006
            00A: 74 04                        jz      short loc_6E456002
            00C: DB 1A                        fistp   dword ptr [edx] 

            This obfuscation is actually an absolute jump. In some occasions, there are multiple sequences of these 
             JZ/JNZ obfuscations chained together. This will only find the obfuscations, the distinction between each 
             isn't important until it comes time to deobfuscate. 
            
            "74 ? 75" type short jumps can cause issues because the byte-search is generic and can hit on things that are not
             instructions. Verfiication is done to determined if the match is in a CODE segment. This will help avoid hitting on 
             strings located in data segments. 

        @return     A list containing each address for the located JZ/JNZ obfuscation

    """   

    jz_short_jmp = "74 ? 75"
    jz_near_jmp = "0F 84 ? ? ? ? 75"
    jnz_near_jmp = "74 ? 0F 85"

    end_ea = ida_ida.cvar.inf.max_ea

    addr_list = set()

    abs_jmp_list = set()

    obfuscated_list = []

    abs_jmp_ea = ida_search.find_binary(0, end_ea, jz_short_jmp, 0, SEARCH_DOWN | SEARCH_CASE)
    while abs_jmp_ea != idc.BADADDR: 
        #print "Short jump: %08x" % abs_jmp_ea
        obfuscated_list.append(abs_jmp_ea)
        abs_jmp_ea =ida_search.find_binary(abs_jmp_ea+4, end_ea,  jz_short_jmp, 0, SEARCH_DOWN | SEARCH_CASE)
    
    abs_jmp_ea = ida_search.find_binary(0, end_ea, jz_near_jmp, 0, SEARCH_DOWN | SEARCH_CASE)
    while abs_jmp_ea != idc.BADADDR: 
        obfuscated_list.append(abs_jmp_ea)
        abs_jmp_ea =ida_search.find_binary(abs_jmp_ea+4, end_ea,  jz_near_jmp, 0, SEARCH_DOWN | SEARCH_CASE)
    
    abs_jmp_ea = ida_search.find_binary(0, end_ea, jnz_near_jmp, 0, SEARCH_DOWN | SEARCH_CASE)
    while abs_jmp_ea != idc.BADADDR: 
        obfuscated_list.append(abs_jmp_ea)
        abs_jmp_ea =ida_search.find_binary(abs_jmp_ea+4, end_ea,  jnz_near_jmp, 0, SEARCH_DOWN | SEARCH_CASE)
    
    
    #print "[START] Find absolute jumps."
        
    
    for abs_jmp_ea in obfuscated_list:
        #
        #   Walk each found obfuscation
        #

        #
        #   Get, Decode, and Verify JZ instruction
        #
        jz_insn_ea = abs_jmp_ea
        jz_insn = ida_ua.insn_t()
        ida_ua.decode_insn(jz_insn, jz_insn_ea)

        #print "%08x - check" % abs_jmp_ea
        if maze_deobf_utils.CheckValidTargettingInstr(jz_insn, "jz"):


            prev_insn_ea = jz_insn_ea - 5
            prev_insn = ida_ua.insn_t()
            ida_ua.decode_insn(prev_insn, prev_insn_ea)
            if maze_deobf_utils.CheckValidTargettingInstr(prev_insn, "push"):
                #
                # if previous instruction is a push <address>, 
                #   this is an obfuscated call, skip to next located absolute jump
                #

                continue

            #
            #   Get, Decode, and Verify JZ instruction
            #
            jnz_insn_ea = jz_insn_ea + jz_insn.size
            jnz_insn = ida_ua.insn_t()
            ida_ua.decode_insn(jnz_insn, jnz_insn_ea)

            #print "%08x - JZ" % abs_jmp_ea
            if maze_deobf_utils.CheckValidTargettingInstr(jnz_insn, "jnz"):
                #
                #   Absolute JMP found
                #

                #print "%08x - verified" % abs_jmp_ea
                addr_list.add(jz_insn_ea)
    
    return addr_list

def FollowJNZForAbsoluteJumpTarget(Insn_ea):
    """
        @detail Follow the JNZ branch of an absolute JMP obfuscation until 
                 an instruction other than JNZ is reached. Once this occurs, return 
                 the address of the non-JNZ instruction. 
        
        @return jnz_target_ea  Target address for absolute JMP
    """

    jnz_insn_target_ea = idc.BADADDR
    jnz_insn_ea = Insn_ea
    insn_dism = generate_disasm_line(jnz_insn_ea,1)

    if insn_dism.startswith("jnz"):
        while insn_dism.startswith("jnz"):
            #
            #   Follow target until instruction is not a JNZ
            #

            #
            #   Get JNZ Instruction
            #
            jnz_insn = ida_ua.insn_t()
            ida_ua.decode_insn(jnz_insn, jnz_insn_ea)
            jnz_insn_target_ea = maze_deobf_utils.GetInstuctionTargetAddress(jnz_insn)

            #
            #   Get disassembly for JNZ target
            #
            jnz_insn_ea = jnz_insn_target_ea
            insn_dism = generate_disasm_line(jnz_insn_ea,1)

    else:
        #
        #   Instruction is not JNZ, target address is Insn_ea
        #

        jnz_insn_target_ea = Insn_ea
    
    return jnz_insn_target_ea    

def PatchAbsoluteJump(Insn_ea):
    """
        @breif Deobfuscate absolute jump obfuscation types

        @detail  Patches Type One and Type Two absolute jumps. There is no need to worry about 
                 any of the located instruction matching the CALL obfuscations, those have already 
                 been dealt with. 

                0000    <two-byte/four-byte opcode>   JZ      xxxxxxxx
                0001    <two-byte/four-byte opcode>   JNZ     <address of another JNZ/JZ block, or address of next non-JNZ instruction>

                The JZ/JNZ block is walked looking for the target address of the abosolute JMP, the initial JZ is not touched.

                0000    <two-byte/four-byte opcode>   JZ      xxxxxxxx
                0001    <five-byte opcode>            JMP     <absolute jmp target address>
    """

    print "Absolute Jump Address: %08x" % (Insn_ea)
    jz_insn_ea = Insn_ea

    abs_jump_ea = idc.BADADDR
    abs_jmp_target_ea = idc.BADADDR

    #
    #   Get JZ instruction 
    #
    jz_insn = ida_ua.insn_t()
    ida_ua.decode_insn(jz_insn, jz_insn_ea)
    jz_insn_target_ea = maze_deobf_utils.GetInstuctionTargetAddress(jz_insn)

    #
    #   Get JNZ Instruction
    #
    jnz_insn_ea = jz_insn_ea + jz_insn.size
    jnz_insn = ida_ua.insn_t()
    ida_ua.decode_insn(jnz_insn, jnz_insn_ea)
    jnz_insn_target_ea = maze_deobf_utils.GetInstuctionTargetAddress(jnz_insn)

    abs_jmp_ea = jz_insn_ea + jz_insn.size
    abs_jmp_target_ea = FollowJNZForAbsoluteJumpTarget(jnz_insn_target_ea)

    WalkAndPatchJZJNZControlFlow(abs_jmp_target_ea, jnz_insn_ea)

    if jz_insn_target_ea == jnz_insn_target_ea:

        abs_jmp_target_offset = (abs_jmp_target_ea - (abs_jmp_ea+5)) & 0xFFFFFFFF

        del_items(jz_insn_ea,1)

        ZeroOutInstruction(jnz_insn)

    else:

        
    
        #
        #   Calculate the offset for the relative JMP instruction.
        #
        #       offset = target_address - address_of_insn_after_JMP
        #
        abs_jmp_target_offset = (abs_jmp_target_ea - (abs_jmp_ea+5)) & 0xFFFFFFFF

        print "JMP EA: %08x, Absolute JMP Target EA: %08x, Offset: %08x" % (abs_jmp_ea, abs_jmp_target_ea, abs_jmp_target_offset) 

        del_items(jz_insn_ea,1)

    #
    #   Apply patch
    #
    patch_byte(abs_jmp_ea, 0xE9)
    patch_dword(abs_jmp_ea+1, abs_jmp_target_offset)

    create_insn(jz_insn_ea) 

def FindObfuscatedWindowsAPICalls():
    '''
        @detail This obfuscation is used to resolve and call Windows procedures. Here is the obfuscation:
        
        68 3F 25 00 00                                  push    253Fh          ; unknown
        68 DC 20 DE 30                                  push    30DE20DCh      ; hash
        E8 0D 00 00 00                                  call    loc_6E44BCBF   ; procedure call
        6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00                                                     'kernel32.dll',0  
        6E44BCBF 68 00 BD 44 6E                         push    offset callwindowsproc_6E44BD00 ; ret addr
        6E44BCC4 0F 84 56 58 FE FF                      jz      findLibrary
        6E44BCCA 75 04                                  jnz     short loc_6E44BCD0 
        
                It is not used for every call to a Windows procedure. However, this function will identify the 
                following pattern:

        68 3F 25 00 00                                                  push    253Fh          ; unknown
        68 DC 20 DE 30                                                  push    30DE20DCh      ; hash
        E8 0D 00 00 00                                                  call    loc_6E44BCBF   ; procedure call
        6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00          aKernel32Dll_44 db 'kernel32.dll',0  

                The match will search for the PUSH->PUSH->CALL and then validate that the bytes following 
                  call instruction is an ASCII string that ends with ".dll"
    
    '''


    opcodes = "68 ? ? ? ? 68 ? ? ? ? E8"

    end_ea = ida_ida.cvar.inf.max_ea

    addr_list = set()

    obfuscated_list = []
    cfg6_ea = ida_search.find_binary(0, end_ea, opcodes, 0, SEARCH_DOWN | SEARCH_CASE)

    while cfg6_ea != idc.BADADDR: 

        first_push_instr_ea = cfg6_ea
        first_push_insn = ida_ua.insn_t()
        ida_ua.decode_insn(first_push_insn, first_push_instr_ea)

        #print "First Push %08x" % first_push_instr_ea
        if maze_deobf_utils.CheckValidInstrImmediate(first_push_insn,"push"):
            
            second_push_instr_ea = first_push_instr_ea + first_push_insn.size
            second_push_insn = ida_ua.insn_t()
            ida_ua.decode_insn(second_push_insn, second_push_instr_ea)

            #print "Second Push %08x" % second_push_instr_ea
            if maze_deobf_utils.CheckValidInstrImmediate(second_push_insn,"push"):

                call_instr_ea = second_push_instr_ea + second_push_insn.size
                call_insn = ida_ua.insn_t()
                ida_ua.decode_insn(call_insn, call_instr_ea)
                call_insn_disasm = generate_disasm_line(call_instr_ea,1)
                
                #print "Call %08x" % call_instr_ea
                if call_insn_disasm.startswith("call"):

                    call_insn_target_ea = maze_deobf_utils.GetInstuctionTargetAddress(call_insn)
                    #print "Call target %08x" % call_insn_target_ea
                    if maze_deobf_utils.CheckValidTarget(call_instr_ea, call_insn_target_ea): 

                        module_name_ea = call_instr_ea + call_insn.size
                        
                        #print "Module Name %08x" % module_name_ea
                        if maze_deobf_utils.CheckIsDllName(module_name_ea):
                            addr_list.add(first_push_instr_ea)

        #
        #   Next match
        #
        cfg6_ea = ida_search.find_binary(cfg6_ea+5, end_ea, opcodes, 0, SEARCH_DOWN | SEARCH_CASE)

    return addr_list

def PatchObfuscatedWindowsAPICalls(Insn_ea):  
    '''
        @detail This patch is a bit tricky and can be easily messed with by the malware's author. Here is the
                original 

        68 3F 25 00 00                                  push    253Fh          ; unknown
        68 DC 20 DE 30                                  push    30DE20DCh      ; hash
        E8 0D 00 00 00                                  call    loc_6E44BCBF   ; procedure call
        6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00                                                     'kernel32.dll',0  
        6E44BCBF 68 00 BD 44 6E                         push    offset callwindowsproc_6E44BD00 ; ret addr
        6E44BCC4 0F 84 56 58 FE FF                      jz      findLibrary
        6E44BCCA 75 04                                  jnz     findLibrary

                The patch is going to look like the following set of instructions:
        
        68 3F 25 00 00                        push    253Fh          ; unknown
        68 DC 20 DE 30                        push    30DE20DCh      ; hash
        68 XX XX XX XX                        push    XXXXXXXX       ; address of kernel32.dll string
        E8 3E F4 FC FF                        call    findLibrary
        E9 31 00 00 00                        jmp     loc_6E44BD00
        XXXXXXXX 65 72 6E 65 6C 33 32 2E 64 6C 6C 00          aKernel32Dll_44 db 'kernel32.dll',0  

                The address of the "findLibrary" call needs to be found, the module name string 
                needs to be moved, and the push  to someplace else for this patch to be effective. 

                My initial patch is not going to worry about moving the module name, only locating 
                the address of findLibrary. Fortunately, that is simple enough the original call instruction
                can be followed to get both the address of the push instruction AND the return address that is 
                pushed on the stack. 

    '''

    first_push_ea = Insn_ea
    #
    #   Get first Push information
    #
    first_push_insn = ida_ua.insn_t()
    ida_ua.decode_insn(first_push_insn, first_push_ea)

    second_push_ea = first_push_ea + first_push_insn.size
    #
    #   Get second Push information
    #
    second_push_insn = ida_ua.insn_t()
    ida_ua.decode_insn(second_push_insn, second_push_ea)

    orig_call_ea = second_push_ea + second_push_insn.size
    #
    #   Get call information, call to get to findlibrary
    #
    orig_call_insn = ida_ua.insn_t()
    ida_ua.decode_insn(orig_call_insn, orig_call_ea)
    orig_call_target_ea = maze_deobf_utils.GetInstuctionTargetAddress(orig_call_insn)

    module_name_ea = orig_call_ea + orig_call_insn.size

    orig_call_target_insn = ida_ua.insn_t()
    ida_ua.decode_insn(orig_call_target_insn, orig_call_target_ea)

    push_retaddr_insn_ea = orig_call_target_ea
    push_ret_addr_insn = ida_ua.insn_t()
    ida_ua.decode_insn(push_ret_addr_insn, push_retaddr_insn_ea)

    #
    #   Get address of find library and return address
    #
    if maze_deobf_utils.CheckValidTargettingInstr(push_ret_addr_insn,"push"):

        #print "Type6 push: %08x" % push_retaddr_insn_ea

        findlibrary_return_address = maze_deobf_utils.GetInstuctionTargetAddress(push_ret_addr_insn)

        
        
        #
        #   JZ calllibrary instruction
        #
        findlibrary_jz_ea = push_retaddr_insn_ea + push_ret_addr_insn.size
        findlibrary_jz_insn = ida_ua.insn_t()
        ida_ua.decode_insn(findlibrary_jz_insn, findlibrary_jz_ea)

        if maze_deobf_utils.CheckValidTargettingInstr(findlibrary_jz_insn,"jz"):
            
            #print "Type6 jz: %08x" % findlibrary_jz_ea

            findlibrary_address =  maze_deobf_utils.GetInstuctionTargetAddress(findlibrary_jz_insn)

            push_modulename_insn_ea = orig_call_ea
            call_find_library_ea = orig_call_ea + 5
            jmp_ret_addr_ea = orig_call_ea + 10

            call_findlibrary_offset = (findlibrary_address - (call_find_library_ea + 5))  & 0xFFFFFFFF
            jmp_ret_addr_offset = (findlibrary_return_address - (jmp_ret_addr_ea + 5))  & 0xFFFFFFFF

            #
            #   JNZ calllibrary instruction, to be zero'd out
            #
            findlibrary_jnz_ea = findlibrary_jz_ea + findlibrary_jz_insn.size
            findlibrary_jnz_insn = ida_ua.insn_t()
            ida_ua.decode_insn(findlibrary_jnz_insn, findlibrary_jnz_ea)
            jnz_calllibrary_target = maze_deobf_utils.GetInstuctionTargetAddress(findlibrary_jnz_insn)

            #
            #   Prepare module name related addresses
            #
            new_modulename_ea = jmp_ret_addr_ea + 5
            module_name = GetModuleName(module_name_ea)

            if module_name:
                del_items(push_modulename_insn_ea,1)

                '''
                    START cleanup of previous instructions
                '''

                #
                #   Zero out previous string
                #
                module_name_len = len(module_name)
                
                zero_name_idx = 0
                while zero_name_idx < module_name_len:
                    patch_byte( module_name_ea+zero_name_idx, 0x00 )
                    zero_name_idx += 1

                if jnz_calllibrary_target != findlibrary_address:
                    #
                    #   Check if Type Three, if so, Zero out the next set of JZ/JNZ instructions as well  
                    #

                    junk_type3_jnz_insn_ea = jnz_calllibrary_target
                    junk_type3_jnz_insn = ida_ua.insn_t()
                    ida_ua.decode_insn(junk_type3_jnz_insn, junk_type3_jnz_insn_ea)

                    junk_type3_jz_insn_ea = junk_type3_jnz_insn_ea + junk_type3_jnz_insn.size
                    junk_type3_jz_insn = ida_ua.insn_t()
                    ida_ua.decode_insn(junk_type3_jz_insn, junk_type3_jz_insn_ea)

                    #
                    #   Zero them out
                    #
                    ZeroOutInstruction(junk_type3_jnz_insn)
                    ZeroOutInstruction(junk_type3_jz_insn)
                
                #
                #   NULL out original instructions related to FindLibrary
                #
                ZeroOutInstruction(push_ret_addr_insn)
                ZeroOutInstruction(findlibrary_jz_insn)
                ZeroOutInstruction(findlibrary_jnz_insn)
                '''
                    END cleanup of previous instructions
                '''

                module_name_idx = new_modulename_ea
                for char in module_name:
                    #
                    #   Write module name to new address
                    #
                    
                    patch_byte(module_name_idx,ord(char))
                    module_name_idx += 1
                    #print hex(module_name_idx), char
                patch_byte(module_name_idx,0x00)

                #
                #   Add push module name string instruction
                #
                CleanupPatchArea(push_modulename_insn_ea,5)
                patch_byte(push_modulename_insn_ea,0x68)
                patch_dword(push_modulename_insn_ea+1, new_modulename_ea)

                #
                #   Add call findlibrary instruction
                #
                CleanupPatchArea(call_find_library_ea,5)
                patch_byte(call_find_library_ea,0xE8)
                patch_dword(call_find_library_ea+1, call_findlibrary_offset)
                
                #
                #   Add JMP ret addr instruction
                #
                CleanupPatchArea(jmp_ret_addr_ea,5)
                patch_byte(jmp_ret_addr_ea,0xE9)
                patch_dword(jmp_ret_addr_ea+1, jmp_ret_addr_offset)

                create_insn(push_modulename_insn_ea)
                create_insn(call_find_library_ea)
                create_insn(jmp_ret_addr_ea)
                create_strlit(new_modulename_ea, module_name_idx)
  

def WalkBasicBlockUntilTerminator(Start_ea):
    '''
        @detail This function will identify the start and ending instructions for a basic block. 
                
                Notice, call instructions are not terminators and will not be followed, this is not part of a
                 recursive descent parser. All it does is find the start and end of a basic: ingress and egress.
                
                It tracks start address, end address, all addresses in-between, and call instructions.  
    
        @return address of last instruction in the basic block
    '''

    #
    #   All jump terminators
    #
    terminators = ['retn','jmp','jnz','jz','jo','jno', 'js','jns', 'je','jne', 'jb', 'jnae', 'jc', 'jnb', 'jae', 'jnc', 'jbe','jna', 'ja','jnbe', 'jl','jnge','jge','jnl','jle','jng','jg','jnle','jp','jpe','jnp','jpo','jcxz','jecxz']

    bb_start_ea = Start_ea
    curr_insn_ea = bb_start_ea

    bb_end_ea = -1

    while curr_insn_ea != idc.BADADDR:
        #
        #   Not ideal, but we will have to rely on other methods to determine if 
        #    a false positive is reached. However, if the address provided is always a legitimate instruction
        #    it has to lead to a terminator at some point. 
        #

        curr_insn = ida_ua.insn_t()
        decoded_success = ida_ua.decode_insn(curr_insn, curr_insn_ea)

        if decoded_success > 0:
            #
            #   Ensure instruction was properly decoded
            #  
            
            curr_insn_dism = generate_disasm_line(curr_insn_ea,1)
            
            #
            #   Undefine instruction
            #
            del_items(curr_insn_ea,1)

            if curr_insn_dism.startswith( tuple( terminators ) ):
                #
                #   End of block found
                #

                bb_end_ea = curr_insn_ea
                break
            
            curr_insn_ea = curr_insn_ea + curr_insn.size

            #
            #   Redefine instruction as code
            #
            create_insn(curr_insn_ea)        
        else:
            break
    
    return bb_end_ea

def WalkAndBuildFunctionByKnownPrologueAndEpilogue(Prologue, Epilogue):
    '''


    '''
    pass


def GetFunctionEpiloguesOne():
    '''
        @detail Identify function epilogues with two different search pattenrs (below). Once the two byte 
                 patterns have been identified, each instruction will be walked from the first byte pattern 
                 down to the second. This should build a basic block for the function.  

            6E454237 81 C4 08 08 00 00          add     esp, 808h    

                The first byte pattern looks for cleanup the space allocated for local variables on the stack 
                 for the stack frame. This is typically followed by restoring registers that were preserved by 
                 the prologue, and terminated by a return-like instruction.

            6E454245 FF 64 24 FC                                                     jmp     dword ptr [esp-4]

                The second byte pattern is the return instruction. In this case, the "jmp esp-4" instruction is 
                 proceeded by some form of incrementing the stack pointer by four. This increment will shift esp
                 past the return address that pushed by the call (thus, esp-4 for the jmp).
                
                If the first byte pattern reaches any version of the return instruction (retn or jmp esp-4) then
                 the address of the first instruction, address of the second instruction, the restored registers, 
                 and the value that esp was shifted by the "add esp, x" instructions are all saved.
                
                The purpsoe of knowning which registers are restored and the value added to esp is going to come up
                 when attempting to identify the prologue. Knowing this information will help know what to expect at the
                 start of the prologue AND if the prologue goes with this epilogue. That is both the registers and the 
                 value for esp should be the same for both epilogue and prologue.
        
        @return  epilogues_found { start_ea:{ "epilogue":FunctionEpilogue } }
    '''
 
    dword_stackframe_cleanup_opcode = "81 C4"
    byte_stackframe_cleanup_opcode = "83 C4"
    return_insn_opcode = "FF 64 24 FC"
    
    end_ea = ida_ida.cvar.inf.max_ea
    stackframe_cleanup_set = set()
    return_insn_set = set()

    epilogues_found = {}
    stack_immediates_found = {}
    
  
    #
    #   Find stack cleanup instructions
    #
    epi1_ea = ida_search.find_binary(0, end_ea, dword_stackframe_cleanup_opcode, 0, SEARCH_DOWN | SEARCH_CASE)
    while epi1_ea != idc.BADADDR:
        stackframe_cleanup_set.add(epi1_ea)
        epi1_ea = ida_search.find_binary(epi1_ea+5, end_ea, dword_stackframe_cleanup_opcode, 0, SEARCH_DOWN | SEARCH_CASE)
    
    #
    #   Find stack cleanup instructions
    #
    epi1_ea = ida_search.find_binary(0, end_ea, byte_stackframe_cleanup_opcode, 0, SEARCH_DOWN | SEARCH_CASE)
    while epi1_ea != idc.BADADDR:
        stackframe_cleanup_set.add(epi1_ea)
        epi1_ea = ida_search.find_binary(epi1_ea+5, end_ea, byte_stackframe_cleanup_opcode, 0, SEARCH_DOWN | SEARCH_CASE)

    #
    #   Find return instructions
    #
    epi1_ea = ida_search.find_binary(0, end_ea, return_insn_opcode, 0, SEARCH_DOWN | SEARCH_CASE)
    while epi1_ea != idc.BADADDR:
        return_insn_set.add(epi1_ea)
        epi1_ea = ida_search.find_binary(epi1_ea+7, end_ea, return_insn_opcode, 0, SEARCH_DOWN | SEARCH_CASE)
    
    for epi1_ea in stackframe_cleanup_set:
        #
        #   Start with the stack frame cleanup addresses. This seems to be the most natural way to start. 
        #     A stack frame cleanup address should lead to either an actual retn instruction or one of the 
        #     return addresses in return_insn_set. If it doesn't, put it in an unmatched set and ignore it.
        #

        stackframe_cleanup_immediate = 0
        bb_start_ea = 0
        bb_end_ea = 0
        unmatched_stackframe_set = set()
        unmatched_return_set = set()
        saved_registers = []

        addesp_ea = epi1_ea
        addesp_insn = ida_ua.insn_t()
        ida_ua.decode_insn(addesp_insn, addesp_ea)

        addesp_dism = generate_disasm_line(addesp_ea,1)

        epilogue_data = {}
        saved_immediates = []

        if (addesp_dism.startswith("add")) and  ("esp," in addesp_dism):
            if addesp_insn.ops[1].type == 5:
                #
                #   verify second operand is an immediate (type 5)
                #
                
                stackframe_cleanup_immediate = addesp_insn.ops[1].value

                next_insn_ea = addesp_ea + addesp_insn.size
                ctr = 0
                max_depth = 50
                while ctr < max_depth:
                    #
                    #   Only walk to max_depth
                    #

                    ctr += 1
                    next_insn = ida_ua.insn_t()
                    decoded_success = ida_ua.decode_insn(next_insn, next_insn_ea)

                    if decoded_success > 0:
                        #
                        #   Ensure instruction was properly decoded
                        #  
                        #print "epi1_ea: %08x, Insn_3a: %08x" % (addesp_ea,next_insn_ea)    
                        next_insn_dism = generate_disasm_line(next_insn_ea,1)
                        if (next_insn_dism.startswith("jmp")) and  ("esp" in next_insn_dism):
                            if next_insn_ea in return_insn_set:
                                #
                                #   Find jmp instruction in set
                                #

                                bb_end_ea = next_insn_ea
                                bb_start_ea = addesp_ea
                                break
                            else:
                                #
                                #   break if JMP of any other kind
                                #
                                break
                        elif next_insn_dism.startswith("retn"):
                            #
                            # straight return instruction, save
                            #

                            bb_end_ea = next_insn_ea
                            bb_start_ea = addesp_ea
                            break
                        
                        elif next_insn_dism.startswith("pop"):
                            if next_insn.ops[0].type == 1:
                                #
                                #   Pop general register, restore pre-function reg value
                                #

                                saved_registers.append(next_insn.ops[0].reg)
                        
                        #
                        #   Next two checks look for JZ->JNZ and JNZ->JZ, break out of loop
                        #    if this is true.
                        #
                        elif next_insn_dism.startswith("jz"):
                            next_next_insn_ea = next_insn_ea + next_insn.size
                            next_next_insn =  ida_ua.insn_t()
                            decoded_success = ida_ua.decode_insn(next_next_insn, next_next_insn_ea)

                            if decoded_success > 0:
                                next_next_isn_disasm =  generate_disasm_line(next_next_insn_ea,1)
                                if next_next_isn_disasm.startswith("jnz"):
                                    break
                        elif next_insn_dism.startswith("jnz"):

                            next_next_insn_ea = next_insn_ea + next_insn.size
                            next_next_insn =  ida_ua.insn_t()
                            decoded_success = ida_ua.decode_insn(next_next_insn, next_next_insn_ea)

                            if decoded_success > 0:
                                next_next_isn_disasm =  generate_disasm_line(next_next_insn_ea,1)
                                if next_next_isn_disasm.startswith("jz"):
                                    break
                        
                        next_insn_ea = next_insn_ea + next_insn.size
                        

        if bb_start_ea > 0:
            basic_block = maze_functions.BasicBlock(bb_start_ea, bb_end_ea)
            basic_block.FillOutBlock()
            epilogue = maze_functions.FunctionEpilogue(basic_block, stackframe_cleanup_immediate, saved_registers)
            #epilogue_data = [bb_start_ea, bb_end_ea, unmatched_stackframe_set, unmatched_return_set, saved_registers, stackframe_cleanup_immediate]
            
            #
            #   stack immediates
            #
            if stackframe_cleanup_immediate in stack_immediates_found.keys():
                stack_immediates_found[stackframe_cleanup_immediate].append(stackframe_cleanup_immediate)
            else:
                saved_immediates.append(bb_start_ea)
                stack_immediates_found[stackframe_cleanup_immediate] = saved_immediates
            
            epilogues_found[bb_start_ea] = epilogue
                            
    #
    #   I don't like doing the return values this way, but whatever
    #
    return [epilogues_found, stack_immediates_found]                

def GetFunctionProloguesOne(StackImmeiatesFound, Epilogues):
    '''
        @detail Identify function prologues with one search pattern (below). Once this search pattern
                 has been identified, the immediate value will be checked agains the immediate value 
                 that is used by epilogues, then the registers pushed will be compared to those poppped, and then
                 the code walks forward to find the correct basic block.   

            6E453F64 81 EC 08 08 00 00                sub     esp, 808h    

                The first byte pattern looks for cleanup the space allocated for local variables on the stack 
                 for the stack frame. This is typically proceeded by saving registers by pushing the register
                 values to the stack.
                
                The purpsoe of knowning which registers are restored and the value added to esp is going to come up
                 when attempting to identify the prologue. Knowing this information will help know what to expect at the
                 start of the prologue AND if the prologue goes with this epilogue. That is both the registers and the 
                 value for esp should be the same for both epilogue and prologue.
        
        @return  epilogues_found {start_ea:[bb_start_ea, bb_end_ea, unmatched_stackframe_set, unmatched_return_set, [registers], stackframe_cleanup_immediate]}
    '''

    stackframe_cleanup_opcode = "81 EC"
    
    end_ea = ida_ida.cvar.inf.max_ea
    stackframe_reserve_set = set()
    return_insn_set = set()

    stack_immediates_found = StackImmeiatesFound

    prologues_found = {}
  
    #
    #   Find stack cleanup instructions
    #
    prol1_ea = ida_search.find_binary(0, end_ea, stackframe_cleanup_opcode, 0, SEARCH_DOWN | SEARCH_CASE)
    while prol1_ea != idc.BADADDR:
        stackframe_reserve_set.add(prol1_ea)
        prol1_ea = ida_search.find_binary(prol1_ea+5, end_ea, stackframe_cleanup_opcode, 0, SEARCH_DOWN | SEARCH_CASE)
    
    for prol1_ea in stackframe_reserve_set:

        stackframe_reserve_immediate = 0
        bb_start_ea = 0
        bb_end_ea = 0

        subesp_ea = prol1_ea
        subesp_insn = ida_ua.insn_t()
        ida_ua.decode_insn(subesp_insn, subesp_ea)

        subesp_dism = generate_disasm_line(subesp_ea,1)

        if (subesp_dism.startswith("sub")) and  ("esp," in subesp_dism):
            if subesp_insn.ops[1].type == 5:
                #
                #   verify second operand is an immediate (type 5)
                #
                

                stackframe_reserve_immediate = subesp_insn.ops[1].value

                if stackframe_reserve_immediate in stack_immediates_found.keys():
                    #
                    #   Look for start address of the last basic block (epilogue)
                    #
                    
                    possible_epilogues = stack_immediates_found[stackframe_reserve_immediate]
                    for epilogue_ea in possible_epilogues:
                        #
                        #   There can be multiple exit points for a function. 
                        #

                        if epilogue_ea in Epilogues.keys():
                            epilogue = Epilogues[epilogue_ea]
                            registers = epilogue.registers
                            #print "Prologue %08x, Epilogue %08x" % (subesp_ea, epilogue_ea)
                            
                            register_match = False
                            idx = 1
                            for popreg in registers:
                                #
                                #   should unwind in the same order as the push instructions
                                #

                                pushreg_ea = subesp_ea - idx
                                pushreg_insn = ida_ua.insn_t()
                                ida_ua.decode_insn(pushreg_insn, pushreg_ea)

                                pushreg_dism = generate_disasm_line(pushreg_ea,1)
                                if pushreg_dism.startswith("push"):
                                    if pushreg_insn.ops[0].type == 1:
                                        if popreg == pushreg_insn.ops[0].reg:
                                            #
                                            # mnemonic, operand type, and reg value verified
                                            #

                                            register_match = True
                                            idx += 1
                                        
                                        else:
                                            register_match = False
                                            break
                                    else:
                                        register_match = False
                                        break                                        
                                else:
                                    register_match = False
                                    break
                            
                            if register_match:
                                bb_end_ea = WalkBasicBlockUntilTerminator(subesp_ea)

                                if bb_end_ea != idc.BADADDR:
                                    prologue_start_ea = subesp_ea - idx + 1
                                    #print "Subesp ea: %08x, Start ea %08x, End ea %08x" % (subesp_ea, prologue_start_ea, bb_end_ea)

                                    if prologue_start_ea in prologues_found.keys():
                                        #
                                        # multiple epilogues
                                        #

                                        prologue = prologues_found[prologue_start_ea]
                                        prologue.connected_epilogues.append(epilogue_ea)
                                        prologues_found[prologue_start_ea] = prologue

                                    else:
                                        #
                                        # create a new prologue
                                        #

                                        basic_block = maze_functions.BasicBlock(prologue_start_ea, bb_end_ea)
                                        basic_block.FillOutBlock()
                                        prologue = maze_functions.FunctionPrologue(basic_block, stackframe_reserve_immediate, registers)
                                        prologue.connected_epilogues.append(epilogue_ea)
                                        prologues_found[prologue_start_ea] = prologue
    
    return prologues_found

def BuildFunctions(FunctionPrologues, FunctionEpilogues):
    '''
        @detail Walk over each prologue and pass it the maze_functions.RecursiveDescent.DoDescentParser()
                 method to be parsed. Once the method returns, the function has been walked and can be 
                 defined. 
    '''

    idx = 0
    
    for prologue_ea in FunctionPrologues.keys():
        
        wrong_functions = set()
         
        prologue =  FunctionPrologues[prologue_ea]
        prologue_bb = prologue.basic_block
        prologue_bb_end_ea = prologue_bb.end_ea

        jcc_queue = []
        undefined_function_queue = []

        #
        #   Get epilogue
        #
        epilogue = FunctionEpilogues[prologue.connected_epilogues[0]]
        epilogue_end_ea = epilogue.basic_block.end_ea
        epilogue_end_insn = ida_ua.insn_t()
        ida_ua.decode_insn(epilogue_end_insn, epilogue_end_ea)
        function_end_ea = epilogue_end_ea + epilogue_end_insn.size
  
        
        #
        #   Call recursion function
        #
        print "Check function: %08x" % (prologue_ea)
        rec_descent = maze_functions.RecursiveDescent(prologue_ea)
        rec_descent.DoDescentParser(prologue.connected_epilogues)

        plan_and_wait(prologue_ea,function_end_ea,0) 

        #
        #   Create function
        #
        add_func_result = add_func(prologue_ea,function_end_ea)
        
        print "Function Created: %s %08x, end ea: %08x" % (add_func_result, prologue_ea, function_end_ea)
 
        for wrong_func_ea in rec_descent.wrong_functions:
            #
            #   redefined functions that were undefined in the DoDescentParser method.
            #
            #print "wrong func, start %08x, end %08x" % (wrong_func_ea[0],wrong_func_ea[1])
            add_func(wrong_func_ea,idc.BADADDR)
        
        idx +=1
    
    print "Number of functions created: %d" % (idx)
         

def CheckAllFunctionsEndAddresses(FunctionPrologues, FunctionEpilogues):
    '''
        @brief Check all known functions to ensure function start and end_ea are correct
    '''

    for known_func_ea in Functions():
        #
        #   Iterate over each defined function in IDA
        #

        for prologue_ea in FunctionPrologues.keys():
            #
            # Iterater over identified prologues
            #

            prologue =  FunctionPrologues[prologue_ea]
            prologue_bb = prologue.basic_block      
            prologue_start_ea = prologue_bb.start_ea

            if prologue_start_ea == known_func_ea:

                #
                #   ida specified end address of the function
                #
                ida_specified_func_end_ea = idc.find_func_end(known_func_ea)

                #
                #   Get epilogue, walk each address in known epilogues of the prologue
                #
                function_end_addresses = []
                for epilogue_ea in prologue.connected_epilogues:
                    epilogue = FunctionEpilogues[epilogue_ea]
                    epilogue_end_ea = epilogue.basic_block.end_ea
                    epilogue_end_insn = ida_ua.insn_t()
                    ida_ua.decode_insn(epilogue_end_insn, epilogue_end_ea)
                    function_end_ea = epilogue_end_ea + epilogue_end_insn.size

                    function_end_addresses.append(function_end_ea)

                if ida_specified_func_end_ea in function_end_addresses:
                    #
                    #   bail if this is correct
                    #
                    break
                
                idc.del_func(known_func_ea)
                plan_and_wait(known_func_ea,function_end_addresses[0])
                idc.del_items(known_func_ea,1)
                add_func(known_func_ea,function_end_addresses[0])
                plan_and_wait(known_func_ea,function_end_addresses[0])

                print "Incorrect function ends: %08x, %08x" % (known_func_ea, ida_specified_func_end_ea)

def BuildFunctions2(FunctionPrologues, FunctionEpilogues):
    '''
        @detail Walk over each prologue and pass it the maze_functions.RecursiveDescent.DoDescentParser()
                 method to be parsed. Once the method returns, the function has been walked and can be 
                 defined. 
    '''

    idx = 0
    
    for prologue_ea in FunctionPrologues.keys():
        
        wrong_functions = set()
         
        prologue =  FunctionPrologues[prologue_ea]
        prologue_bb = prologue.basic_block
        prologue_bb_end_ea = prologue_bb.end_ea

        jcc_queue = []
        undefined_function_queue = []

        #
        #   Get epilogue
        #
        epilogue = FunctionEpilogues[prologue.connected_epilogues[0]]
        epilogue_end_ea = epilogue.basic_block.end_ea
        epilogue_end_insn = ida_ua.insn_t()
        ida_ua.decode_insn(epilogue_end_insn, epilogue_end_ea)
        function_end_ea = epilogue_end_ea + epilogue_end_insn.size
  
        
        #
        #   Call recursion function
        #
        #print "Check function: %08x" % (prologue_ea)
        rec_descent = maze_function_analysis.RecursiveDescent(prologue_ea, None)
        curr_function = rec_descent.DoDescentParser3()

        
        for bblock in curr_function.rogue_basic_blocks:

            print "[Current Function, Start: %08x, End: %08x" % (curr_function.start_ea, curr_function.end_ea)
            incorrect_func_ea = bblock.incorrect_function_ea

            incorrect_ida_func = ida_funcs.get_func(incorrect_func_ea)
            if incorrect_ida_func:

                #
                #   Delete IDA's incorrect function
                #
                print "Deleting Incorrect IDA function: %08x" % incorrect_ida_func.start_ea
                ida_funcs.del_func(incorrect_ida_func.start_ea)

                #
                #   Define the new function and wait
                #
                correct_ida_func = ida_funcs.get_func(curr_function.start_ea)
                if correct_ida_func:
                    #
                    #   Delete if the correct function has already been defined
                    #
                    ida_funcs.del_func(correct_ida_func.start_ea)

                print "Creating Corrected IDA function: %08x" % curr_function.start_ea
                ida_funcs.add_func(curr_function.start_ea, curr_function.end_ea)

                if bblock.start_ea != incorrect_ida_func.start_ea:
                    #
                    #   Recreate function only if the basic block wasn't the prologue
                    #
                    print "Re-creating IDA function: %08x" % incorrect_ida_func.start_ea
                    ida_funcs.add_func(incorrect_ida_func.start_ea, incorrect_ida_func.end_ea)
    

def CheckAllFunctionsEndAddresses2():    
    '''
        @brief Check all known functions to ensure function start and end_ea are correct
    '''

    for known_func_ea in Functions():
        #
        #   Iterate over each defined function in IDA
        #

        ida_func = ida_funcs.get_func(known_func_ea)

        if known_func_ea == 0x004099A0:
            rec_descent = maze_function_analysis.RecursiveDescent(known_func_ea, None)
            curr_function = rec_descent.DoDescentParser3()

            for bblock in curr_function.basic_blocks:
                if ida_func.end_ea in bblock.instruction_addresses:
                    print "Mis-match: Start %08x, End: %08x, Fake: %08x" % (curr_function.start_ea, curr_function.end_ea, ida_func.end_ea)
                    ida_funcs.del_func(curr_function.start_ea)
                    ida_funcs.add_func(curr_function.start_ea, curr_function.end_ea)

    func_prologue_opcode = "55 89 E5"
    
    end_ea = ida_ida.cvar.inf.max_ea

    prologues_found = {}
  
    #
    #   Find stack cleanup instructions
    #
    prol1_ea = ida_search.find_binary(0, end_ea, func_prologue_opcode, 0, SEARCH_DOWN | SEARCH_CASE)
    while prol1_ea != idc.BADADDR:
        found_func = ida_funcs.get_func(prol1_ea)

        if found_func:
            prol1_ea = ida_search.find_binary(prol1_ea+5, end_ea, func_prologue_opcode, 0, SEARCH_DOWN | SEARCH_CASE)  
            continue
        
        

        rec_descent = maze_function_analysis.RecursiveDescent(prol1_ea, None)
        curr_function = rec_descent.DoDescentParser3()

        print "Found function: Start %08x, End %08x" % (curr_function.start_ea, curr_function.end_ea)

        #ida_funcs.add_func(curr_function.start_ea, curr_function.end_ea)

        prol1_ea = ida_search.find_binary(prol1_ea+5, end_ea, func_prologue_opcode, 0, SEARCH_DOWN | SEARCH_CASE)  

        #end_addresses, funcs_to_delete = rec_descent.DoDescentParser()

        #if (ida_func.end_ea not in end_addresses) and (len(end_addresses) > 0): 
        #    print "Start address: %08x, End address: %08x, Found address: %08x" % (ida_func.start_ea, ida_func.end_ea,end_addresses[0])
        #    for ea in funcs_to_delete:
        #        print "Deleting: %08x" % ea
        #        ida_funcs.del_func(ea)
            
        #    ida_funcs.add_func(ida_func.start_ea, end_addresses[0])

        #    for ea in funcs_to_delete:
        #        print "Adding: %08x" % ea
        #        ida_funcs.add_func(ea, idc.BADADDR)


        #if (ida_func.end_ea not in end_address) and (len(end_address) > 0):   
        #    print "Start address: %08x, End address: %08x, Found address: %08x" % (ida_func.start_ea, ida_func.end_ea,end_address[0])
        #    ida_funcs.del_func(known_func_ea)
        #    ida_funcs.add_func(ida_func.start_ea, end_address[0])
            



def main():

    typeone_addresses = set()
    typetwo_addresses = set()
    typethree_addresses = set()
    typefour_addresses = set()
    typefive_addresses = set()
    typesix_addresses = set()
    typeseven_address = set()

    obf_windowsapi_calls = set()
    calltypethree_addresses = set()
    absolute_jumps = set()

    #
    #   Generate a list of functions prior to removing deobfuscations
    #
    prev_state_func_list = []
    for func_ea in idautils.Functions():
        func = ida_funcs.get_func(func_ea)
        prev_state_func_list.append( func )



    find_obfuscations = True
    do_patches = True
    
    if find_obfuscations: 
        obf_windowsapi_calls = FindObfuscatedWindowsAPICalls()
        if len(obf_windowsapi_calls) > 0 and do_patches:
            for obf_windowsapi_call_ea in obf_windowsapi_calls:
                print "Windows API Call: %08x" % obf_windowsapi_call_ea
                PatchObfuscatedWindowsAPICalls(obf_windowsapi_call_ea)
                #break
        
        typetwo_addresses = FindCallTypeTwoCFGObfuscation()    
        if len(typetwo_addresses) > 0 and do_patches:
            for typetwo_ea in typetwo_addresses:
                print "Call Type Two: %08x" % (typetwo_ea)
                PatchCallTypeTwoCFGObfuscation(typetwo_ea)
                #break
        
        typeone_addresses = FindCallTypeOneCFGObfuscation()
        if len(typeone_addresses) > 0 and do_patches:
            #print len(typeone_addresses)
            for typeone_ea in typeone_addresses:
                print "Call Type One: %08x" % (typeone_ea)
                PatchCallTypeOneCFGObfuscation(typeone_ea)
        #       #break

        calltypethree_addresses = FindCallTypeThreeCFGObfuscation()
        if len(calltypethree_addresses) and do_patches:
            for typethree_ea in calltypethree_addresses:
                print "Call Type Three: %08x" % (typethree_ea)
                PatchCallTypeThreeCFGObfuscation(typethree_ea)
                #break
        
        absolute_jumps = FindAbsoluteJumps()
        if len(absolute_jumps) > 0 and do_patches:
            for absolut_jmp_ea in absolute_jumps:
                print "Absolute Jump: %08x" % (absolut_jmp_ea)
                PatchAbsoluteJump(absolut_jmp_ea)
                #break
    
    
    typeone_epilogues, epilogue_immediates = GetFunctionEpiloguesOne()
    typeone_prologues = GetFunctionProloguesOne(epilogue_immediates,typeone_epilogues)
    BuildFunctions(typeone_prologues,typeone_epilogues)

    CheckAllFunctionsEndAddresses(typeone_prologues,typeone_epilogues)
    
    #BuildFunctions2(typeone_prologues, typeone_epilogues)
    CheckAllFunctionsEndAddresses2()

    #
    #   Generate a list of functions after removing deobfuscations
    #
    #post_state_func_list = []
    #for func_ea in idautils.Functions():
    #    func = ida_funcs.get_func(func_ea)
    #    post_state_func_list.append(func.end_ea)
    
    
    #
    #   This chunk of code is used to redifine functions that were correctly defined
    #    prior to the IDB
    #
    #missing_funcs = []
    #for func in prev_state_func_list:
    #    if func.end_ea not in post_state_func_list:
    #        missing_funcs.append(func)

    #for func in missing_funcs:
    #    print "Addr: %08x" % func.start_ea
    
    #print "Number of Type One epilogues: %d" % len(typeone_epilogues.keys())
    #print "Number of Type One prologues: %d" % len(typeone_prologues.keys())
    print "Aboslute Jump count: ", len(absolute_jumps)

main()