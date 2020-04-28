import idautils, idaapi, idc, ida_search, ida_ua, ida_name

def CheckInSegment(Curr_ea, Target_ea):
    '''
        @brief Check if the Target_ea is in the same segment as the Curr_ea and that it is SEG_CODE
    '''

    curr_segm_start_ea = idc.get_segm_start(Curr_ea) 
    curr_segm_end_ea = idc.get_segm_end(Curr_ea)

    return Target_ea >= curr_segm_start_ea and Target_ea <= curr_segm_end_ea

def CheckSegmentIsCode(Curr_ea):
    return idc.get_segm_attr(Curr_ea, idc.SEGATTR_TYPE) == idc.SEG_CODE

def CheckValidInstrImmediate(Curr_insn_t, Expected_mnem):
    '''
        @detail Takes single operand instruction and validates the instruction matches Expected_mnem and
                   that the operand is an immediate (type 5).

    '''
    isValid = False

    mnem = Expected_mnem.lower()

    if type(Curr_insn_t) == ida_ua.insn_t :
        #
        #  Correct type
        #

        insn = Curr_insn_t
        insn_ea = insn.ea
        insn_dism = idc.generate_disasm_line(insn_ea,1)

        if insn_dism[:5].startswith(mnem):
            operands = insn.ops
            if len(operands) > 0:
                idx = 0
                for op in operands:
                    if op.type != 0:
                        if op.type == 5:
                            isValid = True
                        
                        if idx > 0:
                            #
                            #   More than one operand
                            #
                            isVAlid = False
                    idx += 1
    
    return isValid

def CheckValidTarget(Curr_ea, Target_ea):
    '''
        @detail Take the address from the target of a current JMP instruction and verify that the 
                 operand type is immediate (5), the target address is located within the the same section,
                 the segment is code.

                 Not implemented: an xref check may be needed
        
        @returns BOOL
    '''

    valid_jump_target = False
    instr_operand = idautils.DecodeInstruction(Curr_ea).Op1

    if instr_operand.type in [5, 6, 7]:
        #
        #  Type is an immediate, immediate far address, immediate near address
        #
        
        if CheckInSegment(Curr_ea, Target_ea) and CheckSegmentIsCode(Curr_ea):
            valid_jump_target = True

    return valid_jump_target

def CheckValidTargettingInstr(Curr_insn_t, Expected_mnem):
    '''
        @detail Takes a push, jz, jnz, instruction and verifies that the operand
                 and the target of the address is valid.
           
        @returns BOOL           
    '''

    isValid = False

    mnem = Expected_mnem.lower()

    #print type(Curr_insn_t), Expected_mnem

    if (type(Curr_insn_t) == ida_ua.insn_t) and (mnem in ['push', 'jz', 'jnz']) :
        #
        #   Typecheck for Curr_insn_t
        #
    #print "valid check 0"
    
        insn_ea = Curr_insn_t.ea
        insn_dism = idc.generate_disasm_line(insn_ea,1)

        if mnem in insn_dism[:5]:
            #
            #   Ensure expected mnemonic in disassembly
            #
            
            #print "valid check 1"
            #
            #   There shoud be a single populated operand in the ops array
            #    I believe I read that the array always contains 8 op_t objects ( could be x86 only )
            #    Only the one at idx 0 should have a type other than 0.
            #
            operands = Curr_insn_t.ops
            if len(operands) > 0:
                #print "valid check 2"
                for op in operands:
                    if op.type != 0:
                        if (op.type in [5, 6, 7]) and (not isValid):
                            #
                            #  Type is an immediate, immediate far address, immediate near address
                            #

                            if op.type == 5:
                                target_ea = op.value
                            elif op.type == 6 or op.type == 7:
                                target_ea = op.addr
                            #print "valid check 3", hex(insn_ea), hex(target_ea) 
                            if CheckInSegment(insn_ea, target_ea) and CheckSegmentIsCode(insn_ea):
                                #
                                #   Located in the correct segment
                                #

                                #print "valid check 4"
                                isValid = True
                        elif isValid:
                            #
                            #   If other operand type
                            #
                            #print "valid check 5"
                            isValid = False
                            break


    return isValid

def CheckValidInstrImmediate(Curr_insn_t, Expected_mnem):
    '''
        @detail Takes single operand instruction and validates the instruction matches Expected_mnem and
                   that the operand is an immediate (type 5).

    '''
    isValid = False

    mnem = Expected_mnem.lower()

    if type(Curr_insn_t) == ida_ua.insn_t :
        #
        #  Correct type
        #

        insn = Curr_insn_t
        insn_ea = insn.ea
        insn_dism = idc.generate_disasm_line(insn_ea,1)

        if insn_dism.startswith(mnem):
            operands = insn.ops
            if len(operands) > 0:
                idx = 0
                for op in operands:
                    if op.type != 0:
                        if op.type == 5:
                            isValid = True
                        
                        if idx > 0:
                            #
                            #   More than one operand
                            #
                            isVAlid = False
                    idx += 1
    
    return isValid

def CheckFirstOperandIsIndirect(Curr_insn_ea):
    """
        @brief Check only if the first operand contains a register. This 
                 is for call, jmp, and JCC instruction types. No check is 
                 done on the mnemonic.

        @return     True if operand is type 1, 3, or 4 
    """

    isIndirect = False
    curr_insn = Curr_insn_ea

    if type(curr_insn) == ida_ua.insn_t:

        insn_operand = curr_insn.ops[0]

        if insn_operand.type in [1, 3, 4]:
            isIndirect = True
    
    return isIndirect

def GetInstuctionTargetAddress(Target_insn):
    '''
        @brief Return the operand value for the JZ, JNZ, or push isntruciton
    '''

    target_ea = 0

    if type(Target_insn) == ida_ua.insn_t:
        #print "GITA: type match"
        target_op = Target_insn.ops[0]
        #print "GITA: ", target_op.type, hex(target_op.value), hex(target_op.addr)
        if target_op.type == 5: 
            target_ea = target_op.value
        elif target_op.type == 6 or target_op.type == 7:
            target_ea = target_op.addr
    
    return target_ea

def CheckIsDllName(Strlit_ea):
    '''
        @brief Receive an address and verify that the bytes at that address are both
                ASCII and in with ".dll"
        
        @return BOOL
    '''
    is_module_name = False

    start_ea = Strlit_ea
    module_name = ""
    char = idc.get_wide_byte(start_ea)

    while ida_name.is_strlit_cp(char):
        module_name += chr(char)    
        start_ea += 1
        char = idc.get_wide_byte(start_ea)
    
    if idc.get_wide_byte(start_ea) ==  0x00:
        #
        #   Final char in ASCII string should be a NULL byte
        #

        if module_name.endswith(".dll"):
            is_module_name = True

    return is_module_name

def CheckInstructionIsFunctionTerminator(Insn_ea):
    """
        @detail Check if an instruction is RETN or equivilent. 
    """

    curr_insn_ea = Insn_ea

    is_return = False

    curr_insn_dism = idc.generate_disasm_line(curr_insn_ea,1)
    
    if curr_insn_dism.startswith("retn"):
        is_return = True
    
    elif curr_insn_dism.startswith("jmp"):

        jmp_insn = ida_ua.insn_t()
        ida_ua.decode_insn(jmp_insn, curr_insn_ea)

        if CheckFirstOperandIsIndirect(jmp_insn):
            #
            #   Check for esp+4
            #

            op = jmp_insn.ops[0]

            if (op.addr == 0xfffffffc) and (op.reg == 4):
                #
                #   Check if displacement is -4 and register is ESP (4)
                #

                is_return = True

    return is_return                