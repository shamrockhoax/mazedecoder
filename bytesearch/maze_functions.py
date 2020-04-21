import ida_ua, idc

def CheckInSegment(Curr_ea, Target_ea):
    '''
        @brief Check if the Target_ea is in the same segment as the Curr_ea. 
    '''

    #print "segcheck", Target_ea >= get_segm_start(Curr_ea), Target_ea <= get_segm_end(Curr_ea)

    return Target_ea >= get_segm_start(Curr_ea) and Target_ea <= get_segm_end(Curr_ea)

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
        insn_dism = generate_disasm_line(insn_ea,1)

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
        insn_dism = generate_disasm_line(insn_ea,1)

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
                            if CheckInSegment(insn_ea, target_ea):
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

class RecursiveDescent(object):
    '''
        @brief Recurse descent disassembly for a single function (no calls followed)
    '''

    def __init__(self, Start_ea):
        
        self.deferred_targets = []
        self.instructions_walked = []
        self.wrong_functions = []

        self.entry_point = Start_ea
        self.deferred_targets.append(Start_ea)

        self.emulators = Eumulators()



    def DoDescentParser(self,EndAddresses):
        '''
            @brief Walk the function leveraging a recursive descent parser. 

            @detail Starting with a prologue walk each instruction until the associated epilogue is reached. For functions 
                    with multiple epilogues, iterate over each one. 

                    As each instruction is traversed, do the following three
                    things:

                        - Undefine the instruction
                        - Mark the instruction as code
                        - Check to see if the instruction is already a member of another function
                    
                    If an instruction is a member of another function, undefine that function and place it in a queue. At the end
                     of traversing each function, a new function is going to be created with the new prologue and the new epilogue.
                     In addition, the undefined function queue is going to be iterated over and each function will be redefined. This
                     should clean up messy function
                    
                    much thanks to the author of "Practical Malware Analysis" for the break down of the algorithm in Chapter 8.
        '''

        #
        #   jmps = [eval("idaapi."+name) for name in dir(idaapi) if "NN_j" in name]
        #
        jcc_terminators = ['jnz','jz','jo','jno', 'js','jns', 'je','jne', 'jb', 'jnae', 'jc', 'jnb', 'jae', 'jnc', 'jbe','jna', 'ja','jnbe', 'jl','jnge','jge','jnl','jle','jng','jg','jnle','jp','jpe','jnp','jpo','jcxz','jecxz']

        #print EndAddresses

        while len(self.deferred_targets) > 0:

            curr_insn_ea = self.deferred_targets.pop()

            if curr_insn_ea in self.instructions_walked:
                #
                #   skip instructions that were already walked
                #
                continue

            #for target in self.deferred_targets:
            #    print "deferred target: %08x" % target
            

            while curr_insn_ea not in EndAddresses:
                #
                # walk only to a known epilogue
                #
                
                print "Current EA: %08x" % (curr_insn_ea)
                
                self.instructions_walked.append(curr_insn_ea)

                #
                #   Verify current instruction information
                #
                curr_insn = ida_ua.insn_t()
                decode_result = ida_ua.decode_insn(curr_insn, curr_insn_ea)
                if decode_result < 1:
                    # 
                    #   break if instruction invalide
                    #
                    break

                represented_insn_dism = idc.generate_disasm_line(curr_insn_ea,0)
                curr_insn_dism = idc.generate_disasm_line(curr_insn_ea,1)
                if curr_insn_dism != represented_insn_dism:
                    #
                    #   If the item shown at this address in IDA does not match 
                    #     what should be shown (due to obfuscation), fix it
                    #

                    #print "Instructions don't match: %08x" % (curr_insn_ea)
                    idc.del_items(curr_insn_ea,1)
                    #idc.plan_and_wait(curr_insn_ea, curr_insn_ea+curr_insn.size)
                    idc.create_insn(curr_insn_ea)
                    #idc.plan_and_wait(curr_insn_ea, curr_insn_ea+curr_insn.size)
                
                curr_func_name = idc.get_func_name(curr_insn_ea)
                if curr_insn_ea == 0x6E44184C:
                    print "Current function name: ", curr_func_name
                if curr_func_name:
                    #
                    #   check if in function, undefine function, add to list to redefine later
                    #

                    #print "Part of another function: %08x" % (curr_insn_ea)
                    curr_func_ea = idc.get_name_ea_simple(curr_func_name)
                    func_end_ea = idc.find_func_end(curr_func_ea)
                    idc.del_func(curr_func_ea)

                    for curr_function in self.wrong_functions:
                        if curr_function not in curr_function:
                            self.wrong_functions.append([curr_func_ea, func_end_ea])
                

                if curr_insn_dism.startswith( tuple( jcc_terminators ) ):
                    #
                    #   JCC conditionals, recursion control case
                    #
                    
                    #print "Adding jcc target: %08x" % (curr_insn_ea) 
                    jmp_target_ea = self.GetInstuctionTargetAddress(curr_insn)
                    if jmp_target_ea not in self.deferred_targets:
                        self.deferred_targets.append(jmp_target_ea)
                    
                    curr_insn_ea = curr_insn_ea + curr_insn.size
                
                elif curr_insn_dism.startswith("jmp"):
                    jmp_target_ea = self.GetInstuctionTargetAddress(curr_insn)

                    #print "Adding jump target: %08x" % (curr_insn_ea)  
                    if jmp_target_ea not in self.deferred_targets:
                        self.deferred_targets.append(jmp_target_ea)
                    break
                
                elif curr_insn_dism.startswith("retn"):
                    break
                
                else:
                    curr_insn_ea = curr_insn_ea + curr_insn.size

    
    def GetInstuctionTargetAddress(self,Target_insn):
        '''
            @brief Return the operand value for a unirary instruction that contains a target 
                    address (JMP, JNZ, JZ, push, call, etc).
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

    def DoDescentParser2(self, Targ_Funct):
        '''
            @brief Walk the function leveraging a recursive descent parser

            @detail Starting with a prologue walk each instruction until the associated epilogue is reached. For functions 
                    with multiple epilogues, iterate over each one. 

                    As each instruction is traversed, do the following three
                    things:

                        - Undefine the instruction
                        - Mark the instruction as code
                        - Check to see if the instruction is already a member of another function
                    
                    If an instruction is a member of another function, undefine that function and place it in a queue. At the end
                     of traversing each function, a new function is going to be created with the new prologue and the new epilogue.
                     In addition, the undefined function queue is going to be iterated over and each function will be redefined. This
                     should clean up messy function
                    
                    much thanks to the author of "Practical Binary Analysis" for the break down of the algorithm in Chapter 8.
        
                @return function object
        '''

        #
        #   jmps = [eval("idaapi."+name) for name in dir(idaapi) if "NN_j" in name]
        #
        jcc_terminators = ['jnz','jz','jo','jno', 'js','jns', 'je','jne', 'jb', 'jnae', 'jc', 'jnb', 'jae', 'jnc', 'jbe','jna', 'ja','jnbe', 'jl','jnge','jge','jnl','jle','jng','jg','jnle','jp','jpe','jnp','jpo','jcxz','jecxz']

        function = Function()

        while len(self.deferred_targets) > 0:

            curr_insn_ea = self.deferred_targets.pop()

            bblock = BasicBlock(curr_insn_ea)

            if curr_insn_ea in self.instructions_walked:
                #
                #   skip instructions that were already walked
                #
                
                continue
            
            self.instructions_walked.append(curr_insn_ea)

            while curr_insn_ea != idc.BADADDR:

                #
                #   Verify current instruction information
                #
                curr_insn = ida_ua.insn_t()
                decode_result = ida_ua.decode_insn(curr_insn, curr_insn_ea)
                if decode_result < 1:
                    # 
                    #   break if instruction invalid
                    #
                    bblock.end_ea = curr_insn_ea
                    break
            
                #
                #   Call Emulation Code Sequence
                #
                




class Function(object):
    '''
        @brief Representation of a function.
    '''
    def __init__():
        basic_blocks = []

class Eumulators(object):
    '''
        @brief Identify and Deobfuscate the various obfuscations
    '''

    def __init(self):
        pass

    def CheckZeroFlagAbsoluteJMP(self, EffectiveAddress):
        '''
        '''
        pass
    
    def CheckZFEmulatedCall(self, EffectiveAddress):
        '''
            @brief  Identify emulated function calls.

            @detail 

            push    <return address>
	        0000    JZ      xxxxxxxx
	        0001    JNZ     0010


            @returns The return address that is pushed to the stack for the CALL instruction
        '''

        rtrn_addr = idc.BADADDR

        push_instr_ea = EffectiveAddress
       
        push_insn = ida_ua.insn_t()
        ida_ua.decode_insn(push_insn, push_instr_ea)

        if CheckValidTargettingInstr(push_insn, "push"):
            """
                Valid PUSH instruction.
            """

            jz_insn_ea = push_instr_ea + push_insn.size()
            jz_insn = ida_ua.insn_t()
            ida_ua.decode_insn(jz_insn, jz_insn_ea)

            if CheckValidTargettingInstr(push_insn, "push"):
                """
                    Valid PUSH instruction.
                """

        return rtrn_addr



class BasicBlock(object):
    '''
        @brief  Class used for describing basic blocks. 
    '''

    def __init__(self,Start_ea=0, End_ea=0):
        self.start_ea = Start_ea
        self.end_ea = End_ea

        self.traversed = False

        self.instruction_addresses = []
        self.non_terminating_egress = set()

        self.is_prologue = False
        self.is_epilogue = False
    
    def AddInsnAddress(self, Insn_ea):
        self.instruction_addresses.append(ea)
    
    def AddNonTerminatingEgress(self,Target_ea):
        self.non_terminating_egress.append(Target_ea)
    
    def FillOutBlock(self):
        end_insn = ida_ua.insn_t()
        ida_ua.decode_insn(end_insn, self.end_ea)

        curr_insn_ea = self.start_ea
        while curr_insn_ea != self.end_ea + end_insn.size:
            #
            #   Walk and add each address to the list of instruction addresses
            #
            curr_insn = ida_ua.insn_t()
            ida_ua.decode_insn(curr_insn, curr_insn_ea)
            self.instruction_addresses.append(curr_insn_ea)
            curr_insn_ea = curr_insn_ea + curr_insn.size
            

class FunctionEpilogue(object):
    '''
        @brief  Describes a funciton epilogue
    '''    

    def __init__(self, BasicBlock, StackSpaceImmediate, Registers):

        self.basic_block = BasicBlock
        self.stack_space_immediate = StackSpaceImmediate
        self.registers = Registers

class FunctionPrologue(object):
    '''
        @brief  Describes a funciton epilogue
    '''    

    def __init__(self, BasicBlock, StackSpaceImmediate, Registers):

        self.basic_block = BasicBlock
        self.stack_space_immediate = StackSpaceImmediate
        self.registers = Registers

        self.connected_epilogues = []
