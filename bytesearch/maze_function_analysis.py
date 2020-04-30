import ida_ua, idc, idaapi, ida_funcs

idaapi.require("maze_deobf_utils")
#import maze_deobf_utils as mdu

class RecursiveDescent(object):
    '''
        @brief Recurse descent disassembly for a single function (no calls followed)
    '''

    def __init__(self, Start_ea, Approach):
        
        self.deferred_targets = []
        self.instructions_walked = []
        self.wrong_functions = []

        self.entry_point = Start_ea
        self.deferred_targets.append(Start_ea)

        self.emulators = Eumulators()

        self.deobf_approach = Approach
    
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

    def DoDescentParser2(self):
        '''
            @brief Walk the function leveraging a recursive descent parser

            @detail Walks a function based on an Approach. This is unused in the byte-search implementation. 
        
                @return function object
        '''

        #
        #   jmps = [eval("idaapi."+name) for name in dir(idaapi) if "NN_j" in name]
        #
        jcc_terminators = ['jnz','jz','jo','jno', 'js','jns', 'je','jne', 'jb', 'jnae', 'jc', 'jnb', 'jae', 'jnc', 'jbe','jna', 'ja','jnbe', 'jl','jnge','jge','jnl','jle','jng','jg','jnle','jp','jpe','jnp','jpo','jcxz','jecxz']

        print "Starting recursive decent:, starting at: %08x" %    (self.deferred_targets[0])

        func_end_ea = []
        do_things = False

        while len(self.deferred_targets) > 0:

            curr_insn_ea = self.deferred_targets.pop()

            bblock = BasicBlock(curr_insn_ea)

            if curr_insn_ea in self.instructions_walked:
                #
                #   skip instructions that were already walked
                #
                
                continue

            print "Next BB: %08x" % curr_insn_ea
            
            while curr_insn_ea != idc.BADADDR:

                print "Current ip: %08x" % (curr_insn_ea)

                self.instructions_walked.append(curr_insn_ea)

                bblock.AddInsnAddress(curr_insn_ea)

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
                #   Get instruction disasembly
                #
                curr_insn_dism = idc.generate_disasm_line(curr_insn_ea,1)

                #
                #   Check Instruction matches Obfuscated Call
                #
                if curr_insn_dism.startswith("push") and do_things:

                    push_insn = curr_insn
                    if maze_deobf_utils.CheckValidTargettingInstr(push_insn, "push"):
                        #
                        #   Check for different CALL instruction types
                        #

                        #
                        #   Type One
                        #
                        ret_addr_ea = self.deobf_approach.CheckCallTypeOne(curr_insn_ea)
                        if ret_addr_ea != idc.BADADDR:
                            self.deferred_targets.append(ret_addr_ea)
                            bblock.end_ea = curr_insn_ea
                            break
                        
                        #
                        #   Type Two
                        #
                        ret_addr_ea = self.deobf_approach.CheckCallTypeTwo(curr_insn_ea)
                        if ret_addr_ea != idc.BADADDR:
                            self.deferred_targets.append(ret_addr_ea)
                            bblock.end_ea = curr_insn_ea
                            break
                        
                        #
                        #   Type Three
                        #
                        ret_addr_ea = self.deobf_approach.CheckCallTypeThree(curr_insn_ea)
                        if ret_addr_ea != idc.BADADDR:
                            self.deferred_targets.append(ret_addr_ea)
                            bblock.end_ea = curr_insn_ea
                            break
                
                    #
                    #   Check instruction matches an obfuscated Windows API Call
                    #
                    if maze_deobf_utils.CheckValidInstrImmediate(push_insn,"push"):
                        ret_addr_ea = self.deobf_approach.CheckObfuscatedWindowsAPICall(curr_insn_ea)
                        if ret_addr_ea != idc.BADADDR:
                            
                            print "Obfuscated Windows API Call: %08x, Target: %08x" % (curr_insn_ea, ret_addr_ea)

                            self.deferred_targets.append(ret_addr_ea)
                            bblock.end_ea = curr_insn_ea
                            break
                
                #
                #   Check Instruction matches Obfuscated Absolute Jumps
                #
                if curr_insn_dism.startswith("jz") and do_things:

                    jz_insn = curr_insn
                    if maze_deobf_utils.CheckValidTargettingInstr(jz_insn, "jz"):
                        
                        jz_target_ea = maze_deobf_utils.GetInstuctionTargetAddress(jz_insn)
                        
                        next_insn_ea = curr_insn_ea + jz_insn.size
                        next_insn = ida_ua.insn_t()
                        ida_ua.decode_insn(next_insn, next_insn_ea)
                        if maze_deobf_utils.CheckValidTargettingInstr(next_insn, "jnz"):
                            #
                            #   Instruction is an absolute jump
                            #    get absolute jump target address.
                            #

                            print "JZ/JNZ block: %08x" % curr_insn_ea
                            abs_jmp_target_ea = self.deobf_approach.GetObfuscJMPTarget(next_insn_ea)
                            if abs_jmp_target_ea != idc.BADADDR:
                                print "JNZ %08x Adding Target: %08x" % (next_insn_ea, abs_jmp_target_ea)
                                print "JZ %08x Adding Target: %08x" % (curr_insn_ea, jz_target_ea)

                                self.deferred_targets.append(jz_target_ea)
                                self.deferred_targets.append(abs_jmp_target_ea)
                                bblock.end_ea = curr_insn_ea
                                break
                                
                if curr_insn_dism.startswith( tuple( jcc_terminators ) ):
                    #
                    #   JCC conditionals
                    #
                    
                    jcc_insn = curr_insn
                    jmp_target_ea = self.GetInstuctionTargetAddress(jcc_insn)
                    if jmp_target_ea not in self.deferred_targets:
                        self.deferred_targets.append(jmp_target_ea)
                    
                    #
                    #   Add fall through address, BB ends at JCC conditional
                    #
                    self.deferred_targets.append(curr_insn_ea + jcc_insn.size)
                    bblock.end_ea = curr_insn_ea
                    break
                
                if maze_deobf_utils.CheckInstructionIsFunctionTerminator(curr_insn_ea):
                    #
                    #   Return instruction
                    #

                    bblock.end_ea = curr_insn_ea
                    bblock.is_epilogue = True
                    func_end_ea.append(idc.next_head(curr_insn_ea))
                    break

                if curr_insn_dism.startswith("jmp"):

                    jmp_insn = curr_insn
                    jmp_target_ea = maze_deobf_utils.GetInstuctionTargetAddress(jmp_insn)

                    if jmp_target_ea not in self.deferred_targets:
                        self.deferred_targets.append(jmp_target_ea)

                    bblock.end_ea = curr_insn_ea
                    break
                
                
                curr_insn_ea = curr_insn_ea + curr_insn.size
                
        return func_end_ea

    def DoDescentParser(self):
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

        #print "Starting recursive decent:, starting at: %08x" %    (self.deferred_targets[0])

        func_end_ea = []
        ea_part_of_another_func = []
        do_things = False

        curr_func = None

        while len(self.deferred_targets) > 0:
            
            curr_insn_ea = self.deferred_targets.pop()

            if not curr_func:
                curr_func = ida_funcs.get_func(curr_insn_ea)
                
            else:
                target_func = ida_funcs.get_func(curr_insn_ea)
                if target_func and (target_func.start_ea != curr_func.start_ea)  :
                    if (target_func.start_ea not in ea_part_of_another_func):
                        ea_part_of_another_func.append(target_func.start_ea)
            

            bblock = BasicBlock(curr_insn_ea)

            if curr_insn_ea in self.instructions_walked:
                #
                #   skip instructions that were already walked
                #
                
                continue

            #print "Next BB: %08x" % curr_insn_ea
            
            while curr_insn_ea != idc.BADADDR:

                #print "Current ip: %08x" % (curr_insn_ea)

                self.instructions_walked.append(curr_insn_ea)

                bblock.AddInsnAddress(curr_insn_ea)

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
                #   Get instruction disasembly
                #
                curr_insn_dism = idc.generate_disasm_line(curr_insn_ea,1)
                                
                if curr_insn_dism.startswith( tuple( jcc_terminators ) ):
                    #
                    #   JCC conditionals
                    #
                    
                    jcc_insn = curr_insn
                    jmp_target_ea = self.GetInstuctionTargetAddress(jcc_insn)
                    if jmp_target_ea not in self.deferred_targets:
                        self.deferred_targets.append(jmp_target_ea)
                    
                    #
                    #   Add fall through address, BB ends at JCC conditional
                    #
                    self.deferred_targets.append(curr_insn_ea + jcc_insn.size)
                    bblock.end_ea = curr_insn_ea
                    break
                
                if maze_deobf_utils.CheckInstructionIsFunctionTerminator(curr_insn_ea):
                    #
                    #   Return instruction
                    #

                    bblock.end_ea = curr_insn_ea
                    bblock.is_epilogue = True
                    func_end_ea.append(idc.next_head(curr_insn_ea))
                    break

                if curr_insn_dism.startswith("jmp"):

                    jmp_insn = curr_insn
                    jmp_target_ea = maze_deobf_utils.GetInstuctionTargetAddress(jmp_insn)

                    if jmp_target_ea not in self.deferred_targets:
                        self.deferred_targets.append(jmp_target_ea)

                    bblock.end_ea = curr_insn_ea
                    break
                
                
                curr_insn_ea = curr_insn_ea + curr_insn.size
                
        return [func_end_ea, ea_part_of_another_func]

    def DoDescentParser3(self):
        '''
            @brief Walk the function leveraging a recursive descent parser

            @detail Starting at the entry point, it walks a function, creates a basic block, and associates those blocks with a 
                     Function object. 
                    
                    much thanks to the author of "Practical Binary Analysis" for the break down of the algorithm in Chapter 8.
        
                @return function object
        '''

        #
        #   jmps = [eval("idaapi."+name) for name in dir(idaapi) if "NN_j" in name]
        #
        jcc_terminators = ['jnz','jz','jo','jno', 'js','jns', 'je','jne', 'jb', 'jnae', 'jc', 'jnb', 'jae', 'jnc', 'jbe','jna', 'ja','jnbe', 'jl','jnge','jge','jnl','jle','jng','jg','jnle','jp','jpe','jnp','jpo','jcxz','jecxz']

        #print "Starting recursive decent:, starting at: %08x" %    (self.deferred_targets[0])

        func_end_ea = []
        ea_part_of_another_func = []
        do_things = False

        func_start_ea = idc.BADADDR
        expected_func = Function()

        while len(self.deferred_targets) > 0:
            
            curr_insn_ea = self.deferred_targets.pop()

            if curr_insn_ea in self.instructions_walked:
                #
                #   skip instructions that were already walked
                #
                
                continue
            
            bblock = BasicBlock(curr_insn_ea)
            expected_func.AddBlock(bblock)

            if expected_func.start_ea == idc.BADADDR:
                #
                #   Set the function's expected start address
                #
                expected_func.start_ea = curr_insn_ea

            if bblock.incorrect_function_ea == idc.BADADDR:
                #
                #   Check if the BasicBlock is part of another function
                #

                if bblock.CheckPartOfAnotherFunction(curr_insn_ea, expected_func.start_ea):
                    expected_func.rogue_basic_blocks.append(bblock)
                


            #print "Next BB: %08x" % curr_insn_ea
            
            while curr_insn_ea != idc.BADADDR:
                #
                #   Walks the basic block
                #

                #print "Current ip: %08x" % (curr_insn_ea)

                self.instructions_walked.append(curr_insn_ea)

                bblock.AddInsnAddress(curr_insn_ea)

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
                #   Get instruction disasembly
                #
                curr_insn_dism = idc.generate_disasm_line(curr_insn_ea,1)
                                
                if curr_insn_dism.startswith( tuple( jcc_terminators ) ):
                    #
                    #   JCC conditionals
                    #
                    
                    jcc_insn = curr_insn
                    jmp_target_ea = self.GetInstuctionTargetAddress(jcc_insn)
                    if jmp_target_ea not in self.deferred_targets:
                        self.deferred_targets.append(jmp_target_ea)
                    
                    #
                    #   Add fall through address, BB ends at JCC conditional
                    #
                    self.deferred_targets.append(curr_insn_ea + jcc_insn.size)
                    bblock.end_ea = curr_insn_ea
                    break
                
                if maze_deobf_utils.CheckInstructionIsFunctionTerminator(curr_insn_ea):
                    #
                    #   Return instruction
                    #

                    bblock.end_ea = curr_insn_ea
                    bblock.is_epilogue = True
                    expected_func.end_ea = idc.next_head(curr_insn_ea)
                    expected_func.AddExitPoint(curr_insn_ea)
                    break

                if curr_insn_dism.startswith("jmp"):

                    jmp_insn = curr_insn
                    jmp_target_ea = maze_deobf_utils.GetInstuctionTargetAddress(jmp_insn)

                    if jmp_target_ea not in self.deferred_targets:
                        self.deferred_targets.append(jmp_target_ea)

                    bblock.end_ea = curr_insn_ea
                    break
                
                
                curr_insn_ea = curr_insn_ea + curr_insn.size
                
        return expected_func

class Function(object):
    '''
        @brief Representation of a function.
    '''
    def __init__(self):
        self.basic_blocks = []
        self.rogue_basic_blocks = []
        self.start_ea = idc.BADADDR
        self.end_ea = idc.BADADDR
        self.exit_points = set()
    
    def AddBlock(self, BB):
        if BB:
            self.basic_blocks.append(BB)
    
    def AddExitPoint(self, Curr_insn_ea):
        self.exit_points.add(Curr_insn_ea)

class Eumulators(object):
    '''
        @brief Identify and Deobfuscate the various obfuscations

                Currently unused.
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

        if maze_deobf_utils.CheckValidTargettingInstr(push_insn, "push"):
            """
                Valid PUSH instruction.
            """

            jz_insn_ea = push_instr_ea + push_insn.size()
            jz_insn = ida_ua.insn_t()
            ida_ua.decode_insn(jz_insn, jz_insn_ea)

            if maze_deobf_utils.CheckValidTargettingInstr(push_insn, "push"):
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
        
        self.incorrect_function_ea = idc.BADADDR
        
    
    def AddInsnAddress(self, Insn_ea):
        self.instruction_addresses.append(Insn_ea)
    
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
    
    def CheckPartOfAnotherFunction(self, Curr_insn_ea, Expected_func_start_ea):
        '''
            @brief Check if the start address of the function currently being walked
                    matches the start address of whatever function in which 
                    the current instruction exists.
        '''
        is_rouge = False

        testing_func = ida_funcs.get_func(Curr_insn_ea)
        if testing_func:
            if testing_func.start_ea != Expected_func_start_ea:
                self.incorrect_function_ea = testing_func.start_ea
                is_rouge = True
        
        return is_rouge
            

class FunctionEpilogue(object):
    '''
        @brief  Describes a function epilogue
    '''    

    def __init__(self, BasicBlock, StackSpaceImmediate, Registers):

        self.basic_block = BasicBlock
        self.stack_space_immediate = StackSpaceImmediate
        self.registers = Registers

class FunctionPrologue(object):
    '''
        @brief  Describes a function prologue
    '''    

    def __init__(self, BasicBlock, StackSpaceImmediate, Registers):

        self.basic_block = BasicBlock
        self.stack_space_immediate = StackSpaceImmediate
        self.registers = Registers

        #
        #   Connected epilogues have been verified via walking the function
        #
        self.connected_epilogues = []

        #
        #   Possible epilogues are address that are unverified addresses 
        #    that could be an epilogue for this function. 
        #
        self.possible_epilogues = []
