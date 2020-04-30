import ida_ua, idc, idaapi

idaapi.require("maze_deobf_utils")

"""
    This file and the "maze_funtion_analysis.py" containd uplicate method and class names. 
     The "maze_funtion_analysis.py" is going to be the updated version of this file. 

"""

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


    def DoDescentParser(self,Prologue):
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
            

            while curr_insn_ea not in Prologue.possible_epilogues:
                #
                # walk only to a known epilogue
                #
                
                #print "Current EA: %08x" % (curr_insn_ea)
                
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

            if curr_insn_ea in Prologue.possible_epilogues:
                Prologue.connected_epilogues.append(curr_insn_ea)
                continue     

    
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
        self.possible_epilogues = []
