'''
script:
    funANDfileextractions_ghidra.py
Description:
    This script was developed as part of the BiFECT framework.
    It was designed to be used with Ghidra Headless, and can be used to
    extract the following file-level features from a binary:
        0. path to binary
        1. total function count
        2. list of external functions
        3. list of internal functions
        4. list of all instructions in sample
    AND the following function-level features from a binary:
        5. non-stub function names,
        6. per [non-stub] function cyclomatic complexity,
        7. per [non-stub] function instruction sequence
        8. per [non-stub] function prototype

    For convenience, this script combines the features extracted with:
    'filelevelextractions_ghidra.py' and 'fcnlevelextractions_ghidra.py'
Output:
    .csv file, 'ghidra_fcnFile_level_' + DateTime + '.csv'
Generic Ghidra headless command:
    your/path/to/GHIDRA/support/analyzeHeadless
    projectlocation/feature_extraction TestProject
    -import path/to/executables/cb-multios-master_executables/
    -analysisTimeoutPerFile num_seconds
    -deleteProject
    -scriptPath path/to/scripts/code
    -postScript path/to/this/script/funANDfileextractions_ghidra.py
    -scriptlog path/to/log/my_log.log
'''

from ghidra.program.util import CyclomaticComplexity
import csv
from datetime import datetime

now = str(datetime.today().isoformat())

final_list = list()
no_subs_list_func_cc = list()

def extract_file_fcn_data():
    path = currentProgram.getExecutablePath()
    name = currentProgram.getName()
    listing = currentProgram.getListing()
    func_manager = currentProgram.getFunctionManager()
    no_subs = func_manager.getFunctionsNoStubs(True)

    function_count = func_manager.getFunctionCount()
    external_fcns = func_manager.getExternalFunctions()
    internal_fcns = func_manager.getFunctions(True)
    instructions_mgr = listing.getInstructions(True)

    external_fcns = [fun.getName() for fun in external_fcns] # a list of all external functions
    internal_fcns = [fun.getName() for fun in internal_fcns] # a list of all internal functions
    instructions = [str(ins).split()[0] for ins in instructions_mgr] # a list of instructions (for frequency and set comparison)

    cc = CyclomaticComplexity() # create instance of CyclomaticComplexity

    for fun in no_subs:
        complexity = cc.calculateCyclomaticComplexity(fun, monitor) # get the cyclomatic complexity for each true (to stub) fun in program
        prototype = fun.getSignature().getPrototypeString() # function prototype

        fun_addresses = fun.getBody() # get addr range for fcn
        code_units = listing.getCodeUnits(fun_addresses, True) # code units in fcn
        instr_in_fcn = listing.getInstructions(fun_addresses, True) # instr units in fcn
        fun_inst = [code_unit.toString() for code_unit in code_units] # get instr within this function
        mnemonics = [str(ins).split()[0] for ins in instr_in_fcn] # get instr within this function

        no_subs_list_func_cc.append([name, fun.getName(), complexity, prototype, fun_inst, mnemonics])

    final_list.append([path, function_count, external_fcns, internal_fcns, instructions, no_subs_list_func_cc])

    return

extract_file_fcn_data()

file_level = 'ghidra_file_level_' + now + '.csv'
with open(file_level, 'a') as f:
    writer = csv.writer(f)
    writer.writerows(final_list)

fcn_level = 'ghidra_function_level_' + now + '.csv'
with open(fcn_level, 'a') as f:
    writer = csv.writer(f)
    writer.writerows(no_subs_list_func_cc)
