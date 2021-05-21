'''
script:
    fcnlevelextractions_ghidra.py
Description:
    This script was developed as part of the BiFECT framework.
    It was designed to be used with Ghidra Headless, and can be used to
    extract the following function-level features from a binary:
        0. path to binary
        1. non-stub function names,
        2. per [non-stub] function cyclomatic complexity,
        3. per [non-stub] function instruction sequence
Output:
    .csv file, 'ghidra_function_level_' + DateTime + '.csv'
Generic Ghidra headless command:
    your/path/to/GHIDRA/support/analyzeHeadless
    projectlocation/feature_extraction TestProject
    -import path/to/executables/cb-multios-master_executables/
    -analysisTimeoutPerFile num_seconds
    -deleteProject
    -scriptPath path/to/scripts/code
    -postScript path/to/this/script/fcnlevelextractions_ghidra.py
    -scriptlog path/to/log/my_log.log
'''

from ghidra.program.util import CyclomaticComplexity
import csv
from datetime import datetime

now = str(datetime.today().isoformat())
no_subs_list_func_cc = list()
total_instructions = list()

def extract_function_data():
    name = currentProgram.getName()
    listing = currentProgram.getListing()
    func_manager = currentProgram.getFunctionManager()
    no_subs = func_manager.getFunctionsNoStubs(True)

    cc = CyclomaticComplexity() # create instance of CyclomaticComplexity

    for fun in no_subs:
        complexity = cc.calculateCyclomaticComplexity(fun, monitor) # get the cyclomatic complexity for each true (not stub) fcn in program
        fun_addresses = fun.getBody() # get addr range for fcn
        code_units = listing.getCodeUnits(fun_addresses, True) # get code units in fcn
        fun_inst = [code_unit.toString() for code_unit in code_units] # get instr within this function
        no_subs_list_func_cc.append([name, fun.getName(), complexity, fun_inst]) # add to list
    return

extract_function_data()

fcn_level = 'ghidra_function_level_' + now + '.csv'
with open(fcn_level, 'a') as f:
    writer = csv.writer(f)
    writer.writerows(no_subs_list_func_cc)
