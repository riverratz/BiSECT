'''
script:
    fcnlevelextractions_ghidra.py
Description:
    Part of BiFECT. To be used with Ghidra Headless.
    Extracts the cyclomatic complexity, and instruction sequence for each function in a binary.
Output:
    .csv file, 'ghidra_function_level_' + DateTime + '.csv'
Generic Ghidra headless command:
    yourpathto/GHIDRA/support/analyzeHeadless
    projectlocation/feature_extraction TestProject
    -import pathtooneormoreexecutables/cb-multios-master_executables/
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
