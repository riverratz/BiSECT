'''
script:
    filelevelextractions_ghidra.py
Description:
    This script was developed as part of the BiFECT framework.
    It was designed to be used with Ghidra Headless, and can be used to
    extract the following file-level features from a binary:
        0. path to binary
        1. total function count
        2. list of external functions
        3. list of internal functions
        4. list of all instructions in sample
Output:
    .csv file, 'ghidra_file_level_' + DateTime + '.csv'
Generic Ghidra headless command:
    your/path/to/GHIDRA/support/analyzeHeadless
    projectlocation/feature_extraction TestProject
    -import path/to/executables/cb-multios-master_executables/
    -analysisTimeoutPerFile num_seconds
    -deleteProject
    -scriptPath path/to/scripts/code
    -postScript path/to/this/script/filelevelextractions_ghidra.py
    -scriptlog path/to/log/my_log.log
'''

import csv
from datetime import datetime

now = str(datetime.today().isoformat())

final_list = list()

def extract_file_data():
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

    final_list.append([path, function_count, external_fcns, internal_fcns, instructions])
    return

extract_file_data()

file_level = 'ghidra_file_level_' + now + '.csv'
with open(file_level, 'a') as f:
    writer = csv.writer(f)
    writer.writerows(final_list)
