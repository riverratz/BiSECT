import pandas as pd
from pandas import DataFrame
import subprocess
import glob
import math
from datetime import date

today = str(date.today())

def sys_strings(file):
    '''
    Use subprocess to get strings
    '''
    strings = []
    p = subprocess.Popen(["strings", str(file)], stdout=subprocess.PIPE)
    out = p.stdout.readlines()
    out = [word[:-1] for word in out]
    out = set(out)
    strings.append(out)

    return strings

def files():
    '''
    Glob for all the files (aka "samples")
    '''

    file_list = []
    base_dir = '~/cb-multios-master_executables/' #path to test cases

    for file in glob.glob(base_dir, recursive=False):
        strings = sys_strings(file)
        file_list.append([file, strings])
    return file_list

file_list = files()

features_df = DataFrame(file_list, columns=["test_case_name", 'strings'])
features_df.to_csv('BiSECT_Strings.csv')
