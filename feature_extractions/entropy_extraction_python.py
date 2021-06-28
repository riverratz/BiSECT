import pandas as pd
from pandas import DataFrame
import subprocess
import glob
import math
from datetime import date

today = str(date.today())

def calc_entropy(file):
    with open(file, 'rb') as f:
        byteArr = list(f.read())
    fileSize = len(byteArr)

    # calculate the frequency of each byte value in the file
    freqList = []
    for b in range(256):
        ctr = 0
        for byte in byteArr:
            if byte == b:
                ctr += 1
        freqList.append(float(ctr) / fileSize)

    # Shannon entropy
    ent = 0.0
    for freq in freqList:
        if freq > 0:
            ent = ent + freq * math.log(freq, 2)
    ent = -ent
    return fileSize, ent


def files():
    '''
    Glob for all the files (aka "samples")
    '''

    file_list = []

    base_dir = '~/cb-multios-master_executables/'

    for file in glob.glob(base_dir, recursive=False):
        file_bytes, entropy = calc_entropy(file)
        file_list.append([file, file_bytes, entropy])
    return file_list

file_list = files()

features_df = DataFrame(file_list, columns=["test_case_name", 'file_bytes', 'entropy'])
features_df.to_csv('BiSECT_BytesandEntropy.csv')
