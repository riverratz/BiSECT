import argparse
import sys
import os
import pandas as pd
import re
from ast import literal_eval
from datetime import datetime

today = str(datetime.now().date())

print('\n\n\n' +
    '+-+-+-+-+-+-+-+-+-+-+-+-+-+-+' + '\n' +
    '+-+-+-+-+-+-+-+-+-+-+-+-+-+-+' + '\n' +
    '+-+      B|i|S|E|C|T      +-+' + '\n' +
    '+-+-+-+-+-+-+-+-+-+-+-+-+-+-+' + '\n' +
    '+-+-+-+-+-+-+-+-+-+-+-+-+-+-+' + '\n'
    )

def arg_parser():
    parser = argparse.ArgumentParser(description='BiSECT: Binary Semantic, Extraction, Cleaning, and Transformation')

    parser.add_argument('featureFile',
                        help='Path to the feature file.')

    parser.add_argument('-m', '--missingValues',
                        type=int,
                        choices=[0, 1, 2],
                        help='handle missing values, 0: drop, 1: fill, 2: ignore')
    parser.add_argument('-s', '--smooth',
                        nargs='+',
                        choices=['cc', 'ent', 'fs'],
                        help='smooth to reduce noise, cc: cyclomatic complexity, ent: entropy, fs: file size')
    parser.add_argument('-a', '--aggregate',
                        action='store_true',
                        help='aggregate the min, max, and mean complexities for each file_name')
    parser.add_argument('-n', '--normalize',
                        nargs='+',
                        choices=['cc', 'ent', 'fs'],
                        help='normalize (scale) features to fit within a standardized or smaller range, cc: cyclomatic complexity, ent: entropy, fs: file size')
    parser.add_argument('-f', '--fuzzyInstructions',
                        action='store_true',
                        help='generate the fuzzy instruction sequence for each function in every sample')

    return parser

def get_data(path):
    df = pd.read_csv(path, header=None)
    df.columns = ['file_name', 'function_name', 'cc', 'instructions']
    return df

def missing_vals(flag, df):
    if flag == 0:
        print("\nDropping missing values.")
        return df.dropna()
    elif flag == 1:
        print("\nFilling missing values with 0.")
        return df.fillna(0)
    elif flag == 2:
        print("\nIgnoring missing values.")
        return df
    else:
        print('\nOops! Valid options are 0, 1, or 2')
        return df

    return

def smooth(col, df):
    print('\nSmoothing: ' + col + ' (default to keep data between the 5-95th quantiles)')

    Q1 = df[col].quantile(0.05) # change the lower bound as desired
    Q3 = df[col].quantile(0.95) # change the upper bound as desired
    IQR = Q3 - Q1 # only keep data between the 5-95th quantiles
    df[col] = df[~((df[col] < (Q1 - 1.5 * IQR)) |(df[col] > (Q3 + 1.5 * IQR))).any(axis=1)]
    print('\tSmoothing complete')
    return df[col]

def normalize(col, df):
    print('\nNormalizing col: ' + col)
    df[col] = (df[col] - df[col].min()) / (df[col].max() - df[col].min())
    print('\tNormalization complete')
    return df[col]

def aggregation(df):
    print('\nAggregating cyclomatic complexity data... ')
    df_mean = df.groupby('file_name', as_index=False)['cc'].mean()
    df_mean.columns = ['file_name', 'cc_mean']
    df_min = df.groupby('file_name', as_index=False)['cc'].min()
    df_min.columns = ['file_name', 'cc_min']
    df_max = df.groupby('file_name', as_index=False)['cc'].max()
    df_max.columns = ['file_name', 'cc_max']
    result = pd.merge(df_mean, df_min, on='file_name')
    df = pd.merge(result, df_max, on='file_name')
    print('\tAggregation complete')

    return df

def clean_fuzzy(df):
    print('\nCreating Fuzzy Instruction Sequences... ')

    df.instructions = df.instructions.apply(literal_eval)
    df['fuzzy_instr'] = df['instructions'].apply(lambda x: " ".join(x)) #convert to space separated string
    df['fuzzy_instr'] = df['fuzzy_instr'].apply(lambda x: x.lower()) #make lower
    df['fuzzy_instr'] = df['fuzzy_instr'].apply(lambda x: re.sub(',', ' ', x)) # replace commas with spaces
    words = ['qword', 'dword', 'genreplacement', 'word', 'ptr', 'dptr', 'byte', '[', ']', '-', '.', 'ds: ', 'es: ', '+', '-', '*']
    big_regex = re.compile('|'.join(map(re.escape, words)))
    df['fuzzy_instr'] = df['fuzzy_instr'].apply(lambda x: big_regex.sub('', x)) # remove stop words
    df['fuzzy_instr'] = df['fuzzy_instr'].apply(lambda x: re.sub(r'0x[a-zA-Z0-9]{6,}', 'addr', x)) # replace hex addr with addr
    df['fuzzy_instr'] = df['fuzzy_instr'].apply(lambda x: re.sub(r'0x[a-zA-Z0-9]{1,}', 'num', x)) # replace hex nums with num
    df['fuzzy_instr'] = df['fuzzy_instr'].apply(lambda x: re.sub('[^a-zA-Z ]', ' ', x)) # replace non alphanumerics with space
    df['fuzzy_instr'] = df['fuzzy_instr'].apply(lambda x: ' '.join(x.split())) # delete empty whitespace
    print('\tFuzzy Instructions complete')

    return df

def main():
    parser = arg_parser()
    args = parser.parse_args(sys.argv[1:])

    try:
        file = str(args.featureFile)
        print('\n\nUsing the following feature file: ' + file + '\n')
        df = get_data(file)
        print(df.head())
    except:
        print("\nError reading file")

    if args.missingValues is not None:
        try:
            df = missing_vals(args.missingValues, df)
        except:
            pass

    if args.smooth is not None:
        try:
            for x in args.smooth:
                df[col] = smooth(x, df)
        except:
            pass

    if args.aggregate:
        try:
            df_aggregation = aggregation(df)
            name = 'aggregated_cc_' + today + '.csv'
            print('\tSaving aggregated cyclomatic complexity data to: ' + name)
            df_aggregation.to_csv(name)
        except:
            pass

    if args.normalize is not None:
        try:
            for x in args.normalize:
                df[col] = normalize(x, df)
        except:
            pass

    if args.fuzzyInstructions:
        try:
            df = clean_fuzzy(df)
            print(df.head())
            print('\n')
        except:
            pass

    original = str(args.featureFile).split('/')[-1].split('.csv')[0]
    final = original+'_bisected_' + today + '.csv'
    df.to_csv(final)
    print('Your original feature data has been BiSECTed. \nCheck out: ' + final + ' for the results!\n\n')

if __name__ == "__main__":
    main()
