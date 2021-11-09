# BiSECT

The BiSECT (Binary Synthesized, Extraction, Cleaning, and Transformation) framework provides a user-friendly and synthesized means to extract common features from compiled binary files and transform them into a format compatible with data mining and machine learning techniques. We designed BiSECT to support vulnerability research, but we encourage users to extend and use BiSECT in any way that's useful to them.

## Prerequisites:
- Python
- [Ghidra](https://ghidra-sre.org/) (tested on Ghidra 9.1.2)
- [Jupyter](https://jupyter.org/)

## Details:
This repository contains everything you need to get started with BiSECT. BiSECT currently includes the following feature extractions:

| Feature       | Granularity  | Source
| ------------- |:-------------|:-------------|
| path to binary            | file            | Ghidra + Python|
| total function count      | file            | Ghidra + Python|
| external functions        | file            | Ghidra + Python|
| internal functions        | file            | Ghidra + Python|
| instructions              | file & function | Ghidra + Python|
| fuzzy_instructions        | file & function | Python         |
| entropy                   | file            | Python         |
| ASCII strings             | file            | Python         |
| opcodes                   | file            | Ghidra + Python|
| opcode frequency          | file            | Python         |
| non-stub function names   | function        | Ghidra + Python|
| cyclomatic complexity (cc)| function        | Ghidra + Python|
| min cc                    | file            | Python         |
| max cc                    | file            | Python         |
| mean cc                   | file            | Python         |
| function prototype        | function        | Python         |

### How it works...

We recommend checking out `BiSECT_main.ipny` in the `bisect/` directory of this repo. However, here are a few tips to get you started:

#### Extracting function and file information using Ghidra headless
You can run any of the `*_ghidra.py` scripts in the `feature_extractions` directory of this repo via Ghidra headless like so,

```
/home/user/.local/java_applications/ghidra_9.1.2_PUBLIC/support/analyzeHeadless /home/user/Desktop/ TestProject -import /home/user/Desktop/bath_to_binaries/ -deleteProject -analysisTimeoutPerFile 100 -scriptPath /home/user/Desktop/ -postScript /home/user/Desktop/sample_functions_cpy.py -scriptlog /home/user/Desktop/log.log
```

Note: path information should be modified as appropriate.


#### Extracting function and file information using raw Python
You can also run any of the `*_python.py` scripts in the `feature_extractions` directory of this repo via the command line like so,

```
./script_extraction_python.py path/to/binaries
```

Where `path/to/binaries` is the path to the directory where your samples are.

Let's walk through a quick example.

### Example: Functions, Cyclomatic Complexity, \& Fuzzy Instruction Sequences
In this example we'll use Ghidra headless to extract the cyclomatic complexity and instruction sequences for all of the non-stub functions in the CB-Multios corpus. Then, we'll demonstrate some core BiSECT cleaning and transformation steps, such as `smoothing`, `normalization`, `aggregation` and the transformation of `fuzzy_instructions`.

#### Step 1. Feature Extraction
To extract the initial features we'll run Ghidra headless with the `fcnlevelextractions_ghidra.py` script (found in the BiSECT `feature_extractions` directory). Our Ghidra headless command looks like this:

```
/Desktop/ghidra_9.0.2/support/analyzeHeadless /Desktop/BiSECT-main/datasets/cb_multios_binaries_originalvpatched/features_original TestProject -import /Desktop/BiSECT-main/datasets/cb_multios_binaries_originalvpatched/cbmultios_original/ -analysisTimeoutPerFile 60 -deleteProject -scriptPath /Desktop/BiSECT-main/feature_extractions/ -postScript /Desktop/BiSECT-main/feature_extractions/fcnlevelextractions_ghidra.py -scriptlog extraction_log.log
```

time python bisect_main.py ~/Desktop/BiSECT-main/feature_extractions/ghidra_function_level_2021-07-12.csv -m 0 -s cc -a -n cc -f

#### Step 2. Cleaning and Transformation
To use the cleaning and transformations provided by `BiSECT` you have two options:
1. `BiSECT` command line (`bisect_main.py`)
2. `BiSECT` Jupyter (`bisect_main.ipny`)

##### Option 1. BiSECT Command Line
To run `BiSECT` via the command line simply point `BiSECT_main.py` to the file you want to bisect (e.g., the feature file created in Step 1). Something like this should do the trick:

`./bisect_main.py myfeaturefile.csv -m 0 -s cc -a -n cc -f`

Using this command we told `BiSECT` to:
1. use `myfeaturefile.csv`,
2. drop all missing values (`-m 0`),
3. smooth the cyclomatic complexity to reduce noise (`-s cc`),
4. aggregate the min, max, and mean complexities for every sample (`-a`). Aggregation creates a new file, called `aggregated_cc_today.csv`, where `today` is the current date.
5. Normalize the cyclomatic complexity to fit between 0 and 1 (`-n cc`),
6. and finally generate the Fuzzy Instruction sequence for every function in every sample (`-f`).

Ultimately, and regardless of the flags you select, `BiSECT` will create a new file, `myfeaturefile_bisected_today.csv`, where `myfeaturefile` is the name of the original file you told `BiSECT` to use, and `today` is the current date.

When in doubt you can always check out `bisect_main.py -h` to see a list of available command line arguments.

![BiSECT Command Line](linkredacted) #link redacted

##### Option 2. BiSECT Jupyter
If you're at odds with the command line or perhaps simply prefer a more interactive experience, you can access all of the features offered by `BiSECT` via our Jupyter notebook, `BiSECT_main.ipny`.

![BiSECT Jupyter](https://github.com/Kayla0x41/BiSECT/blob/149066c8ec029f026f0233fcc056cc8ba7cae2db/resources/gifs/bisect_jupyter.gif)


#### Step 3. Learn!
After extracting, cleaning, and transforming features, the next step is to use the built in representation models or another popular model like `doc2vec` or `fastText`. In any case, the goal is to use `BiSECT` features to learn something about your data.

**Coming Soon** As an example, check out the `xxx.ipny` notebook based on our [paper](link) **Coming Soon** 

## Author Information
-- redacted -- 
