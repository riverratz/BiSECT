# BiFECT

The BiFECT (Binary Feature Extraction, Cleaning, and Transformation) framework provides a user-friendly and repeatable means to extract common features from compiled binary files and transform them into a format compatible with data mining and machine learning techniques. We designed BiFECT to support vulnerability research, but we encourage users to extend and use BiFECT in any way that's useful to them.

## Prerequisites:
- Python
- [Ghidra](https://ghidra-sre.org/) (tested on Ghidra 9.1.2)
- [Jupyter](https://jupyter.org/)

## Details:
This repository contains everything you need to get started with BiFECT. BiFECT currently includes the following feature extractions:

| Feature       | Granularity  | Source
| ------------- |:-------------|:-------------|
| path to binary            | file            | Ghidra + Python|
| total function count      | file            | Ghidra + Python|
| external functions        | file            | Ghidra + Python|
| internal functions        | file            | Ghidra + Python|
| Instructions              | file & function | Ghidra + Python|
| fuzzy_instructions        | file & function | Python         |
| McCabe entropy            | file            | Python         |
| ASCII strings             | file            | Python         |
| opcodes                   | file            | Ghidra + Python|
| opcode frequency          | file            | Python         |
| non-stub function names   | function        | Ghidra + Python|
| cyclomatic complexity (cc)| function        | Ghidra + Python|
| min cc                    | file            | Python         |
| max cc                    | file            | Python         |
| avg cc                    | file            | Python         |
| function prototype        | function        | Python         |

### How it works...

#### Extracting function and file information using Ghidra headless
Users may run any of the `*_ghidra.py` scripts in the `feature_extractions` directory of this repo via Ghidra headless like so,

```
/home/user/.local/java_applications/ghidra_9.1.2_PUBLIC/support/analyzeHeadless /home/user/Desktop/ TestProject -import /home/user/Desktop/bath_to_binaries/ -deleteProject -analysisTimeoutPerFile 100 -scriptPath /home/user/Desktop/ -postScript /home/user/Desktop/sample_functions_cpy.py -scriptlog /home/user/Desktop/log.log
```

Note: path information should be modified as appropriate.


#### Extracting function and file information using raw Python
Users may run any of the `*_python.py` scripts in the `feature_extractions` directory of this repo via the command line like so,

```
./script_extraction_python.py path/to/binaries
```

Where `path/to/binaries` is the path to the directory where your samples are.

Let's walk through a quick example.

### Example 1: Cyclomatic Complexity \& Instruction Sequences
In this example we'll use Ghidra headless to extract the cyclomatic complexity and instruction sequences for all of the functions in a few sample binaries. Then, we'll demonstrate some core BiFECT cleaning and transformation steps, such as `smoothing` and the creation of `fuzzy_instructions`.

#### Step 1. Feature Extraction
To extract the cyclomatic complexity and instruction sequence features we'll run Ghidra headless with the `fcnlevelextractions_ghidra.py` script (found in the BiFECT `feature_extractions` directory). Our Ghidra headless command looks like this:

```
/home/user/.local/java_applications/ghidra_9.1.2_PUBLIC/support/analyzeHeadless /home/user/Desktop/ TestProject -import /home/user/Desktop/bath_to_binaries/ -deleteProject -analysisTimeoutPerFile 100 -scriptPath /home/user/Desktop/ -postScript /home/user/Desktop/sample_functions_cpy.py -scriptlog /home/user/Desktop/log.log
```

If you want to follow along with this example,

#### Step 2. Feature Cleaning
![Smoothing the cyclomatic complexity](https://github.com/Kayla0x41/BiFECT/blob/773eeef2e64a64da99b9ec1386f000d2e30e7885/resources/cc_gif.gif)

#### Step 3. Feature Tranformation


In the ```auto_bindiff.py``` script, this line,
```python
exporter.export(f, currentProgram, addr_set, monitor)
```

## Author Information
Kayla Afanador, knkeen@nps.edu
