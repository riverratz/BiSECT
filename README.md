# BiFECT

The BiFECT (Binary Feature Extraction, Cleaning, and Transformation) framework provides a user-friendly and repeatable means to extract common features from compiled binary files and transform them into a format compatible with data mining and machine learning techniques. We designed BiFECT to support vulnerability research, but we encourage users to extend and use BiFECT in any way that's useful to them.

## Prerequisites:
- Python
- Ghidra, found [here](https://ghidra-sre.org/) (tested on Ghidra 9.1.2)
- Jupyter, found [here](https://jupyter.org/)

## Details:
This repository contains everything you need to get started with BiFECT, and includes the following feature extractions: 

  1. file name
  2.  
  

### How it works...

#### Extracting function and file information using Ghidra headless
Users may run any of the `*_ghidra.py` scripts in the `code` directory of this repo via Ghidra Headless like so,

```python
/home/user/.local/java_applications/ghidra_9.1.2_PUBLIC/support/analyzeHeadless /home/user/Desktop/ TestProject -import /home/user/Desktop/bath_to_binaries/ -deleteProject -analysisTimeoutPerFile 100 -scriptPath /home/user/Desktop/ -postScript /home/user/Desktop/sample_functions_cpy.py -scriptlog /home/user/Desktop/log.log
```

Note: path information should be modified as appropriate.

#### Example 1: Function level Cyclomatic Complexity \& Instruction Sequences

![Smoothing the cyclomatic complexity](https://github.com/Kayla0x41/BiFECT/resources/cc_gif.mp4)

In the ```auto_bindiff.py``` script, this line,
```python
exporter.export(f, currentProgram, addr_set, monitor)
```

## Author Information
Kayla Afanador, knkeen@nps.edu
