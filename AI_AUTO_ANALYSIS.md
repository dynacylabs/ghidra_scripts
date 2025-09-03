# `ai_auto_analysis.py`
## Overview
The script currently supports the following functions:
1. Function Renaming: Automatically generates meaningful function names based on decompiled code analysis
2. Function Signature Generation: Creates proper C function signatures with parameter types and return types
3. Variable Renaming & Retyping: Provides meaningful variable names and proper data types within functions
4. Function Commenting: Generates detailed documentation comments for functions
5. Struct Generation: Automatically creates C structures based on memory access patterns in the decompiled code

## Setup
### Install
#### PyGhidra
This step will install PyGhidra. Ghidra must be run in PyGhidra mode for the script to work. You can use this command to launch Ghidra in PyGhidra mode in the future.
```sh
$GHIDRA_HOME/support/pyghidrarun
```

#### Requirements
This step will install some python dependencies `ai_auto_analysis.py` needs to run.
```sh
source $HOME/.config/ghidra/$GHIDRA_VERSION/venv/bin/activate
pip install -r ai_auto_analysis_requirements.txt
deactivate
```

### API Key
#### Obtain Your API Key
To obtain your API key, review the instructions [here](https://github.northgrum.com/NG-Cloud-for-AI/AI-Integrations). Once you have your API key, update this line in `ai_auto_analysis.py` with your API key:
```python
os.environ["AZURE_OPENAI_API_KEY"] = "<your-api-key>"
```

### PLN "hack"
For whatever reason the AI endpoint is not resolvable on the PLN but is accessible. To fix this, the following entry needs to be added to the `/etc/hosts` (or equivalent) file:
```txt
10.14.228.68    aiml-aoai-api.gc1.myngc.com
```
**Note**: This _could_ break in the future if the IP or hostname of the endpoint ever changes.
