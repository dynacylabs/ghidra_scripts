# Installing [`PyGhidra`](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/PyGhidra/src/main/py/README.md)

Download and install the [Ghidra Version](https://github.com/NationalSecurityAgency/ghidra/releases) you prefer as you normally would.

If you had previously installed this version of Ghidra before, it is recommended to backup and then clear the configuration before continuing.

```sh
mv $HOME/.config/ghidra/$GHIDRA_VERSION $HOME/.config/ghidra/$GHIDRA_VERSION.old
```

This step will install `PyGhidra` and will launch Ghidra in `PyGhidra` mode. This is also how you should launch Ghidra.

```sh
$GHIDRA_HOME/support/pyghidrarun
```

# `ai_auto_comment.py`
## Resources
[**NG-Cloud-for-AI**](https://github.northgrum.com/NG-Cloud-for-AI/AI-Integrations)

## Install
This step will install some `python` dependencies `ai_auto_comment.py` needs to run.

```sh
source $HOME/.config/ghidra/$GHIDRA_VERSION/venv/bin/activate
pip install -r ai_auto_comment_requirements.txt
deactivate
```

## Issues
### PLN DNS
**Issue:** `aiml-aoai-api.gc1.myngc.com` becomes unresolvable shortly after reboot.

**Solution:** Add an entry to `/etc/hosts`:
```
10.14.228.68	aiml-aoai-api.gc1.myngc.com  # This is more of a hack than a fix
```

## Limitations
1. This likely will fail on large functions. This could be due to several reasons:
  - Token limit on the AI
  - Decompiled function is too complex
  - Decompilation of the function takes longer than 30 seconds

## Observations
The script iterates over functions from smallest to largest, based on function size. Starting out, functions will not get very descriptive names due to:
- Functions being small
- Lack of descriptive function names

As the script proceeds, the function names will begin to be more descriptive as the decompilation will have more of the renamed functions in it. This will aid the AI in determining the functionality.

Further, as the script runs and begins to encounter larger functions, processing will become slower. This is due to:
- Decompilation of larger functions taking longer
- AI response time increases as there is more data to process