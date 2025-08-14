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
