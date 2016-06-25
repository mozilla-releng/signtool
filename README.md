This repository contains the tool `signtool` used by Mozilla Release Engineering.
The original copy of signtool is [here](https://github.com/mozilla/build-tools/blob/master/release/signing/signtool.py)

This was intended to be a py3 port, but for some reason poster is still busted.  Something tells me this needs a bigger overhaul.

To run tests:
```
pip install tox
tox
```
