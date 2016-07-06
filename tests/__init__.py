from __future__ import print_function
from contextlib import contextmanager
import os
import shutil
import tempfile


@contextmanager
def signtool_env():
    orig_dir = os.getcwd()
    try:
        tmpdir = tempfile.mkdtemp()
        os.chdir(tmpdir)
        for f in ("cert", "token"):
            with open(f, "w") as fh:
                print(f, file=fh)
        yield
    finally:
        os.chdir(orig_dir)
        shutil.rmtree(tmpdir)
