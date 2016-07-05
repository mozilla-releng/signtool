from __future__ import print_function
import mock
import os
import signtool.signing.client as sclient
import tempfile


# getfile {{{1
def test_getfile():
    m = mock.MagicMock()
    sclient.getfile("baseurl", "filehash", "format", "cert", method=m)
    m.assert_called_once_with("baseurl/sign/format/filehash", verify="cert")


# overwrite_file {{{1
def overwrite_file_helper(empty=True):
    test_string = "blahdeblah!"
    try:
        _, t1 = tempfile.mkstemp()
        _, t2 = tempfile.mkstemp()
        assert(os.path.exists(t1))
        if empty:
            os.remove(t2)
            assert(not os.path.exists(t2))
        else:
            assert(os.path.exists(t2))
        with open(t1, "w") as fh:
            print(test_string, file=fh)
        sclient.overwrite_file(t1, t2)
        with open(t2, "r") as fh:
            assert fh.read().rstrip() == test_string
    finally:
        for f in t1, t2:
            try:
                os.remove(f)
            except OSError:
                pass


def test_overwrite_nonexistent_file():
    overwrite_file_helper(empty=True)


def test_overwrite_existing_file():
    overwrite_file_helper(empty=False)
