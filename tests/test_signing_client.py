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
def test_overwrite_existing_file():
    test_string = "blahdeblah!"
    _, t1 = tempfile.mkstemp()
    _, t2 = tempfile.mkstemp()
    assert(os.path.exists(t1))
    assert(os.path.exists(t2))
    with open(t1, "w") as fh:
        print(test_string, file=fh)
    sclient.overwrite_file(t1, t2)
    with open(t2, "r") as fh:
        assert fh.read().rstrip() == test_string


def test_overwrite_nonexistent_file():
    test_string = "blahdeblah!"
    _, t1 = tempfile.mkstemp()
    _, t2 = tempfile.mkstemp()
    os.remove(t2)
    assert(os.path.exists(t1))
    assert(not os.path.exists(t2))
    with open(t1, "w") as fh:
        print(test_string, file=fh)
    sclient.overwrite_file(t1, t2)
    with open(t2, "r") as fh:
        assert fh.read().rstrip() == test_string
