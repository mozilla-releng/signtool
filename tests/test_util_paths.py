import mock
import os
import pytest

import signtool.util.paths as paths

# params {{{1
CONVERT_PARAMS = [(
    os.path.join('unsigned-build1', 'unsigned', 'update', 'win32', 'foo', 'bar'),
    os.path.join('signed-build1', 'update', 'win32', 'foo', 'bar'),
), (
    os.path.join('unsigned-build1', 'unsigned', 'win32', 'foo', 'bar'),
    os.path.join('signed-build1', 'win32', 'foo', 'bar'),
), (
    os.path.join('unsigned-build1', 'win32', 'foo', 'bar'),
    os.path.join('signed-build1', 'win32', 'foo', 'bar'),
)]

CYGPATH_PARAMS = (
    ("cygwin", "cygwin"),
    ("not-cygwin", "filename"),
)


# tests {{{1
def test_find_files(tmpdir):
    tmp = tmpdir.strpath
    os.makedirs(os.path.join(tmp, "d1"))
    with open(os.path.join(tmp, "foo"), 'w') as fh:
        fh.write("hello")
    with open(os.path.join(tmp, "d1", "bar"), 'w') as fh:
        fh.write("world")
    assert paths.findfiles(tmp) == [os.path.join(tmp, "foo"), os.path.join(tmp, "d1", "bar")]
    assert paths.finddirs(tmp) == [os.path.join(tmp, "d1")]


@pytest.mark.parametrize("path_tuple", CONVERT_PARAMS)
def test_convert_path(path_tuple):
    assert paths.convertPath(path_tuple[0], 'signed-build1') == path_tuple[1]


@pytest.mark.parametrize("args", CYGPATH_PARAMS)
def test_cygpath(args, mocker):
    m = mock.MagicMock()
    m.communicate.return_value = [args[0]]

    with mock.patch('sys.platform', new=args[0]):
        with mock.patch.object(paths, 'Popen', new=lambda *args, **kwargs: m):
            assert paths.cygpath("filename") == args[1]
