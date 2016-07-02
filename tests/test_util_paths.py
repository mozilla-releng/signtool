import os
import pytest

from signtool.util.paths import findfiles, finddirs, convertPath

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


class TestPaths(object):
    def testFindFiles(self, tmpdir):
        tmp = tmpdir.strpath
        os.makedirs(os.path.join(tmp, "d1"))
        with open(os.path.join(tmp, "foo"), 'w') as fh:
            fh.write("hello")
        with open(os.path.join(tmp, "d1", "bar"), 'w') as fh:
            fh.write("world")

        assert findfiles(tmp) == [os.path.join(tmp, "foo"), os.path.join(tmp, "d1", "bar")]
        assert finddirs(tmp) == [os.path.join(tmp, "d1")]

    @pytest.mark.parametrize("path_tuple", CONVERT_PARAMS)
    def testConvertPath(self, path_tuple):
        assert convertPath(path_tuple[0], 'signed-build1') == path_tuple[1]
