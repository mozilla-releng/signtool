import mock
import os
import pytest
import subprocess

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


def test_find_files2(tmpdir):
    tmp = tmpdir.strpath
    orig_dir = os.getcwd()
    tarball = os.path.abspath(os.path.join(os.path.dirname(__file__), "data", "dirtree.tgz"))
    try:
        os.chdir(tmp)
        subprocess.check_call(["tar", "xf", tarball])
        files = paths.findfiles(['dir1', 'dir2', 'no_dir'], includes=('*.*', ), excludes=('*.tar.*', ))
        assert sorted(files) == sorted([
            "no_dir",
            os.path.join("dir1", "file1.exe"),
            os.path.join("dir1", "dir1_a", "dir1_a_1", "file1_a_1.dmg"),
            os.path.join("dir1", "dir1_a", "dir1_a_1", "file1_a_1.jpg"),
        ])
    finally:
        os.chdir(orig_dir)


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
