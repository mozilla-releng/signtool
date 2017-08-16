import os
import pytest
import subprocess

import signtool.util.archives as archives

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
TARBALL = os.path.join(DATA_DIR, "dirtree.tgz")


# noumask
def test_noumask():
    orig_umask = os.umask(2)
    try:
        archives._noumask()
        assert os.umask(2) == 0
    finally:
        os.umask(orig_umask)


# bzip2 {{{1
def test_bzip2(tmpdir):
    fn = "%s/foo" % tmpdir
    open(fn, "w").write("hello")
    archives.bzip2(fn)
    proc = subprocess.Popen(["bzcat", fn], stdout=subprocess.PIPE)
    assert b"hello" == proc.stdout.read()

    archives.bunzip2(fn)
    assert b"hello" == open(fn, 'rb').read()


# tar {{{1
def test_tar(tmpdir):
    tmpdir_path = str(tmpdir)
    assert not os.path.exists(os.path.join(tmpdir_path, "dir2", "foobar"))
    with pytest.raises(Exception):
        archives.unpacktar(__file__, tmpdir_path)
    archives.unpacktar(TARBALL, tmpdir_path)
    assert os.path.exists(os.path.join(tmpdir_path, "dir2", "foobar"))
    new_tarball = os.path.join(tmpdir_path, "x.tgz")
    archives.packtar(new_tarball, ["dir1_a/file1_a.tar.gz"], os.path.join(tmpdir_path, "dir1"))
    proc = subprocess.Popen(["tar", '-tzf', new_tarball], stdout=subprocess.PIPE)
    assert b"dir1_a/file1_a.tar.gz" == proc.stdout.read().rstrip()


# unpackfile {{{1
@pytest.mark.parametrize('path,raises,expected', ((
    TARBALL, False, 'dir2/foobar'
), (
    __file__, ValueError, None
), (
    "foo.exe", False, None
), (
    "foo.mar", False, None
)))
def test_unpackfile(tmpdir, path, raises, expected, mocker):
    tmpdir_path = str(tmpdir)
    mocker.patch.object(archives, "unpackmar")
    mocker.patch.object(archives, "unpackexe")
    if raises:
        with pytest.raises(raises):
            archives.unpackfile(path, tmpdir_path)
    else:
        archives.unpackfile(path, tmpdir_path)
        if expected is not None:
            assert os.path.exists(os.path.join(tmpdir_path, expected))
