from __future__ import print_function
from contextlib import contextmanager
import mock
import optparse
import os
import pytest
import shutil
import signtool.signing.client as sclient
import tempfile
import time

CACHE = ("cached", "5dc0f60874af2d0cb171f07df7ee02cdc8352ce3")


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
            print(test_string, file=fh, end='')
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


# check_cached_fn {{{1
@contextmanager
def cache_dir():
    tmpdir = tempfile.mkdtemp()
    with open(os.path.join(tmpdir, "src"), "w") as fh:
        print(CACHE[0], file=fh, end="\n")
    yield tmpdir
    shutil.rmtree(tmpdir)


def test_cached_fn_noop():
    result = sclient.check_cached_fn(
        optparse.Values(), "nonexistent_path", "hash", "filename", "src"
    )
    assert result is None


def test_cached_fn_no_nss():
    options = optparse.Values()
    options.nsscmd = None
    with cache_dir() as tmpdir:
        target = os.path.join(tmpdir, "foo.exe")
        result = sclient.check_cached_fn(
            options, os.path.join(tmpdir, "src"), CACHE[1], target, target
        )
        assert result is True
        assert not os.path.exists(os.path.join(tmpdir, "foo.chk"))
        with open(target, "r") as fh:
            assert fh.read().rstrip() == CACHE[0]


def test_cached_fn_nss():
    options = optparse.Values()
    options.nsscmd = "echo"
    with cache_dir() as tmpdir:
        target = os.path.join(tmpdir, "foo.exe")
        chkfile = os.path.join(tmpdir, "foo.chk")
        # create chkfile to force nss signature
        with open(chkfile, "w") as fh:
            print("blah", file=fh)
        with mock.patch('signtool.signing.client.check_call') as m:
            result = sclient.check_cached_fn(
                options, os.path.join(tmpdir, "src"), "badsha", target, target
            )
            assert result is True
            m.assert_called_once_with('echo "%s"' % target, shell=True)
        with open(target, "r") as fh:
            assert fh.read().rstrip() == CACHE[0]


# remote_signfile {{{1
@pytest.mark.parametrize('cachedir,fmt,dest', ((
    'cachedir', 'gpg', 'dest',
), (
    None, 'widevine', None,
)))
def test_remote_signfile_noop(mocker, cachedir, fmt, dest):

    def noop(*args, **kwargs):
        pass

    def fake_iter(*args):
        return ['a', 'b']

    fake_r = mock.MagicMock()
    fake_r.iter_content = fake_iter
    fake_r.headers = {
        'X-Nonce': None,
        'X-Sha1-Digest': 'foo',
    }

    def fake_get(*args):
        return fake_r

    def fake_hash(*args):
        return 'hash'

    options = optparse.Values()
    options.cachedir = cachedir
    options.cert = 'cert'

    mocker.patch.object(sclient, 'sha1sum', new=fake_hash)
    mocker.patch.object(sclient, 'check_cached_fn', new=noop)
    mocker.patch.object(sclient, 'getfile', new=fake_get)
    mocker.patch.object(sclient, 'check_call', new=noop)
    mocker.patch.object(sclient, 'uploadfile', new=fake_get)
    mocker.patch.object(time, 'sleep', new=noop)
    with cache_dir() as tmpdir:
        options.noncefile = os.path.join(tmpdir, "nonce")
        sclient.remote_signfile(
            options, ['a', 'b'], os.path.join(tmpdir, 'foo'), fmt, 'token',
            dest=dest
        )


# uploadfile {{{1
def test_uploadfile():
    m = mock.MagicMock()
    with cache_dir() as tmpdir:
        tmpfile = os.path.join(tmpdir, "src")
        sclient.uploadfile("baseurl", tmpfile, "format", "token", "nonce", "cert", method=m)
        assert len(m.call_args_list) == 1
        args, kwargs = m.call_args
        assert args == ("baseurl/sign/format", )
        assert kwargs['files']['filedata'].read() == b'cached\n'
        assert list(kwargs['files'].keys()) == ['filedata', ]
        del(kwargs['files'])
        assert kwargs == {
            'data': {
                'sha1': CACHE[1],
                'filename': "src",
                'token': 'token',
                'nonce': 'nonce',
            },
            'verify': 'cert',
        }
