from __future__ import print_function
from contextlib import contextmanager
import logging
import mock
import optparse
import os
import pytest
import shutil
import signtool.signtool as stool
import tempfile

log = logging.getLogger(__name__)


# authenticode {{{1
@pytest.fixture(scope='function')
def pe():
    p = mock.MagicMock()
    p.OPTIONAL_HEADER = mock.MagicMock()
    p.OPTIONAL_HEADER.DATA_DIRECTORY = [mock.MagicMock()]
    return p


def test_authenticode_false(pe):
    with mock.patch('pefile.PE') as m:
        m.return_value = pe
        result = stool.is_authenticode_signed(None)
        assert result is False
        m.assert_called_once_with(None)
        pe.close.assert_called_once_with()


def test_authenticode_true(pe):
    with mock.patch('pefile.PE') as m:
        m.return_value = pe
        enable_auth = mock.MagicMock()
        enable_auth.name = 'IMAGE_DIRECTORY_ENTRY_SECURITY'
        enable_auth.VirtualAddress = 1
        pe.OPTIONAL_HEADER.DATA_DIRECTORY.append(enable_auth)
        result = stool.is_authenticode_signed(None)
        assert result is True
        m.assert_called_once_with(None)
        pe.close.assert_called_once_with()


def test_authenticode_exception(pe):
    def exc():
        raise Exception("foo")
    with mock.patch('pefile.PE', new=exc):
        with mock.patch.object(stool, 'log') as m:
            result = stool.is_authenticode_signed(None)
            assert result is False
            m.exception.assert_called_once_with('Problem parsing file')


# parse_cmdln_opts {{{1
# These are fragile tests, but better something than nothing, especially given
# how little these cmdln opts have changed
# parse_cmdln helpers {{{2
BASE_ARGS = ["-H", "gpg:mar:jar:hostname:port", "-c", "cert", "-t", "token", "-n", "nonce"]
NSS_ARGS = BASE_ARGS + ['--nsscmd', 'echo']
FMTS_ARGS = BASE_ARGS + ['-i', 'foo', '-x', 'bar', "-f"]
MISSING_FMTS_PARAMS = ("dmgv2", "signcode,emevoucher")
INVALID_FMTS_PARAMS = ("foobar", "mar,foobar")
GOOD_FMTS_PARAMS = (
    ("mar", ("mar", )),
    ("mar,jar", ("mar", "jar")),
    ("gpg,jar", ("jar", "gpg"))
)
MISSING_ARGS_PARAMS = (
    ([], "at least one host is required"),
    (BASE_ARGS[:2], "certificate is required"),
    (BASE_ARGS[:4], "token file is required"),
    (BASE_ARGS[:6], "nonce file is required"),
    (BASE_ARGS, "no formats specified"),
)


class ParserHelper(optparse.OptionParser):
    """Store errors from parse_cmdln_opts
    """
    msg = None

    def error(self, msg):
        self.msg = msg
        raise SystemExit(msg)


@contextmanager
def env():
    orig_dir = os.getcwd()
    try:
        tmpdir = tempfile.mkdtemp()
        os.chdir(tmpdir)
        with open("cert", "w") as fh:
            print("cert", file=fh)
        yield
    finally:
        os.chdir(orig_dir)
        shutil.rmtree(tmpdir)


# parse_cmdln tests {{{2
@pytest.mark.parametrize("args", MISSING_ARGS_PARAMS)
def test_parse_missing_args(args):
    log.info(args)
    parser = ParserHelper()
    with env():
        with pytest.raises(SystemExit):
            stool.parse_cmdln_opts(parser, args[0])
    assert parser.msg == args[1]


def test_parse_missing_cert():
    parser = ParserHelper()
    with pytest.raises(SystemExit):
        stool.parse_cmdln_opts(parser, BASE_ARGS)
    assert parser.msg == "certificate not found"


def test_parse_nss():
    pass
    # TODO


@pytest.mark.parametrize("fmt", MISSING_FMTS_PARAMS)
def test_missing_fmts(fmt):
    log.info(fmt)
    parser = ParserHelper()
    with env():
        with pytest.raises(SystemExit):
            stool.parse_cmdln_opts(parser, FMTS_ARGS + [fmt])
    assert parser.msg.startswith("no hosts capable of signing")


@pytest.mark.parametrize("fmt", INVALID_FMTS_PARAMS)
def test_invalid_fmts(fmt):
    log.info(fmt)
    parser = ParserHelper()
    with env():
        with pytest.raises(SystemExit):
            stool.parse_cmdln_opts(parser, FMTS_ARGS + [fmt])
    assert parser.msg.startswith("invalid format:")


@pytest.mark.parametrize("args", GOOD_FMTS_PARAMS)
def test_good_fmts(args):
    log.info(args)
    parser = ParserHelper()
    with env():
        options, _ = stool.parse_cmdln_opts(parser, FMTS_ARGS + [args[0]])
    assert options.formats == list(args[1])
