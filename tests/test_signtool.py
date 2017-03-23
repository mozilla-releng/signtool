from __future__ import print_function
import logging
import mock
import optparse
import pytest
import signtool.signtool as stool
from . import signtool_env

log = logging.getLogger(__name__)


# params {{{1
BASE_ARGS = ["-H", "gpg:mar:jar:hostname:port", "-c", "cert", "-t", "token", "-n", "nonce"]
FMTS_ARGS = BASE_ARGS + ['-i', 'foo', '-x', 'bar', "-f"]
MISSING_FMTS_PARAMS = ("dmg", "signcode,emevoucher")
INVALID_FMTS_PARAMS = ("foobar", "mar,foobar")
GOOD_FMTS_PARAMS = (
    (["mar", "-H", "hostname:port"], ("mar", )),
    (["mar,jar", "-d", "foo"], ("mar", "jar")),
    (["gpg,jar", "-d", "."], ("jar", "gpg"))
)
MISSING_ARGS_PARAMS = (
    ([], "at least one host is required"),
    (BASE_ARGS[:2], "certificate is required"),
    (BASE_ARGS[:4], "token file is required"),
    (BASE_ARGS[:6], "nonce file is required"),
    (BASE_ARGS, "no formats specified"),
)
GOOD_ARGS = BASE_ARGS + ['-f', 'gpg']
NSS_ARGS = GOOD_ARGS + ['--nsscmd']
NSS_PARAMS = (
    ("win32", "asdf", "asdf"),
    ("win32", "/c/asdf", "c:/asdf"),
    ("not-win32", "asdf", "asdf"),
    ("not-win32", "/c/asdf", "/c/asdf"),
)


# helpers {{{1
class ParserHelper(optparse.OptionParser):
    """Store errors from parse_cmdln_opts
    """
    msg = None

    def error(self, msg, *args):
        self.msg = msg
        raise SystemExit(msg)


class ExpectedError(Exception):
    pass


@pytest.fixture(scope='function')
def sign_options():
    options = optparse.Values()
    options.tokenfile = "token"
    options.format_urls = {
        "gpg": ["gpgurl1", "gpgurl2"],
        "signcode": ["signcodeurl1", "signcodeurl2"],
        "dmg": ["dmgurl1", "dmgurl2"],
    }
    options.includes = ['cert']
    options.excludes = []
    options.output_dir = None
    options.formats = ["dmg", "signcode", "gpg"]
    return options


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
@pytest.mark.parametrize("args", MISSING_ARGS_PARAMS)
def test_parse_missing_args(args):
    log.info(args)
    parser = ParserHelper()
    with signtool_env():
        with pytest.raises(SystemExit):
            stool.parse_cmdln_opts(parser, args[0])
    assert parser.msg == args[1]


def test_parse_missing_cert():
    parser = ParserHelper()
    with pytest.raises(SystemExit):
        stool.parse_cmdln_opts(parser, BASE_ARGS)
    assert parser.msg == "certificate not found"


def test_parse_output_file():
    parser = ParserHelper()
    with signtool_env():
        with pytest.raises(SystemExit):
            stool.parse_cmdln_opts(parser, GOOD_ARGS + ['-o', '.', "."])
    assert parser.msg == "-o / --output-file can only be used when signing a single file"


def test_parse_output_dir():
    parser = ParserHelper()
    with signtool_env():
        with pytest.raises(SystemExit):
            stool.parse_cmdln_opts(parser, GOOD_ARGS + ['-d', 'cert', "."])
    assert parser.msg.startswith("output_dir (")


@pytest.mark.parametrize("args", NSS_PARAMS)
def test_parse_nss(args):
    log.debug(args)
    parser = ParserHelper()
    with mock.patch('sys.platform', new=args[0]):
        with signtool_env():
            options, _ = stool.parse_cmdln_opts(parser, NSS_ARGS + [args[1]])
    assert options.nsscmd == args[2]


@pytest.mark.parametrize("fmt", MISSING_FMTS_PARAMS)
def test_missing_fmts(fmt):
    log.info(fmt)
    parser = ParserHelper()
    with signtool_env():
        with pytest.raises(SystemExit):
            stool.parse_cmdln_opts(parser, FMTS_ARGS + [fmt])
    assert parser.msg.startswith("no hosts capable of signing")


@pytest.mark.parametrize("fmt", INVALID_FMTS_PARAMS)
def test_invalid_fmts(fmt):
    log.info(fmt)
    parser = ParserHelper()
    with signtool_env():
        with pytest.raises(SystemExit):
            stool.parse_cmdln_opts(parser, FMTS_ARGS + [fmt])
    assert parser.msg.startswith("invalid format:")


@pytest.mark.parametrize("args", GOOD_FMTS_PARAMS)
def test_good_fmts(args):
    log.info(args)
    parser = ParserHelper()
    with signtool_env():
        options, _ = stool.parse_cmdln_opts(parser, FMTS_ARGS + args[0])
    assert options.formats == list(args[1])


@pytest.mark.parametrize("args", (("__main__", "Done."), ("not-main", None)))
def test_main(args):
    log.debug(args)
    with mock.patch.object(stool, 'sign'):
        with mock.patch('sys.argv', new=["signtool"] + GOOD_ARGS):
            with signtool_env():
                with mock.patch.object(stool, 'log') as l:
                    stool.main(name=args[0])
                    if args[1] is not None:
                        l.info.assert_called_once_with(args[1])
                    else:
                        assert len(l.info.call_args_list) == 0


# sign {{{1
@pytest.mark.parametrize("output_dir", ("foo", None))
def test_sign(output_dir, sign_options):
    sign_options.output_dir = output_dir
    with mock.patch.object(stool, 'remote_signfile') as m:
        with mock.patch.object(stool, 'is_authenticode_signed', new=lambda x: True):
            with signtool_env():
                m.return_value = True
                stool.sign(sign_options, ["cert"])
                log.debug(m.call_args_list)
                m.return_value = False
                with pytest.raises(SystemExit):
                    stool.sign(sign_options, ["cert"])
