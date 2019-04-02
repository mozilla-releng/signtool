from __future__ import print_function
import logging
import mock
import optparse
import pytest
import os
import signtool.signtool as stool
from . import signtool_env

log = logging.getLogger(__name__)


# params {{{1
BASE_ARGS = ["-H", "gpg:mar:sha2signcode-v2:hostname:port", "-c", "cert", "-t", "token", "-n", "nonce"]
FMTS_ARGS = BASE_ARGS + ['-i', 'foo', '-x', 'bar', "-f"]
MISSING_FMTS_PARAMS = ("dmg", "mar_sha384,sha2signcode-v2")
INVALID_FMTS_PARAMS = ("foobar", "mar,foobar")
GOOD_FMTS_PARAMS = (
    (["mar", "-H", "hostname:port"], ("mar", )),
    (["mar,sha2signcode-v2", "-d", "foo"], ("mar", "sha2signcode-v2")),
    (["gpg,sha2signcode-v2", "-d", "."], ("sha2signcode-v2", "gpg")),
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
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
TARBALL = os.path.join(DATA_DIR, "dirtree.tgz")


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
        "sha2signcode-v2": ["sha2signcode1", "sha2signcode2"],
        "dmg": ["dmgurl1", "dmgurl2"],
        "macapp": ["dmgurl1", "dmgurl2"],
    }
    options.includes = ['cert']
    options.excludes = []
    options.output_dir = None
    options.output_file = None
    options.formats = ["dmg", "sha2signcode-v2", "gpg", "macapp"]
    return options


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
                with mock.patch.object(stool, 'log') as patched_log:
                    stool.main(name=args[0])
                    if args[1] is not None:
                        patched_log.info.assert_called_once_with(args[1])
                    else:
                        assert len(patched_log.info.call_args_list) == 0


# sign {{{1
@pytest.mark.parametrize("output_dir,output_file", (
    ("foo", None),
    (None, "foo"),
    (None, None))
)
def test_sign(output_dir, output_file, sign_options):
    sign_options.output_dir = output_dir
    sign_options.output_file = output_file
    with mock.patch.object(stool, 'remote_signfile') as m:
        with mock.patch.object(stool, 'is_authenticode_signed', new=lambda x: True):
            with signtool_env():
                m.return_value = True
                stool.sign(sign_options, ["cert"])
                log.debug(m.call_args_list)
                m.return_value = False
                with pytest.raises(SystemExit):
                    stool.sign(sign_options, ["cert"])


# is_authenticode_signed {{{1
def test_is_authenticode_signed_false():
    assert not stool.is_authenticode_signed(TARBALL)
    assert not stool.is_authenticode_signed(os.path.join(DATA_DIR, 'unsigned32.exe'))
    assert not stool.is_authenticode_signed(os.path.join(DATA_DIR, 'unsigned64.exe'))


def test_is_authenticode_signed_true():
    assert stool.is_authenticode_signed(os.path.join(DATA_DIR, 'signed32.exe'))
    assert stool.is_authenticode_signed(os.path.join(DATA_DIR, 'signed64.exe'))
