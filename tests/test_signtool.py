from __future__ import print_function
import mock
import optparse
import pytest
import signtool.signtool as stool
import sys


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
class ParserHelper(optparse.OptionParser):
    """Store errors from parse_cmdln_opts
    """
    msg = None
    def error(self, msg):
        self.msg = msg
        raise Exception()


def test_parse_no_args():
    parser = ParserHelper()
    with pytest.raises(Exception):
        stool.parse_cmdln_opts(parser, [])
    assert parser.msg.startswith("at least one host")
