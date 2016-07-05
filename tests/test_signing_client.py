import mock
import signtool.signing.client as sclient


def test_getfile():
    m = mock.MagicMock()
    sclient.getfile("baseurl", "filehash", "format", "cert", method=m)
    m.assert_called_once_with("baseurl/sign/format/filehash", verify="cert")
