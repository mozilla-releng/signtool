import subprocess

from signtool.util.archives import bzip2, bunzip2


class TestSigningUtils(object):
    def test_bzip2(self, tmpdir):
        fn = "%s/foo" % tmpdir
        open(fn, "w").write("hello")
        bzip2(fn)
        proc = subprocess.Popen(["bzcat", fn], stdout=subprocess.PIPE)
        assert b"hello" == proc.stdout.read()

        bunzip2(fn)
        assert b"hello" == open(fn, 'rb').read()
