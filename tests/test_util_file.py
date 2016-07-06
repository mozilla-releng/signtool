import hashlib
import os

from signtool.util.file import compare, sha1sum, safe_copyfile


class TestFileOps(object):
    def testCompareEqFiles(self, tmpdir):
        tmp = tmpdir.strpath
        file1 = os.path.join(tmp, "foo")
        file2 = os.path.join(tmp, "bar")
        open(file1, "w").write("hello")
        open(file2, "w").write("hello")
        assert compare(file1, file2)

    def testCompareDiffFiles(self, tmpdir):
        tmp = tmpdir.strpath
        file1 = os.path.join(tmp, "foo")
        file2 = os.path.join(tmp, "bar")
        open(file1, "w").write("hello")
        open(file2, "w").write("goodbye")
        assert not compare(file1, file2)

    def testSha1sum(self):
        h = hashlib.new('sha1')
        h.update(open(__file__, 'rb').read())
        assert sha1sum(__file__) == h.hexdigest()

    def testCopyFile(self, tmpdir):
        tmp = os.path.join(tmpdir.strpath, "t")
        safe_copyfile(__file__, tmp)
        assert sha1sum(__file__) == sha1sum(tmp)
        assert os.stat(__file__).st_mode == os.stat(tmp).st_mode
        assert int(os.stat(__file__).st_mtime) == int(os.stat(tmp).st_mtime)
