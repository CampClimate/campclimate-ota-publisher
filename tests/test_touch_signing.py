import unittest

from release_signing import SigningError
from sign_touch import DESCRIPTOR, touch_manifest


class TouchSigningTests(unittest.TestCase):
    def image(self, board):
        return bytes([0xe9]) + bytes(23) + DESCRIPTOR.pack(
            b"CCFWSEQ1", 1, b"CCTGTID1", board.encode(), b"1.0.0-rc1")

    def manifest(self, board="touch-usbc", version="1.0.0-rc1", sequence=1, image=None):
        return touch_manifest(self.image(board) if image is None else image, board, version, sequence, "test")

    def test_both_board_targets(self):
        for board in ("touch-usbc", "touch-original"):
            self.assertEqual(self.manifest(board).target, board)

    def test_wrong_board_factory_version_sequence_or_ambiguous_descriptor(self):
        image = self.image("touch-usbc")
        for args in (dict(board="touch-original", image=image), dict(image=self.image("factory-usbc")),
                     dict(version="2"), dict(sequence=0), dict(sequence=2), dict(image=image[:-1]),
                     dict(image=image + image), dict(image=b"\0" + image[1:])):
            with self.subTest(args=list(args)), self.assertRaises(SigningError):
                self.manifest(**args)
