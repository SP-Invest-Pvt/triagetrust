import unittest

from triagetrust.context import strip_comments
from triagetrust.models import Finding
from triagetrust.triagers.llm import build_prompt


class LeakageTests(unittest.TestCase):
    def test_comments_removed_strings_kept(self):
        src = ('String bar = (String) map.get("keyA"); // get safe value back out\n'
               '/* the value is\n   never tainted */ String u = "http://x//y"; char c = \'/\';\n'
               'String s = "/* not a comment */";')
        out = strip_comments(src)
        self.assertNotIn("safe value", out)
        self.assertNotIn("never tainted", out)
        self.assertIn('"http://x//y"', out)
        self.assertIn('"/* not a comment */"', out)
        self.assertIn("'/'", out)
        self.assertEqual(src.count("\n"), out.count("\n"))  # line numbers stay valid

    def test_prompt_is_comment_free_by_default(self):
        f = Finding("x", "r", "sqli", 89, "A.java", 1,
                    code="bar = list.get(1); // get the last 'safe' value\n")
        self.assertNotIn("'safe' value", build_prompt(f))
        self.assertIn("'safe' value", build_prompt(f, keep_comments=True))


if __name__ == "__main__":
    unittest.main()
