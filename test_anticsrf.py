#!/usr/bin/env python3
import unittest
import time

import anticsrf


class TestAntiCSRF(unittest.TestCase):

    def test_create(self):
        t = anticsrf.token_clerk()
        self.assertTrue(t)

    def test_register(self):
        t   = anticsrf.token_clerk()
        tok = t.register_new()
        self.assertTrue(tok["exp"] - tok["iat"] == t.expire_after)
        self.assertTrue(len(tok["tok"])         == t.keysize)
        self.assertTrue(tok["tok"]     in t.current_tokens)
        self.assertTrue(tok["tok"] not in t.expired_tokens)
        self.assertTrue(t.current_tokens[ tok["tok"] ] > anticsrf.microtime())

    def test_unregister(self):
        t    = anticsrf.token_clerk()
        toka = t.register_new()["tok"]
        tokb = t.register_new()["tok"]
        self.assertTrue(len(t.expired_tokens) == 0)
        self.assertTrue(all(x in t.current_tokens for x in [toka, tokb]))

        ct   = t.unregister(toka, tokb)

        self.assertTrue(all(x not in t.current_tokens for x in [toka, tokb]))
        self.assertTrue(all(x in t.expired_tokens for x in [toka, tokb]))
        self.assertEqual(2, ct)

    def test_unregister_all(self):
        t    = anticsrf.token_clerk()
        toks = [t.register_new()["tok"] for i in range(10)]
        ct   = t.unregister_all()
        self.assertEqual(10, ct)

        self.assertFalse(all(tok in t.current_tokens for tok in toks))
        self.assertTrue( all(tok in t.expired_tokens for tok in toks))

    def test_clean_expired(self):
        t    = anticsrf.token_clerk(expire_after=0)
        toks = [t.register_new(clean=False)["tok"] for i in range(10)]
        time.sleep(.001)
        t.clean_expired()

        self.assertFalse(all(tok in t.current_tokens for tok in toks))
        self.assertTrue( all(tok in t.expired_tokens for tok in toks))

    def test_is_registered(self):
        t    = anticsrf.token_clerk()
        toks = [t.register_new()["tok"] for i in range(10)]

        self.assertTrue(all( t.is_registered(tok)  for tok in toks ) )
        # False + 0 = 0 -- these were never registered
        self.assertTrue(0 == sum( sum(t.is_registered(junk)) for junk in ["abc", "cat", "def"])) # noqa

    def test_was_registered(self):
        t    = anticsrf.token_clerk(expire_after=0)
        toks = [t.register_new(clean=False) for i in range(10)]
        time.sleep(.001)
        t.clean_expired()

        # these were registered and their expiry times should be preserved
        for tok in toks:
            isreg, expd = t.is_registered(tok["tok"])
            self.assertFalse(isreg)
            self.assertTrue( expd == tok["exp"])

    def test_roundtrips(self):
        from anticsrf import token_clerk, keyfun_r
        t = token_clerk(
            preset_tokens={"a": 1},
            expire_after=360,
            keyfunc=keyfun_r,
            keysize=2
        )
        x = eval(repr(t))
        self.assertTrue(t.__class__ == x.__class__)


def suiteFactory(
        *testcases,
        testSorter   = None,
        suiteMaker   = unittest.makeSuite,
        newTestSuite = unittest.TestSuite
    ):
    """
    make a test suite from test cases, or generate test suites from test cases.

    *testcases     = TestCase subclasses to work on
    testSorter     = sort tests using this function over sorting by line number
    suiteMaker     = should quack like unittest.makeSuite.
    newTestSuite   = should quack like unittest.TestSuite.
    """

    if testSorter is None:
        ln         = lambda f:    getattr(tc, f).__code__.co_firstlineno
        testSorter = lambda a, b: ln(a) - ln(b)

    test_suite = newTestSuite()
    for tc in testcases:
        test_suite.addTest(suiteMaker(tc, sortUsing=testSorter))

    return test_suite


def caseFactory(
        scope        = globals().copy(),
        caseSorter   = lambda f: __import__("inspect").findsource(f)[1],
        caseSuperCls = unittest.TestCase,
        caseMatches  = __import__("re").compile("^Test")
    ):
    """
    get TestCase-y subclasses from frame "scope", filtering name and attribs

    scope        = iterable to use for a frame; preferably a hashable
                   (dictionary).
    caseMatches  = regex to match function names against; blank matches every
                   TestCase subclass
    caseSuperCls = superclass of test cases; unittest.TestCase by default
    caseSorter   = sort test cases using this function over sorting by line
                   number
    """

    from re import match

    return sorted(
        [
            scope[obj] for obj in scope
                if match(caseMatches, obj)
                and issubclass(scope[obj], caseSuperCls)
        ],
        key=caseSorter
    )


if __name__ == '__main__':

    cases = suiteFactory(*caseFactory())
    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(cases)
