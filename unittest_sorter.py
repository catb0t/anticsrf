import unittest


def suiteFactory(
        *testcases,
        testSorter   = None,
        suiteMaker   = unittest.makeSuite,
        newTestSuite = unittest.TestSuite):
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
        caseMatches  = __import__("re").compile("^Test")):
    """
    get TestCase-y subclasses from frame "scope", filtering name and attribs

    scope        = iterable to use for a frame; preferably one with hashable
                   contents like a dictionary.
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


def main(scope=globals().copy()):
    cases  = suiteFactory( *caseFactory(scope=scope) )
    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(cases)
