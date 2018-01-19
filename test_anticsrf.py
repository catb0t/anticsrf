#!/usr/bin/env python3
import unittest
import unittest_sorter
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

        ct   = t.unregister(toka, tokb, clean=False)

        self.assertTrue(all(x not in t.current_tokens for x in [toka, tokb]))
        self.assertTrue(all(x in t.expired_tokens for x in [toka, tokb]))
        self.assertEqual(2, ct)

    def test_unregister_all(self):
        t    = anticsrf.token_clerk()
        toks = [t.register_new()["tok"] for i in range(10)]
        ct   = t.unregister(clr=True, clean=False)
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

    def test_is_valid(self):
        t    = anticsrf.token_clerk()
        toks = [t.register_new()["tok"] for i in range(10)]

        self.assertTrue(all( t.is_valid(tok, clean=False)  for tok in toks ) )
        # False + 0 = 0 -- these were never registered
        for junk in ["abc", "cat", "def", "notakey", "ab"]:
            ji = t.is_valid(junk, clean=False)
            self.assertEqual(ji, {"old": False, "exp": 0, "reg": False})

    def test_was_registered(self):
        t    = anticsrf.token_clerk(expire_after=0)
        toks = [t.register_new(clean=False) for i in range(10)]
        time.sleep(.001)
        t.clean_expired()

        # these were registered and their expiry times should be preserved
        for tok in toks:
            info = t.is_valid(tok["tok"], clean=False)
            self.assertEqual(
                info, {"old": True, "exp": tok["exp"], "reg": False})

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


class TestExampleServer(unittest.TestCase):

    def test_server(self):
        from example import example_main
        import example
        import threading
        import json
        import requests
        import sys
        count_reqs = 1000
        sl = .06
        port = 9962
        em = lambda: example_main(port, count_reqs=count_reqs * 2, quiet=True)
        server_thread = threading.Thread(target=em)
        server_thread.start()
        time.sleep(0)
        print()

        def make_request():
            new_raw = requests.get("http://localhost:" + str(port) + "/?action=new") # noqa
            time.sleep(0)
            new = json.loads(new_raw.text)

            now = anticsrf.microtime()
            check_raw = requests.get(
                "http://localhost:" + str(port) + "/?action=valid&key=" + new["tok"] # noqa
            )
            time.sleep(0)
            check = json.loads(check_raw.text)
            sys.stdout.write("       " + str(i + 1) + "     requests\r")
            sys.stdout.flush()
            if now < new["exp"]:
                self.assertTrue(check["reg"])
                self.assertTrue(not check["old"])
                self.assertTrue(example.t.is_valid(new["tok"]))
            else:
                self.assertTrue(not check["reg"])
                self.assertTrue(check["old"])
                self.assertTrue(not example.t.is_valid(new["tok"]))

        for i in range(count_reqs):
            r = threading.Thread(target=make_request)
            r.start()
            time.sleep(sl)


unittest_sorter.main(scope=globals().copy())
