#!/usr/bin/env python3
'''
AntiCSRF.py Single File CSRF Protection
Copyright (C) 2017 Cat Stevens

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

import time

# 1 hour in microseconds
DEFAULT_EXPIRY = (10**6) * 60 * 60


def microtime():
    return round( (10 ** 6) * time.time() )


def random_key(keysize):
    from os       import urandom
    from binascii import hexlify
    return hexlify(urandom(keysize // 2)).decode("ascii")


def _static_vars(**kwargs):
    def decorate(func):
        for k in kwargs:
            setattr(func, k, kwargs[k])
        return func
    return decorate


@_static_vars(index=0)
def keyfun_r(keysize, alpha=__import__("string").ascii_lowercase):
    '''simple reentrant predictable key generator'''
    if not keysize:
        keyfun_r.index = 0
        return

    if keyfun_r.index + keysize >= len(alpha):
        slc = alpha[keyfun_r.index:]
        keyfun_r.index = 0
    else:
        slc = alpha[keyfun_r.index : keyfun_r.index + keysize]
        keyfun_r.index += keysize

    return slc


class token_clerk():
    '''
        Arguments:  preset_tokens: a mapping<string, int>, default: empty
                    expire_after:  int (microseconds),  3600000000 (1 hour)
                    keysize:       int (token length),  42
                    keyfunc:       func<int> -> str[keysize]
        Returns:    a token_clerk object
        Throws:     no
        Effects:    none

        Instantiate an object capable of registering, validating and expiring
            antiCSRF tokens

        API (dictionary keys returned by functions and their meaning):
            - tok: a token (string) of length self.keysize
            - exp: a time (int) in microsecs after the epoch when tok expires/d
            - iat: a time (int) in microsecs, "issued at"
            - reg: a flag (bool) indicating whether tok is currently valid
            - old: a flag (bool) indicating whether tok was valid previously

        Methods that return just an int probably return the number of removed
            or force-expired tokens.
    '''

    def __init__(
        self,
        # preset tokens, for debugging and special cases
        preset_tokens=(),
        # 1 hour (NOTE: microseconds)
        expire_after=DEFAULT_EXPIRY,
        # a number between 32 (too short) and 64 (too long)
        # life, the universe and everything
        keysize=42,
        # default is actual unguessable random key
        keyfunc=random_key,
        # for roundtripping:
        **kwargs
    ):
        import threading
        # currently valid tokens
        self.current_tokens = dict(preset_tokens)
        # keep some expired tokens (TODO: make sure this is trashed routinely)
        self.expired_tokens = dict()
        # after how long tokens should expire, in **microseconds**
        self.expire_after   = expire_after
        # key size to use for the tokens
        self.keysize        = keysize
        # custom key generator function
        self.keyfunc        = keyfunc
        self.Lock           = threading.Lock()

    def register_new(self, clean=True):
        '''
            Arguments:  clean (a bool; whether to call clean_expired,
                        default=True)
            Returns:    a dict with three keys: tok (a token), iat (issued at,
                        a number), and exp (expires at, a number)
            Throws:     anything thrown by self._register
            Effects:    modifies the module-global registry of tokens, updating
                        it with a new key

            Generate and register a new anti-CSRF token with the dictionary.
            By default, tokens expire 1 hour (3600 seconds) after issued.
            Before registering the new token, expired ones are purged.
        '''
        if clean:
            self.clean_expired()

        return self._register(self.keyfunc(self.keysize))

    def unregister(self, *tokens, clr=False, clean=True):
        '''
            Arguments:  tokens (strings)
                        clr (a bool; whether to ignore the given tokens and
                            completely empty the entire registry)
                        clean (a bool; whether to call clean_expired,
                            default=True)
            Returns:    the total number of removed tokens, after the
                        clean_expired job is completed and its value added
            Throws:     TypeError if *tokens contains a non-string
            Effects:    modifies the module-global registry of tokens, possibly
                        deleting the given token or all tokens, and inherited

            Manually expire a token before its 1 hour limit.
            Included in the return value is clean_expired(), so that we can
                expire old tokens at every possible moment.
        '''

        expd = 0
        if clr:
            expd = len(self.current_tokens)
            with self.lock:
                self._log_expired_tokens(self.current_tokens.copy())
                self.current_tokens = dict()
            return expd

        if clean:
            expd = self.clean_expired()

        if not tokens:
            return expd

        if not all( type(t) == str for t in tokens ):
            raise TypeError(
                "expected tokens as strings but got an unhashable type instead"
            )

        expire = dict()

        for t in tokens:
            if t in self.current_tokens:
                expd += 1
                expire.update( { t: self.current_tokens[t] } )
                with self.lock:
                    del self.current_tokens[t]

        self._log_expired_tokens(expire)
        return expd

    def clean_expired(self):
        '''
            Arguments:  none
            Returns:    the number of tokens which were expired after all
            Throws:     no
            Effects:    modifies the module-global registry of tokens, possibly
                        deleting any tokens found to have expired

            Filter out expired tokens from the registry, by only leaving those
                tokens which expire in the future.
            The return value is the difference in length from before and after
                this operation.
        '''
        plen = len(self.current_tokens)

        if not plen:
            return 0

        expire = dict()
        now = microtime()

        copyitems = self.current_tokens.copy().items()
        for tok, exp in copyitems:
            # print(tok, now, exp, exp - now, now >= exp)
            if now >= exp:
                # print("expiring token", tok, "from", exp)
                with self.lock:
                    expire.update({tok: exp})
                    del self.current_tokens[tok]

        self._log_expired_tokens(expire)

        return abs(len(self.current_tokens) - plen)

    def are_valid(self, *tokens, clean=True):
        '''
            Arguments:  tokens (strings), and clean (a bool; whether to call
                        clean_expired, default=True)
            Returns:    a dict<string, dict<string, int>>; each token is a key
                        and each value is a dict<string, int> as returned
                        by self.is_valid.
            Throws:     no
            Effects:    (inherited)

            Test whether a list of tokens are valid (registered).
            Effectively the collection generalisation of is_valid.
        '''
        if clean:
            self.clean_expired()

        # if you passed just one token then the resultant verbosity's your own
        # fault
        return {
            tok: inf
            for tok, inf
            in (self.is_valid(token).items() for token in tokens)
        }

    def is_valid(self, tok, clean=True):
        '''
            Arguments:  a token (string), and clean (a bool; whether to call
                        clean_expired, default=True)
            Returns:    a dict<string, int> with three keys:
                            reg: whether the key is currently registered
                            exp: when the key expires/d or 0 if never was a key
                            old: whether the key was valid in the past
            Throws:     no
            Effects:    (inherited)

            Test whether a token is valid (registered).
            Unpythonically, this function does not let a KeyError be raised if
                the token is not a key; this is because we clean out expired
                tokens first, so they no longer exist by the time the condition
                is tested.
            While it is possible a token could expire after the call to
                clean_expired() but before the condition is checked, this is
                extremely unlikely -- but the code is probably redundant just
                to be safe anyways.
        '''
        if clean:
            self.clean_expired()

        if type(tok) == dict:
            tok = tok["tok"]
        elif type(tok) in (tuple, list, set):
            return self.are_valid(*tok, clean=clean)

        info = {"reg": False, "exp": 0, "old": False}
        if tok in self.current_tokens:
            info = {
                "reg": True,                      # currently registered
                "exp": self.current_tokens[tok],  # when it expires
                "old": False                      # not old
            }
        elif tok in self.expired_tokens:
            info.update(
                # was previously registered, and when it expired
                { "old": True, "exp": self.expired_tokens[tok] }
            )
        # grabs default values too
        return info

    def unexpire(self, *tokens, expire_after=None):
        '''
            Arguments:  tokens (a list of strings), and expire_after (an int;
                        how long tokens should last, default=DEFAULT_EXPIRY)
            Returns:    a dict<string, dict>, that maps tokens from the
                        argument list to their new attributes, as dicts
                        returned by self._register
            Throws:     no
            Effects:    modifies the instance's registry of tokens, updating it
                        with new keys, and modifies the instance's registry of
                        recently expired token

            Given tokens which may or may not have recently expired, register
                them again, removing their expired status and updating their
                time data.
            It is not an error to give tokens which are registered or which
                were never registered.

            Tokens re-registered through this function expire after
                expire_after microseconds, or self.expire_after if that
                argument was None.
        '''
        if expire_after is None:
            expire_after = self.expire_after
        res = {}
        for tok in tokens:
            info = self.is_valid(tok)
            if info["old"] and not info["reg"]:
                res[tok] = self._register(tok, expire_after=expire_after)
                with self.lock:
                    del self.expired_tokens[tok]
        return res

    def _register(self, tok, expire_after=None):
        '''
            Arguments:  tok (a string) and expire_after (an int; microsecs)
            Returns:    a dict with three keys:
                            tok: token, a string
                            iat: issued-at, an integer time in microseconds
                            exp: expires at, an integer time in microseconds
            Throws:     ValueError if tok is not the same len as self.keysize
            Effects:    modifies the instance's registry of tokens, updating
                        it with a new key

            Register an anti-CSRF token with the dictionary.
            By default, tokens expire 1 hour (3600 seconds) after issued.
        '''
        if expire_after is None:
            expire_after = self.expire_after

        if len(tok) != self.keysize:
            raise ValueError(
                "self.keysize: != len(tok) :: {} != {}"
                .format(self.keysize, len(tok))
            )

        now = microtime()
        exp = now + expire_after
        with self.lock:
            self.current_tokens[tok] = exp

        return {"tok": tok, "iat": now, "exp": exp}

    def _log_expired_tokens(self, tokens):
        '''
            Arguments:  tokens (a dict<string, int>)
            Returns:    None
            Throws:     no
            Effects:    modifies self.expired_tokens, deleting and adding keys

            Record tokens that have expired in another dictionary.
        '''
        self._clear_expired_kept(trash=len(tokens))
        with self.lock:
            self.expired_tokens.update(tokens)

    def _clear_expired_kept(self, trash=30):
        '''
            Arguments:  trash (an int, defaults to 30)
            Returns:    None
            Throws:     no
            Effects:    modifies self.expired_tokens, deleting keys

            Trash the oldest kept-expired tokens.
        '''
        stoks = sorted(self.expired_tokens.items(), key=lambda x: x[1])
        with self.lock:
            self.expired_tokens = dict(stoks[trash:])

    def __repr__(self):
        '''
            Represent a token_clerk object in a way that roundtrips (providing
                token_clerk is a bound name).
        '''
        import pprint
        return """token_clerk(
    preset_tokens  = {},
    expire_after   = {},
    keyfunc        = {},
    keysize        = {},
    # other attrs follow as **kwargs
    expired_tokens = {},
)""".format(
            pprint.pformat(self.current_tokens),
            self.expire_after,
            self.keyfunc.__name__,
            self.keysize,
            pprint.pformat(self.expired_tokens)
        )


if __name__ == '__main__':
    t = token_clerk()
    x = eval(repr(t))
