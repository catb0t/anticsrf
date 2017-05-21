#!/usr/bin/env python3
import time
import threading


def microtime():
    return round( (10 ** 6) * time.time() )


def random_key(keysize):
    from os       import urandom
    from binascii import hexlify
    return hexlify(urandom(keysize)).decode("ascii")[keysize:]


def _static_vars(**kwargs):
    def decorate(func):
        for k in kwargs:
            setattr(func, k, kwargs[k])
        return func
    return decorate


@_static_vars(index=0)
def keyfun_r(keysize, alpha=__import__("string").ascii_lowercase):
    '''simple reentrant non-secure key generator'''
    if not keysize:
        keyfun_r.index = 0
        return

    if keyfun_r.index + keysize > len(alpha):
        slc = alpha[keyfun_r.index:]
        keyfun_r.index = 0
    else:
        slc = alpha[keyfun_r.index : keyfun_r.index + keysize]
        keyfun_r.index += keysize

    return slc


class token_clerk():
    '''
        Arguments:  preset_tokens: a tuple<string, int>, default: empty
                    expire_after:  int (microseconds),  3600000000 (1 hour)
                    keysize:       int (token length),  42
                    keyfunc:       func<int> -> str[keysize]
        Returns:    a token_clerk object
        Throws:     no
        Effects:    none

        Instantiate an object capable of registering, validating and expiring
            antiCSRF tokens
    '''

    def __init__(
        self,
        # preset tokens, for debugging and special cases
        preset_tokens=(),
        # 1 hour (NOTE: microseconds)
        expire_after=(10**6) * 60 * 60,
        # a number between 32 (too short) and 64 (too long)
        keysize=42,
        # default is actual unguessable random key
        keyfunc=random_key,
        # for roundtripping:
        **kwargs
    ):
        # currently valid tokens
        self.current_tokens = dict(preset_tokens)
        # keep some expired tokens (TODO: make sure this is trashed routinely)
        self.expired_tokens = dict()
        # after how long tokens should expire, in **microseconds**
        self.expire_after   = expire_after
        # key size to use for the tokens
        # life, the universe and everything
        self.keysize        = keysize
        # custom key generator function
        self.keyfunc        = keyfunc

    def register_new(self, clean=True):
        '''
            Arguments:  clean (a bool; whether to call clean_expired,
                        default=True)
            Returns:    a dict with three keys: tok (a token), iat (issued at,
                        a number), and exp (expires at, a number)
            Throws:     ValueError if self.keyfunc returns a string of length
                        different than self.keysize
            Effects:    modifies the module-global registry of tokens, updating
                        it with a new key

            Register a new anti-CSRF token with the dictionary.
            Tokens expire 1 hour (3600 seconds) after they are issued.
            Before registering the new token, expired ones are purged.
        '''
        if clean:
            self.clean_expired()
        tok = self.keyfunc(self.keysize)

        if len(tok) != self.keysize:
            raise ValueError(
                "self.keysize: != len(tok) :: {} != {}"
                .format(self.keysize, len(tok))
            )

        now = microtime()
        exp = now + self.expire_after
        with threading.Lock():
            self.current_tokens[tok] = exp
        return {"tok": tok, "iat": now, "exp": exp}

    def unregister_all(self):
        '''
            Arguments:  none
            Returns:    the total number of removed tokens
            Throws:     no
            Effects:    modifies the registry of tokens, clearing it
        '''
        plen = len(self.current_tokens)
        with threading.Lock():
            self._log_expired_tokens(self.current_tokens.copy())
            self.current_tokens = dict()
        return plen

    def unregister(self, *tokens, clean=True):
        '''
            Arguments:  tokens (strings) and clean (a bool; whether to call
                        clean_expired, default=True)
            Returns:    the total number of removed tokens, after the
                        clean_expired job is completed and its value added
            Throws:     TypeError if *tokens contains a non-string
            Effects:    modifies the module-global registry of tokens, possibly
                        deleting the given token, and any side effects of
                        clean_expired()

            Manually expire a token before its 1 hour limit.
            Tail-called and included in the return value is clean_expired(), so
                that we can expire old tokens at every possible moment.
        '''

        expd = 0
        if clean:
            expd = self.clean_expired()

        if not tokens:
            return expd

        if not all( type(t) == str for t in tokens ):
            raise TypeError(
                "expected tokens as strings but got an unhashable type instead"
            )

        expire = dict()

        with threading.Lock():
            for t in tokens:
                if t in self.current_tokens:
                    expd += 1
                    expire.update( { t: self.current_tokens[t] } )
                    del self.current_tokens[t]

        self._log_expired_tokens(expire)
        return expd

    def clean_expired(self):
        '''
            Arguments:  none
            Returns:    the number of tokens which were expired
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

        with threading.Lock():
            copyitems = self.current_tokens.copy().items()
            for tok, exp in copyitems:
                # print(tok, now, exp, exp - now, now >= exp)
                if now >= exp:
                    # print("expiring token", tok, "from", exp)
                    expire.update({tok: exp})
                    del self.current_tokens[tok]

        self._log_expired_tokens(expire)

        return abs(len(self.current_tokens) - plen)

    def is_registered(self, tok, clean=True):
        '''
            Arguments:  a token (string), and clean (a bool; whether to call
                        clean_expired, default=True)
            Returns:    True or False, based on whether the given token is in
                        fact registered and valid
            Throws:     no
            Effects:    any side effects of clean_expired()

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

        exist = tok in self.current_tokens
        old   = tok in self.expired_tokens

        if exist:
            # return True and when it expires
            exp = self.current_tokens[tok]
            return exp > microtime(), exp
        elif old:
            # return False and when it expired
            old_exp = self.expired_tokens[tok]
            return False, old_exp
        else:
            # return False and 0
            return False, 0

    def _log_expired_tokens(self, tokens):
        '''
            Arguments:  tokens (a dict<string, int>)
            Returns:    None
            Throws:     no
            Effects:    modifies self.expired_tokens, deleting and adding keys

            Record tokens that have expired in another dictionary.
        '''
        self._clear_expired_kept(trash=len(tokens))
        with threading.Lock():
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
        with threading.Lock():
            self.expired_tokens = dict(stoks[trash:])

    def __repr__(self):
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
    print(x)
