import api_helper  # from api_helper import microtime, random_key
import threading

'''
    Very basic anti-cross site request forgery token validation scheme.
    For use with low-traffic, low-risk JSON APIs.
'''

# module-global registry of tokens
# a mapping from token strings to expiry times with millisecond precision
ANTICSRF_REGISTER = {
    # here's a good vulnerability to leave uncommented ;)
    # "token": 12344478634234
}

# time until a token expires
ANTICSRF_EXPIRY  = 1000 * 60 * 60  # 1 hour
# length, in bytes of randomness from /dev/urandom or equivalent, to use
ANTICSRF_KEYSIZE = 42


def register_token():
    '''
        Arguments:  none
        Returns:    the newly generated / registered token as a string
        Throws:     no
        Effects:    modifies the module-global registry of tokens, updating it
                    with a new key

        Register a new anti-CSRF token with the global dictionary.
        Tokens expire 1 hour (3600 seconds) after they are issued.
        Before registering the new token, expired ones are purged.
    '''
    global ANTICSRF_REGISTER
    clean_expired()  # clean at every opportunity
    tok = api_helper.random_key(ANTICSRF_KEYSIZE)
    # tokens expire
    lock = threading.Lock()
    with lock:
        ANTICSRF_REGISTER[tok] = api_helper.microtime() + ANTICSRF_EXPIRY
    return tok


# deliberately and prematurely expire a token
def expire_1_token(tok):
    '''
        Arguments:  a token (string)
        Returns:    the total number of removed tokens, after the clean_expired
                    job is completed and its value added
        Throws:     KeyError if the token is not registered, and anything
                    thrown by clean_expired()
        Effects:    modifies the module-global registry of tokens, possibly
                    deleting the given token, and any side effects of
                    clean_expired()

        Manually expire a token before its 1 hour limit.
        Tail-called and included in the return value is clean_expired(), so
            that we can expire old tokens at every possible moment.
    '''
    global ANTICSRF_REGISTER
    lock = threading.Lock()
    with lock:
        del ANTICSRF_REGISTER[tok]
    # also check for other expired tokens
    return 1 + clean_expired()

def expire_all_tokens():
    '''
        Arguments:  none
        Returns:    the total number of removed tokens
        Throws:     no
        Effects:    modifies the module-global registry of tokens, clearing it
    '''
    global ANTICSRF_REGISTER
    ol = len(ANTICSRF_REGISTER)
    lock = threading.Lock()
    with lock:
        ANTICSRF_REGISTER = {}
    return ol

def clean_expired():
    '''
        Arguments:  none
        Returns:    the number of tokens which were expired in this operation
        Throws:     TypeError if a value in ANTICSRF_REGISTER is not a number
        Effects:    modifies the module-global registry of tokens, possibly
                    deleting any tokens found to have expired

        Filter out expired tokens from the registry, by only leaving those
            tokens which expire in the future.
        The return value is the difference in length from before and after
            this operation.
    '''
    global ANTICSRF_REGISTER
    lock = threading.Lock()
    ol = len(ANTICSRF_REGISTER)
    with lock:
        ANTICSRF_REGISTER = dict(filter(
            lambda o: o[1] > api_helper.microtime(),
            ANTICSRF_REGISTER.items()
        ))
    return abs(len(ANTICSRF_REGISTER) - ol)


def is_registered(tok):
    '''
        Arguments:  a token (string)
        Returns:    True or False, based on whether the given token is in fact
            registered and valid
        Throws:     TypeError if the value at ANTICSRF_REGISTER[tok] is not
            orderable with int (i.e, not a number), and anything thrown
            by clean_expired()
        Effects:    any side effects of clean_expired()

        Test whether a token is valid (registered).
        Unpythonically, this function does not let a KeyError be raised if the
            token is not a key; this is because we clean out expired
            tokens first, so they no longer exist by the time the condition is
            tested.
        While it is possible a token could expire after the call to
            clean_expired() but before the condition is checked, this is
            extremely unlikely -- but the code is probably redundant just to
            be safe anyways.
    '''
    clean_expired()  # do this first to prevent replays
    return (tok in ANTICSRF_REGISTER
            and ANTICSRF_REGISTER[tok] > api_helper.microtime())
