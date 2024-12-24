__all__ = ["analyze"]

import core.chap as chap

from core.commands import *
from core.encryption import *
from core.exceptions import *
from core.models import *
from core.utils import *


commands = {
    b"\x01": ("upload file", None),
    b"\x02": ("download file", None),
    b"\x03": ("reverse shell", reverse_shell),
}


def analyze(capture, secret: str, signature: str, **kwargs):
    """
    Decrypts traffic from capture and prints as plain text.

    See the command-line help for the meaning of the arguments and the contents
    of kwargs.
    """
    context = chap.step_1(capture, secret, **kwargs)
    assert(isinstance(context, Context))
    try:
        chap.step_2(context, signature, **kwargs)
    except:
        # FIXME: Nested exceptions are malformed.
        warning((
            f"CHAP failed. At best, this means that the wrong shared secret "
            f"(now '{secret}') has been set. Does your ic2kp MD5 match that "
            f"of 'eec8680ebb6926b75829acec93bb484d'? If not so, then the "
            f"default secret AND a MAGIC SIGNATURE (now '{signature}') may be "
            f"different."
        ))
        raise
    while True:
        command = context.get_data(sender = MASTER)
        if command == None:
            break
        if len(command) != 1:
            raise ProtocolError("A command code of length 1 is expected.")
        if not command in commands:
            raise ProtocolError(f"Unknown command code {hexdigest(command)}.")
        display_name, entry_function = commands[command]
        info(f"Handling '{display_name}' command.")
        if entry_function == None:
            raise NotImplementedError((
                "This command has not yet been implemented."
            ))
        entry_function(context, **kwargs)
    info("Done.")
