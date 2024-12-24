__all__ = ["reverse_shell"]

from core.encryption import *
from core.exceptions import *
from core.models import *
from core.utils import *


def read_initializations(context, verbose: int = 0):
    term = context.get_data(sender = MASTER) # environment variable
    argp = context.get_data(sender = MASTER) # ioctl 3'th param
    TBD = context.get_data(sender = MASTER)
    if verbose > 0:
        info(f"putenv('TERM={term.decode()}');")
        info(f"ioctl(..., ..., argp={hexdigest(argp)});")
        info(f"TBD: {TBD}")


def reverse_shell(context, verbose: int = 0, **kwargs) -> None:
    read_initializations(context, verbose)
    
    cout = str()
    cin = str()
    while True:
        try:
            pack = context.get_data()
            if pack == None:
                break
            sender, binary = pack
            text = binary.decode()
            if sender == SLAVE:
                cout += text
            else:
                cin += text
        except:
            error("Error while reading data from the socket.")
            
            # raise
    newline = "← "
    print(colored(newline + cin.replace("\r", f"\n{newline}"), "dark_grey"))
    newline = "→ "
    print(newline + cout.replace("\n", f"\n{newline}"))
