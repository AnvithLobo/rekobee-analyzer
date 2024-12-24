"""Provides pretty printing features.
"""

__all__ = ["colored", "info", "warning", "success", "error", "dump"]

try:
    from termcolor import colored
    from colorama import init
    init()
    del init
except ImportError:
    def colored(message: str, color: str = str()) -> str:
        return message

from .encoding import *


def get_markered_list(label_len: int, body: str) -> str:
    """
    Replace the newlines in the body, just like the bullet list does.

    Has prefix alignment but not the prefix itself.
    """
    tab = " " * (label_len + 1)
    marker = "• "
    result = body.replace("\n", "\n" + tab + marker)
    return result


def get_enumerated_list(label_len: int, body: str) -> str:
    """
    Replace the newlines in the body, just like the numbered list does.

    Has prefix alignment but not the prefix itself.
    """
    tab = " " * (label_len + 1)
    body_lines = body.split("\n")
    result_lines = [body_lines[0],]
    for enumerator, part in enumerate(body_lines[1:], 1):
        result_lines.append(f"{tab}{enumerator}) {part}")
    result = "\n".join(result_lines)
    return result


styles = {
    "list": get_markered_list,
    "enum": get_enumerated_list,
}


def pprint(label: str, color: str, *objects, **kwargs) -> None:
    separator = kwargs.get("sep", " ")
    end = kwargs.get("end", "\n")
    style = kwargs.get("style", None)

    head = colored(label, color) # colored prefix like [info]
    body = separator.join(map(str, objects)) # message after prefix

    if style != None:
        if not style in styles:
            raise ValueError(f"Unknown pprint style '{style}'.")
        formatter = styles[style]
        label_len = len(label) # head has extra ANSI escape codes
        body = formatter(label_len, body)

    print(f"{head} {body}", end = end)


def get_pprint_wrapper(label, color):
    def wrapped(*args, **kwargs):
        pprint(label, color, *args, **kwargs)
    return wrapped


info = get_pprint_wrapper("[info]", "light_blue")
warning = get_pprint_wrapper("[warning]", "light_yellow")
success = get_pprint_wrapper("[ ok ]", "light_green")
error = get_pprint_wrapper("[error]", "light_red")


def chunks(iterable, size: int) -> list:
    for index in range(0, len(iterable), size):
        yield iterable[index:index + size]


def escaped(iterable):
    bad_charset = ("\x0a", "\x0b", "\x0c", "\x0d")
    for char in iterable:
        if not char in bad_charset:
            yield char
        else:
            dummy_escaped = str(char.encode()) # "b'\x0b'"
            hex_escaped = dummy_escaped[2:-1] # "\x0b"
            yield str(hex_escaped)


def dump(data: bytes, size: int = 16, highlights: tuple = ()) -> str:
    """
    Represents the data in dump format, i.e.:

    ```
    [data] 00 01 02 03 44 75 6d 70 | \x00\x01\x02\x03Dump
    [0x08] a5                      | ¥
    ```
    
    :param          data:  The binary data to represent.
    :type           data:  bytes
    :param          size:  The column width.
    :type           size:  int
    :param    highlights:  A segments to highlight in format `(start, end)`.
    :type     highlights:  tuple[tuple[int, int]]
    
    :returns:   Returns the dump as a string with ANSI escape codes.
    :rtype:     str
    """
    codes = hexdigest(data) # "000102"
    pairs = zip(codes[0::2], codes[1::2]) # ('0', '0', '0'), ('0', '1', '2')
    codes = [str().join(pair) for pair in pairs] # ["00", "01", "02"]
    chars = list(map(chr, data)) # ['\x00', '\x01', '\x02']

    lines = list()
    prefix = "data"
    codes = chunks(codes, size)
    chars = chunks(chars, size)
    for line_codes, line_chars in zip(codes, chars):
        colored_line_codes = list()
        offset = len(lines) * size
        for index, code in enumerate(line_codes):
            color = "light_grey"
            for start, end in highlights:
                code_index = index + offset
                if code_index >= start and code_index < end:
                    color = "light_yellow"
                    break
            colored_line_codes.append(colored(code, color))
        justed_codes = " ".join(colored_line_codes)
        justed_codes += " " * (size - len(colored_line_codes)) * 3
        escaped_chars = " ".join(escaped(line_chars))
        lines.append((
            colored("[%s]", "dark_grey") +
            " " +
            colored("%s", "light_grey") +
            colored(" | ", "dark_grey") +
            colored("%s", "light_blue")
        ) % (prefix, justed_codes, escaped_chars))
        prefix = "0x" + hexdigest(size * len(lines))
    result = "\n".join(lines)
    return result
