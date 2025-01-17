"""Decrypts traffic generated by ic2kp (rekobee).

Created for the HTB challenge (https://app.hackthebox.com/challenges/295). There
you can find the ic2kp client and a sample capture.
"""

__help__ = """common problems:

pyshark.tshark.tshark.TSharkNotFoundException : TShark not found
    Change wireshark (tshark & dumpcap) location in 'config.ini'

verbose levels:

1) -v: extra information;
2) -vv: packets and advances.

example: analyze.py -c capture.pcap -s secret -vv
"""

import argparse
import pyshark
from pathlib import Path

import core
import core.utils


def get_args():
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog=__help__,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "-c",
        required=True,
        dest="capture_file",
        help="path to capture file from wireshark",
        metavar="CAPTURE",
        type=Path
    )
    parser.add_argument(
        "-s",
        required=True,
        dest="secret",
        help="ic2kp session shared secret",
        metavar="SECRET",
        type=str
    )
    parser.add_argument(
        "-i",
        default=None,
        dest="initial",
        help="initial packet index",
        metavar="INDEX",
        type=int
    )
    parser.add_argument(
        "-v",
        action="count",
        default=0,
        dest="verbose",
        help="everything in detail",
    )
    parser.add_argument(
        "--signature",
        default="5890ae86f1b91cf6298395711dde580d",
        dest="signature",
        help="ic2kp magic hex signature, e.g. 5890...580d",
        metavar="HEX",
        type=str
    )
    parser.add_argument(
        "--filter",
        default="tcp && tcp.len > 0 && !(http or ssh)",
        dest="filter",
        help="display filter for tshark",
        metavar="FILTER",
        type=str
    )
    return parser.parse_args()


def filter_capture(options):
    if options.initial:
        return options.capture_file

    try:
        filtered_capture = pyshark.FileCapture(str(options.capture_file), display_filter=args.filter)
        # get the 0th packet to force tsark to read the file
        _ = filtered_capture[0]

        return filtered_capture
    except FileNotFoundError as exp:
        core.utils.error(f"File '{options.capture_file}' not found.")
        raise exp
    except pyshark.capture.capture.TSharkCrashException as exp:
        core.utils.error("TShark crashed. likely due to invalid filter.")
        raise exp


if __name__ == "__main__":
    args = get_args()
    try:
        core.analyze(capture=filter_capture(args), **vars(args))
    except Exception as exception:
        core.utils.error(str(exception))
        if args.verbose != 0:
            raise
