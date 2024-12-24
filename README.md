<h1 align="center"><br>Rekobee analyzer<br></h1>
<h4 align="center">Tool to view ic2kp traffic from a wireshark capture.</h4>
<p align="center">
  <a href="#installing-and-running">Installing and running</a> •
  <a href="#usage">Description of use</a> •
  <a href="#outputs">Outputs</a>
</p>

# Disclaimer

Most of the code was written by `alexander-utkov` and was deleted / set to private due to unknown reasons. 

This repository is a fork of the original repository and maintains the same license as the original repository with some code changes to make it easier to parse larger captures.

I have also removed mentions to the active challenge that this was originally written for as the challenge solution is not supposed to made be public yet.

# Purpose

The main goal is to solve REDACTED
challenge. Therefore, the tool is underdeveloped. Commands implementation:

| Command       | Status                  |
|---------------|-------------------------|
| reverse shell | :heavy_check_mark: done |
| download      | :x: not planned         |
| upload        | :x: not planned         |

Development will be easier with a ic2kp server executable or capture sample with
all the commands used. You can continue development only with the ic2kp client -
more reverse engineering and write an emulator for the server, but that's not my
goal. So the implementation of the remaining commands is not planned.

# Installing and running <a id="installing-and-running"></a>

Software requirements:

- Python 3.10;
- Wireshark or tshark.

Quick start commands:

```cmd
git clone https://github.com/AnvithLobo/rekobee-analyzer
cd rekobee-analyzer
py -m pip install -r requirements.txt
analyze.py --help
```

# Description of use <a id="usage"></a>

This section has a wetter explanation of the command line arguments. See help
message for dry version.

> **Warning**
> The default values were obtained from the client executable, which has an MD5
> of `eec8680ebb6926b75829acec93bb484d`. If you have a different client, you
> must explicitly pass in your values.

### -c CAPTURE

This is a wireshark `pcap` capture file or more modern that tshark supports. You
can find one in the challenge.

### -s SECRET

The operator uses this password to start the client and server.

If a default value is incorrect, then there is no easy way to decrypt the
traffic. Maybe a known plaintext attack on AES 128 CBC. Use `-vv` verbose
mode to get AES contexts and determine which one is used next. Then look at the
second ic2kp packet - this is the first CHAP challenge containing the magic
signature. See `core/encryption.py` for the structure of the ic2kp packet.

### -i INDEX

The index of a initial ic2kp packet, 40 bytes in size. For small captures it
will be determined automatically.

### --signature HEX

The magic signature that the client and server used during CHAP.

To find the signature in the client executable, define the following calls:

- `send` (exported symbol);
- `send_raw_packet`;
- `send_enc_packet`;
- `client_init`.

Only `send_enc_packet` is used in 4 places. So look for a call that sends 0x14
bytes from static data.

# Outputs <a id="outputs"></a>

## Reverse Shell

Displays input (from the server) and output (from the client) streams.

<p align="center"><img src=".github/revsh.png"></p>

In verbose mode, also displays TERM, argp for ioctl, and anything else that I
don't take into account.
