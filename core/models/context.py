__all__ = ["Context"]

import pyshark

from dataclasses import dataclass
from Crypto.Cipher import AES

from core.models.filters import *
from core.utils import *


@dataclass
class Context:
    """
    Provides information about the decryption process, TCP and ic2kp packets.

    See 'chap.step_1' for some comments about fields.
    """
    aes_1: AES
    aes_2: AES
    capture: pyshark.FileCapture
    current_packet: int
    packets_filter: PacketsFilter
    verbose: int

    def __post_init__(self):
        self._decrypted = list()
        self._last_sender = None

    def __del__(self):
        try:
            self.capture.close()
        except:
            # FIXME: Happens in some cases.
            warning("Failed to gracefully close capture.")
            if self.verbose != 0:
                raise

    @property
    def tcp_packet(self):
        try:
            return self.capture[self.current_packet]
        except KeyError:
            return None

    def advance(self, sender: str = None):
        """
        Safe advances the current_packet index.

        Note that a TCP packet can contain more than one ic2kp packet.

        :param    sender:  MASTER, SLAVE or None.
        :type     sender:  str
        
        :returns:   Returns the current TCP packet itself or None.
        :rtype:     pyshark.packet.packet.Packet
        """
        try:
            while True:
                self.current_packet += 1
                packet = self.capture[self.current_packet]
                if int(packet.tcp.len) == 0:
                    continue
                if not self.packets_filter(packet, sender):
                    if self.verbose > 1:
                        if sender is None or self.packets_filter(packet):
                            warning("The non-empty packet was ignored.")
                    continue
                if self.verbose > 1:
                    info((
                        f"Advance to packet {self.current_packet} (sent by "
                        f"{sender})."
                    ))
                return packet
        except KeyError:
            return None

    def get_data(self, sender: str = None) -> bytes:
        """
        Decrypts the next ic2kp packet (probably in the same TCP packet).

        :param    sender:  MASTER, SLAVE or None to auto identify.
        :type     sender:  str
        
        :returns:   Returns the decrypted data or None. If the sender was
                    automatically identified, return a tuple like (sender,
                    decoded); otherwise, just decoded.
        :rtype:     bytes | tuple[str, bytes]
        """
        if len(self._decrypted) == 0:
            from core.encryption import decrypt

            # One or more a ic2kp packets from a TCP packet.
            packets = self.advance(sender)
            if packets is None:
                return None

            liable = sender
            if sender is None:
                liable = self.packets_filter.identify_sender(packets)
            self._last_sender = sender

            decrypted = decrypt(self, data(packets), sender=liable)
            if self._last_sender == None:
                self._decrypted.extend([(liable, dat) for dat in decrypted])
            else:
                self._decrypted.extend(list(decrypted))
        elif sender != self._last_sender:
            # Probably outside of the function, the packet is expected to be
            # sent (and decrypted) by the sender, but in fact the packet can
            # be sent by both the client and the server.
            #
            # FIXME: I killed multi-command support? Does the server even
            # support this? Or is the fork thread just to protect against
            # debugging?
            if sender != self.packets_filter.identify_sender(self.tcp_packet):
                raise ImplementationError((
                    f"Undefined behaviour: not fetched all available ic2kp "
                    f"packets as {self._last_sender}, but started fetching "
                    f"as {sender}."
                ))
        return self._decrypted.pop(0)
