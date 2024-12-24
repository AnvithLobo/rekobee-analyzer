__all__ = ["PacketsFilter", "MASTER", "SLAVE"]

from core.exceptions import *


MASTER = "master"
SLAVE = "slave"


class PacketsFilter:
    """
    Provides information about the client (infected) and the server (CNC).
    """
    def __init__(self, packet):
        """
        Constructor that extracts information from the initial packet.

        :param      packet:  The initial packet.
        :type       packet:  pyshark.packet.packet.Packet
        """
        self.master_address = str(packet.ip.src)
        self.slave_address = str(packet.ip.dst)
        self.master_port = int(packet.tcp.srcport)
        self.slave_port = int(packet.tcp.dstport)
        self._comparable_master = set((
            self.master_address,
            self.master_port,
        ))
        self._comparable_slave = set((
            self.slave_address,
            self.slave_port,
        ))
        self._comparable = set((
            self.master_address,
            self.master_port,
            self.slave_address,
            self.slave_port,
        ))

    def __call__(self, packet, sender: str = None) -> bool:
        """
        Checks if the packet belongs to the participants.

        :param      packet:  The packet.
        :type       packet:  pyshark.packet.packet.Packet
        :param      sender:  The requested side to send the packet or None.
        :type       sender:  str
        
        :returns:   Returns true if so; otherwise, false.
        :rtype:     bool
        """
        if sender == None:
            comparable = set((
                str(packet.ip.src),
                int(packet.tcp.srcport),
                str(packet.ip.dst),
                int(packet.tcp.dstport),
            ))
            return comparable == self._comparable
        comparable = set((
            str(packet.ip.src),
            int(packet.tcp.srcport),
        ))
        if sender == MASTER:
            return comparable == self._comparable_master
        elif sender == SLAVE:
            return comparable == self._comparable_slave
        raise NotImplementedError(f"Unknown sender '{sender}'.")

    def identify_sender(self, packet) -> str:
        for sender in (MASTER, SLAVE):
            if self(packet, sender):
                return sender
        raise ImplementationError("Automatic sender identification failed.")
