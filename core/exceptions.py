class ProtocolError(Exception):
    """
    The ic2kp protocol does not match capture.
    """
    pass


class HandshakeError(Exception):
    """
    Challenge Handshake Authentication Protocol is failed.
    """
    pass
    

class ImplementationError(Exception):
    """
    Something is wrong in a implementation, e.g. a command does not fetch all
    available ic2kp packets on unordered reads. Close to a protocol error, but
    more our fault.
    """
    pass
