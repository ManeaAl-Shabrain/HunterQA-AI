"""One shared post-DNS TCP/TLS/HTTP I/O deadline for native cloud calls."""
from __future__ import annotations

import io
import time

REQUEST_TIMEOUT = 5.0


def deadline():
    return time.monotonic() + REQUEST_TIMEOUT


def remaining(end):
    value = end - time.monotonic()
    if value <= 0:
        raise TimeoutError("Cloud transport deadline exceeded")
    return value


class _Reader(io.RawIOBase):
    def __init__(self, owner):
        super().__init__()
        self.owner = owner

    def readable(self):
        return True

    def readinto(self, buffer):
        if self.closed:
            raise ValueError("Read from closed cloud response")
        self.owner.check()
        return self.owner.channel.recv_into(buffer)

    def close(self):
        if not self.closed:
            try:
                super().close()
            finally:
                self.owner.release_reader()


class DeadlineSocket:
    """HTTP socket subset with deadline-aware reads and response-file ownership.

    HTTPConnection closes its socket before returning a Connection: close
    response. Keep that response's reader alive, then release the TLS channel
    when both the connection owner and its readers have closed.
    """
    def __init__(self, channel, end):
        self.channel, self.end = channel, end
        self.closed, self.released, self.readers = False, False, 0

    def check(self):
        self.channel.settimeout(remaining(self.end))

    def sendall(self, data):
        if self.closed:
            raise OSError("Cloud connection closed")
        self.check()
        self.channel.sendall(data)

    def makefile(self, mode="rb"):
        if self.closed or mode != "rb":
            raise ValueError("Unsupported cloud response stream")
        self.readers += 1
        raw = _Reader(self)
        try:
            return io.BufferedReader(raw)
        except BaseException:
            raw.close()
            raise

    def release_reader(self):
        self.readers -= 1
        self._release()

    def _release(self):
        if self.closed and not self.readers and not self.released:
            self.released = True
            self.channel.close()

    def close(self):
        self.closed = True
        self._release()


def finish_tls(channel, context, host, end):
    tls = None
    try:
        channel.settimeout(remaining(end))
        tls = context.wrap_socket(channel, server_hostname=host)
        tls.settimeout(remaining(end))
        return DeadlineSocket(tls, end)
    except BaseException:
        (tls if tls is not None else channel).close()
        raise


def read_response(response, limit):
    """Retain the existing byte/encoding limits and always close the reader."""
    try:
        if response.getheader("Content-Encoding", "identity").lower() != "identity":
            raise ValueError("Unsupported cloud response encoding")
        body = response.read(limit + 1)
        if len(body) > limit:
            raise ValueError("Cloud response size rejected")
        return {"status": response.status, "body": body}
    finally:
        response.close()
