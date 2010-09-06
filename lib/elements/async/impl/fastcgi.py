# This file is part of Elements.
# Copyright (c) 2010 Sean Kerr. All rights reserved.
#
# The full license is available in the LICENSE file that was distributed with this source code.
#
# Author: Noah Fontes <nfontes@invectorate.com>

import struct
try: import cStringIO as StringIO
except ImportError: import StringIO

from elements.core.exception import ClientException
from elements.core.exception import ProtocolException

from elements.async.client   import Client
from elements.async.client   import EVENT_READ

from elements.async.server   import Server

# ----------------------------------------------------------------------------------------------------------------------
# PROTOCOL SPECIFICATION AND CONSTANTS
# ----------------------------------------------------------------------------------------------------------------------

"""
typedef struct {
    unsigned char version;
    unsigned char type;
    unsigned char requestIdB1;
    unsigned char requestIdB0;
    unsigned char contentLengthB1;
    unsigned char contentLengthB0;
    unsigned char paddingLength;
    unsigned char reserved;
} FCGI_Header;
"""

FCGI_HEADER_LEN = 8

# ----------------------------------------------------------------------------------------------------------------------

FCGI_VERSION_1 = 1

# ----------------------------------------------------------------------------------------------------------------------

FCGI_BEGIN_REQUEST     =  1
FCGI_ABORT_REQUEST     =  2
FCGI_END_REQUEST       =  3
FCGI_PARAMS            =  4
FCGI_STDIN             =  5
FCGI_STDOUT            =  6
FCGI_STDERR            =  7
FCGI_DATA              =  8
FCGI_GET_VALUES        =  9
FCGI_GET_VALUES_RESULT = 10
FCGI_UNKNOWN_TYPE      = 11
FCGI_MAXTYPE           = FCGI_UNKNOWN_TYPE

# ----------------------------------------------------------------------------------------------------------------------

FCGI_NULL_REQUEST_ID = 0

# ----------------------------------------------------------------------------------------------------------------------

"""
typedef struct {
    unsigned char roleB1;
    unsigned char roleB0;
    unsigned char flags;
    unsigned char reserved[5];
} FCGI_BeginRequestBody;
"""

"""
typedef struct {
    FCGI_Header header;
    FCGI_BeginRequestBody body;
} FCGI_BeginRequestRecord;
"""

FCGI_KEEP_CONN = 1

# ----------------------------------------------------------------------------------------------------------------------

FCGI_RESPONDER  = 1
FCGI_AUTHORIZER = 2
FCGI_FILTER     = 3

# ----------------------------------------------------------------------------------------------------------------------

"""
typedef struct {
    unsigned char appStatusB3;
    unsigned char appStatusB2;
    unsigned char appStatusB1;
    unsigned char appStatusB0;
    unsigned char protocolStatus;
    unsigned char reserved[3];
} FCGI_EndRequestBody;
"""

"""
typedef struct {
    FCGI_Header header;
    FCGI_EndRequestBody body;
} FCGI_EndRequestRecord;
"""

FCGI_REQUEST_COMPLETE = 0
FCGI_CANT_MPX_CONN    = 1
FCGI_OVERLOADED       = 2
FCGI_UNKNOWN_ROLE     = 3

# ----------------------------------------------------------------------------------------------------------------------

FCGI_MAX_CONNS  = "FCGI_MAX_CONNS"
FCGI_MAX_REQS   = "FCGI_MAX_REQS"
FCGI_MPXS_CONNS = "FCGI_MPXS_CONNS"

"""
typedef struct {
    unsigned char type;    
    unsigned char reserved[7];
} FCGI_UnknownTypeBody;
"""

"""
typedef struct {
    FCGI_Header header;
    FCGI_UnknownTypeBody body;
} FCGI_UnknownTypeRecord;
"""

HEADER_STRUCT            = struct.Struct('>BBHHBx')

BEGIN_REQUEST_STRUCT     = struct.Struct('>HBxxxxx')
END_REQUEST_STRUCT       = struct.Struct('>IBxxx')
UNKNOWN_TYPE_STRUCT      = struct.Struct('>Bxxxxxxx')

NAME_VALUE_PAIR_STRUCTS  = { (1, 1): struct.Struct('>BB'),
                             (1, 4): struct.Struct('>BI'),
                             (4, 1): struct.Struct('>IB'),
                             (4, 4): struct.Struct('>II') }

NAME_VALUE_PAIR_ENCODERS = { 1: lambda length: length,
                             4: lambda length: length | 0x80000000L }
NAME_VALUE_PAIR_DECODERS = { 1: lambda length: length,
                             4: lambda length: length & ~0x80000000L }

# ----------------------------------------------------------------------------------------------------------------------
# RECORD WRITERS
# ----------------------------------------------------------------------------------------------------------------------

class _Record (object):

    def __init__ (self, type, request_id = FCGI_NULL_REQUEST_ID):
        self._version = FCGI_VERSION_1
        self._type = type
        self._request_id = request_id

    def write (self, client):
        data = self.render()
        data_length = len(data)

        client.write(HEADER_STRUCT.pack(self._version, self._type, self._request_id, data_length, 0))
        client.write(data)

    def render (self):
        raise NotImplementedError("_Record#render() must be overridden")

# ----------------------------------------------------------------------------------------------------------------------

class _GetValuesResultRecord (_Record):

    def __init__ (self, results):
        _Record.__init__(self, FCGI_GET_VALUES_RESULT)
        self._results = results

    def _write_kv_pair (self, key, value, destination):
        key_length = len(key)
        value_length = len(value)

        nll = 1 if key_length < 128 else 4
        vll = 1 if value_length < 128 else 4

        destination.write(NAME_VALUE_PAIR_STRUCTS[(nll, vll)].pack(
                NAME_VALUE_PAIR_ENCODERS[nll](key_length),
                NAME_VALUE_PAIR_ENCODERS[vll](value_length)
        ))
        destination.write(key)
        destination.write(value)

    def render (self):
        buffer = StringIO.StringIO()

        for key, value in self._results.iteritems():
            self._write_kv_pair(key, value, buffer)

        contents = buffer.getvalue()
        buffer.close()

        return buffer

# ----------------------------------------------------------------------------------------------------------------------

class _UnknownTypeRecord (_Record):

    def __init__ (self, unknown_type):
        _Record.__init__(self, FCGI_UNKNOWN_TYPE)
        self._unknown_type = unknown_type

    def render (self):
        return UNKNOWN_TYPE_STRUCT.pack(self._unknown_type)

# ----------------------------------------------------------------------------------------------------------------------

class _EndRequestRecord (_Record):

    def __init__ (self, application_status, protocol_status, request_id):
        _Record.__init__(self, FCGI_END_REQUEST, request_id)
        self._application_status = application_status
        self._protocol_status = protocol_status

    def render (self):
        return END_REQUEST_STRUCT.pack(self._application_status, self._protocol_status)

# ----------------------------------------------------------------------------------------------------------------------

class _StreamRecord (_Record):

    def __init__ (self, type, data, request_id):
        _Record.__init__(self, type, request_id)
        self._data = data

    def render (self):
        return self._data

# ----------------------------------------------------------------------------------------------------------------------
# STDIN/STDOUT WRITER
# ----------------------------------------------------------------------------------------------------------------------

class _OutputWriter (object):

    def __init__ (self, client, type):
        self._client = client
        self._type = type
        self._closed = False
        self._has_data = False

    def write (self, data):
        if not self._closed and len(data) > 0:
            self._client._write_record(_StreamRecord(self._type, data, self._client.request_id))
            self._has_data = True

    def writelines (self, sequence):
        for data in sequence:
            self.write(data)

    def close (self):
        if not self._closed and self._has_data:
            self._client._write_record(_StreamRecord(self._type, "", self._client.request_id))

        self._closed = True

    @property
    def closed (self):
        return self._closed

# ----------------------------------------------------------------------------------------------------------------------

class FastcgiException (ProtocolException):
    """
    Raised when an unexpected protocol error occurs while handling a FastCGI request.
    """

    pass

# ----------------------------------------------------------------------------------------------------------------------

class FastcgiClient (Client):

    def __init__ (self, client_socket, client_address, server, server_address):
        """
        Creates a new FastcgiClient instance.

        @param client_socket  (socket) The client socket.
        """

        Client.__init__(self, client_socket, client_address, server, server_address)

        self._is_allowing_persistence = False                # whether this client will be allowed to handle multiple
                                                             # connections
        self._maximum_requests        = None                 # the maximum number of requests this client will accept
        self._handled_requests        = 0                    # number of requests processed so far
        self._persistence_requested   = True                 # whether the server wants to use persistence for further
                                                             # requests

        self._params_io               = None                 # temporary (StringIO) storage for FCGI_PARAMS
        self._has_params              = False                # whether we've read in all the params
        self._stdin_io                = None                 # temporary (StringIO) storage for FCGI_STDIN
        self._has_stdin               = False                # whether we've read in stdin completely

        self.request_id               = FCGI_NULL_REQUEST_ID # the current FastCGI request ID for this process
        self.flags                    = None                 # flags associated with the current request
        self.params                   = None                 # input parameters to the current request

        self.stdin                    = None                 # FCGI_STDIN
        self.stdout                   = None                 # FCGI_STDOUT
        self.stderr                   = None                 # FCGI_STDERR

        # get the first record and parse from there
        self._read_record()

    # ------------------------------------------------------------------------------------------------------------------

    def allow_persistence (self, status, max_requests = None):
        """
        Set the persistence status.

        @param status       (bool) The persistence status.
        @param max_requests (int)  The maximum persistent requests to serve before the connection will be closed.
        """

        self._is_allowing_persistence = status
        self._maximum_requests        = max_requests

    # ------------------------------------------------------------------------------------------------------------------

    def _read_nv_pair (self, pair):
        # section 3.4 of the protocol might be one of the most retarded things I have ever seen in my life
        if len(pair) < 2:
            raise FastcgiException("Could not decode name-value pair: Input length too small (%d)" % len(pair))

        nll = vll = 1
        if (ord(pair[0]) >> 7) == 1:
            # name is 4 bytes
            if len(pair) < 4 + vl:
                raise FastcgiException("Could not decode name-value pair: Input length too small (%d)" % len(pair))
            nll = 4
        if (ord(pair[nll]) >> 7) == 1:
            # value is 4 bytes
            if len(pair) < 4 + nl:
                raise FastcgiException("Could not decode name-value pair: Input length too small (%d)" % len(pair))
            vll = 4

        offset = nll + vll

        (nl, vl) = NAME_VALUE_PAIR_STRUCTS[(nll, vll)].unpack(pair[:offset])
        nl = NAME_VALUE_PAIR_DECODERS[nll](nl)
        vl = NAME_VALUE_PAIR_DECODERS[vll](vl)
        if len(pair[offset:]) < (nl + vl):
            raise FastcgiException("Could not decode name-value pair: data length too small: " +
                                   "%d (expected %d (%d) + %d (%d) = %d)" % (len(pair[offset:]), nl, vl, nl + vl))

        name = pair[offset:(offset + nl)]
        value = pair[(offset + nl):(offset + nl + vl)]

        return (name, value, offset + nl + vl)

    def _read_nv_pairs (self, data):
        pairs = {}

        while len(data) > 0:
            (name, value, offset) = self._read_nv_pair(data)
            pairs[name] = value
            data = data[offset:]

        return pairs

    # ------------------------------------------------------------------------------------------------------------------

    def _handle_record_get_values (self, header, data):
        requests = self._read_nv_pairs(data)
        responses = {}

        for key in requests.keys():
            if key == FCGI_MAX_CONNS or key == FCGI_MAX_REQS:
                responses[key] = str(self._server.worker_count)
            elif key == FCGI_MPXS_CONNS:
                responses[key] = "1" if self._is_allowing_persistence else "0"

        self._write_record(_GetValuesResultRecord(responses))
        self.flush()

    def _handle_record_unknown_type (self, header, data):
        unknown_type = header["type"]
        self._write_record(_UnknownTypeRecord(unknown_type))
        self.flush()

    # ------------------------------------------------------------------------------------------------------------------

    def handle_dispatch (self):
        raise ClientException("FastcgiClient#handle_dispatch() must be overriden")

    def _maybe_dispatch (self):
        # need both params and stdin to dispatch a request
        if self._has_params and self._has_stdin:
            self.params = self._read_nv_pairs(self._params_io.getvalue())
            self.stdin = self._stdin_io.getvalue()

            self.stdout = _OutputWriter(self, FCGI_STDOUT)
            self.stderr = _OutputWriter(self, FCGI_STDERR)

            self._params_io.close()
            self._params_io = None
            self._has_params = False
            self._stdin_io.close()
            self._stdin_io = None
            self._has_stdin = False

            status = self.handle_dispatch()

            self._write_record(_EndRequestRecord(0 if status is None else status, FCGI_REQUEST_COMPLETE, self.request_id))

            # flush everything at the end of the request; this can result in the connection closing
            self.flush()
        else:
            self._read_record()

    def _handle_record_begin_request (self, header, data):
        request_id = header["request_id"]
        
        if self.request_id:
            # we're already executing a request, so cancel this one
            self._write_record_and_flush(_EndRequestRecord(0, FCGI_CANT_MPX_CONN))

        self.request_id = request_id

        (role, flags) = BEGIN_REQUEST_STRUCT.unpack(data)

        # do we want to keep persistence enabled?
        if flags & FCGI_KEEP_CONN == 0 or (self._maximum_requests and self._handled_requests == self._maximum_requests):
            self._persistence_requested = False
        elif self._maximum_requests and self._handled_requests > self._maximum_requests:
            self._persistence_requested = False
            self._write_record_and_flush(_EndRequestRecord(0, FCGI_OVERLOADED, request_id))
            return

        if role == FCGI_RESPONDER:
            self.flags = flags
            self._params_io = StringIO.StringIO()
            self._has_params = False
            self._stdin_io = StringIO.StringIO()
            self._has_stdin = False

            self._handled_requests += 1

            self._read_record()
        else:
            self._write_record_and_flush(_EndRequestRecord(0, FCGI_UNKNOWN_ROLE, request_id))

    def _handle_record_abort_request (self, header, data):
        # since we execute requests in series within a single client, we can't do anything about this (it will be
        # received after we send the END_REQUEST record anyway)
        self._read_record()

    def _handle_record_params (self, header, data):
        request_id = header["request_id"]

        if request_id != self.request_id:
            return

        if header["content_length"] == 0:
            self._has_params = True
        else:
            self._params_io.write(data)

        self._maybe_dispatch()

    def _handle_record_stdin (self, header, data):
        request_id = header["request_id"]

        if request_id != self.request_id:
            return

        if header["content_length"] == 0:
            self._has_stdin = True
        else:
            self._stdin_io.write(data)

        self._maybe_dispatch()

    # ------------------------------------------------------------------------------------------------------------------

    def _handle_record (self, header, data):
        data = data[:header["content_length"]]

        if header["request_id"] == FCGI_NULL_REQUEST_ID:
            # management records
            if header["type"] == FCGI_GET_VALUES:
                self._handle_record_get_values(header, data)
            else:
                self._handle_record_unknown_type(header, data)

            self._read_record()
        else:
            # request headers
            if header["type"] == FCGI_BEGIN_REQUEST:
                self._handle_record_begin_request(header, data)
            elif header["type"] == FCGI_ABORT_REQUEST:
                self._handle_record_abort_request(header, data)
            elif header["type"] == FCGI_PARAMS:
                self._handle_record_params(header, data)
            elif header["type"] == FCGI_STDIN:
                self._handle_record_stdin(header, data)
            elif header["type"] == FCGI_DATA:
                # there's a fairly good chance that we've already dispatched the request by the time we receive this, so
                # we just won't support it
                pass
            else:
                raise FastcgiException("Unexpected record type %d while trying to handle request", header["type"])

    def _handle_record_header (self, data):
        (version, type, request_id, content_length, padding_length) = HEADER_STRUCT.unpack(data)

        if version != FCGI_VERSION_1:
            raise ClientException("Invalid FastCGI version received in header: %d" % version)

        header = { "type":           type,
                   "request_id":     request_id,
                   "content_length": content_length }

        self.read_length(content_length + padding_length,
                         lambda data: self._handle_record(header, data))    

    def _read_record (self):
        self.read_length(FCGI_HEADER_LEN, self._handle_record_header)

    # ------------------------------------------------------------------------------------------------------------------

    def _write_record (self, record):
        record.write(self)

        if isinstance(record, _EndRequestRecord):
            self.request_id = FCGI_NULL_REQUEST_ID

            if self._is_allowing_persistence and self._persistence_requested:
                self.clear_write_buffer()
                self._read_record()
            else:
                self._events &= ~EVENT_READ

    def _write_record_and_flush (self, record):
        self._write_record(record)
        self.flush()

    def handle_write_finished (self):
        # if we're no long reading events, and we just flushed the write buffer, then clear all events so the socket
        # shuts down
        if self._events & EVENT_READ == 0:
            self.clear_events()

# ----------------------------------------------------------------------------------------------------------------------

class FastcgiServer (Server):

    def __init__ (self, **kwargs):
        """
        Creates a new FastcgiServer instance.
        """

        Server.__init__(self, **kwargs)

    def handle_client (self, client_socket, client_address, server_address):
        """
        Registers a new FastcgiClient instance.

        @param client_socket  (socket) The client socket.
        @param client_address (tuple)  A two-part tuple containing the client ip and port.
        @param server_address (tuple)  A two-part tuple containing the server ip and port to which the client has
                                       made a connection.
        """

        raise NotImplementedError("FastcgiServer#handle_client() must be overridden")

    def handle_exception (self, exception, client = None):
        """
        Handles an unexpected exception that occurs during client processing.

        @param exception (Exception)     The exception raised.
        @param client    (FastcgiClient) The client instance that generated the exception.
        """

        Server.handle_exception(self, exception, client)

        if not client or not client.request_id:
            return

        client._write_record(_StreamRecord(FCGI_STDERR, "Could not process request: Internal error", client.request_id))
        client._write_record_and_flush(_EndRequestRecord(1, FCGI_REQUEST_COMPLETE, client.request_id))
