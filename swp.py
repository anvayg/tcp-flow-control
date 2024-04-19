from collections import OrderedDict
import enum
import logging
import llp
import queue
import struct
import threading

class SWPType(enum.IntEnum):
    DATA = ord('D')
    ACK = ord('A')

class SWPPacket:
    _PACK_FORMAT = '!BI'
    _HEADER_SIZE = struct.calcsize(_PACK_FORMAT)
    MAX_DATA_SIZE = 1400 # Leaves plenty of space for IP + UDP + SWP header 

    def __init__(self, type, seq_num, data=b''):
        self._type = type
        self._seq_num = seq_num
        self._data = data

    @property
    def type(self):
        return self._type

    @property
    def seq_num(self):
        return self._seq_num
    
    @property
    def data(self):
        return self._data

    def to_bytes(self):
        header = struct.pack(SWPPacket._PACK_FORMAT, self._type.value, 
                self._seq_num)
        return header + self._data
       
    @classmethod
    def from_bytes(cls, raw):
        header = struct.unpack(SWPPacket._PACK_FORMAT,
                raw[:SWPPacket._HEADER_SIZE])
        type = SWPType(header[0])
        seq_num = header[1]
        data = raw[SWPPacket._HEADER_SIZE:]
        return SWPPacket(type, seq_num, data)

    def __str__(self):
        return "%s %d %s" % (self._type.name, self._seq_num, repr(self._data))

class SWPSender:
    _SEND_WINDOW_SIZE = 5
    _TIMEOUT = 1

    def __init__(self, remote_address, loss_probability=0):
        self._llp_endpoint = llp.LLPEndpoint(remote_address=remote_address,
                loss_probability=loss_probability)

        # Start receive thread
        self._recv_thread = threading.Thread(target=self._recv)
        self._recv_thread.start()

        # Sliding Window variables
        self._last_ack_received = 0     # LAR
        self._last_frame_sent = 0       # LFS
        self._last_frame_written = 0

        # Initialize bounded semaphore with value of SWS
        self._send_window_not_full = threading.BoundedSemaphore(value=self._SEND_WINDOW_SIZE)

        # Buffer for retransmission: maps from sequence number to a (data, timer) pair
        self._buffer = {}

        # Lock to ensure only one thread accesses the buffer at a time
        self._lock = threading.Lock()

    def send(self, data):
        for i in range(0, len(data), SWPPacket.MAX_DATA_SIZE):
            self._send(data[i:i+SWPPacket.MAX_DATA_SIZE])

    def _send(self, data):
        # Wait for free space in the sender window
        self._send_window_not_full.acquire()

        # Assign data a sequence number and increment LFS
        seq_num = self._last_frame_sent + 1
        self._last_frame_sent = seq_num

        # Add data and timer to buffer (but don't start timer yet)
        timer = threading.Timer(self._TIMEOUT, self._retransmit, [seq_num])
        self._lock.acquire()
        self._buffer[seq_num] = (data, timer)
        logging.debug("Buffer (send): %s" % self._buffer)

        # Construct packet and send data
        packet = SWPPacket(SWPType.DATA, seq_num, data)
        bytes = packet.to_bytes()
        self._llp_endpoint.send(bytes)
        self._lock.release()
        logging.debug("Sending packet with seq_num: %s" % seq_num)

        # Start timer to call retransmit
        timer.start()

        return
        
    def _retransmit(self, seq_num):
        # Re-send packet
        logging.debug("Trying to retransmit packet with seq_num: %s" % seq_num)
        self._lock.acquire()
        (data, timer) = self._buffer.get(seq_num)
        packet = SWPPacket(SWPType.DATA, seq_num, data)
        bytes = packet.to_bytes()
        self._llp_endpoint.send(bytes)
        self._lock.release()
        logging.debug("Re-transmitting packet with seq_num: %s" % seq_num)

        # Start timer to call retransmit
        timer = threading.Timer(self._TIMEOUT, self._retransmit, [seq_num])
        timer.start()

        return 

    def _recv(self):
        while True:
            # Receive SWP packet
            raw = self._llp_endpoint.recv()
            if raw is None:
                continue
            packet = SWPPacket.from_bytes(raw)
            logging.debug("Received: %s" % packet)

            # Check that packet is of type ACK
            if packet.type != SWPType.ACK: continue

            # Check that the seq num is in the buffer (if it is not, we removed it earlier)
            seq_num = packet.seq_num
            if not (seq_num in self._buffer): continue

            # Cancel retransmission timer
            self._lock.acquire()
            (_, timer) = self._buffer.get(seq_num)
            timer.cancel()
            self._lock.release()

            # Update LAR
            current_last_ack = self._last_ack_received
            self._last_ack_received = seq_num
            logging.debug("Received ACK with seq_num: %s" % seq_num)

            # Discard data from buffer
            self._lock.acquire()
            self._buffer = {k:v for k, v in self._buffer.items() if k > seq_num}
            logging.debug("Buffer(receive): %s" % self._buffer)
            self._lock.release()

            # Update send window semaphore
            for i in range(current_last_ack, seq_num):
                self._send_window_not_full.release()

        return

class SWPReceiver:
    _RECV_WINDOW_SIZE = 5

    def __init__(self, local_address, loss_probability=0):
        self._llp_endpoint = llp.LLPEndpoint(local_address=local_address, 
                loss_probability=loss_probability)

        # Received data waiting for application to consume
        self._ready_data = queue.Queue()

        # Start receive thread
        self._recv_thread = threading.Thread(target=self._recv)
        self._recv_thread.start()
        
        # State variables
        self._last_acceptable_frame = 0 + self._RECV_WINDOW_SIZE
        self._last_frame_recd = 0

        # Buffer in case out of order
        self._buffer = OrderedDict()

    def recv(self):
        return self._ready_data.get()

    def _recv(self):
        while True:
            # Receive data packet
            raw = self._llp_endpoint.recv()
            packet = SWPPacket.from_bytes(raw)
            logging.debug("Received: %s" % packet)

            # Check if outside window (ignore if so)
            seq_num = packet.seq_num
            if seq_num <= self._last_frame_recd or seq_num > self._last_acceptable_frame:
                continue

            # Retransmit ack for LFR
            ack_packet = SWPPacket(SWPType.ACK, self._last_frame_recd)
            bytes = ack_packet.to_bytes()
            self._llp_endpoint.send(bytes)

            # Add to buffer
            self._buffer[seq_num] = packet.data
            logging.debug("Buffer in receiver: %s" % self._buffer)

            # Traverse buffer to find seq_num to acknowledge
            i = self._last_frame_recd + 1
            seq_num_to_ack = self._last_frame_recd
            while True:
                if i in self._buffer:
                    seq_num_to_ack = i
                    i = i + 1
                else:
                    break

            # Remove chunks of data from buffer and enqueue them
            new_buffer = {}
            for k, v in self._buffer.items():
                if k <= seq_num_to_ack:
                    self._ready_data.put(v)
                else:
                    new_buffer[k] = v

            self._buffer = new_buffer
            logging.debug("New buffer in receiver: %s" % self._buffer)

            # Update LFR and LAR
            self._last_frame_recd = seq_num_to_ack
            self._last_acceptable_frame = self._last_frame_recd + self._RECV_WINDOW_SIZE

            # Send ack
            ack_packet = SWPPacket(SWPType.ACK, self._last_frame_recd)  # LFR has been updated already
            bytes = ack_packet.to_bytes()
            self._llp_endpoint.send(bytes)
            logging.debug("Sending ACK with seq_num: %s" % seq_num_to_ack)

        return
