# tcp-flow-control

This is an implementation of the sliding window protocol used for TCP using
the socket library in Python. The client (in `client.py`) sends packets and
the server (in `server.py`) receives packets and send acknowledgements to the
client. The client and server interact using a low-level protocol (in `llp.py`); the `LLPEndpoint` classes exposes
a basic API for sending and receiving packets.

The sliding window protocol itself is implemented in `swp.py`. The sender side is responsible for transmitting packets, ensuring that the number of in-flight packets remains within a fixed bound and retransmitting packets 
if an acknowledgement is not received within a specified
time-frame. The receiver side is responsible for sending cumulative acknowledgemnts (ACKs).


#### Running the tool

To run the protocol, start the server in one terminal window using:

````./server.py -p PORT````

where `PORT` needs to be >= 1024.

Then, start the client in another terminal window:

````./client.py -p PORT -h 127.0.0.1````

Whatever you now type in the client window should be transmitted to the server, and you should see the the server
printing the received packets and sending acknowledgements.