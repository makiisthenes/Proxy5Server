# 04/07/2022 Michael Peres.
# Socks5 Proxy Server in Python.


# Python Sockets Module
# Based on Doc  | https://docs.python.org/3/library/socket.html
# Based on Site | https://www.tutorialspoint.com/python_network_programming/python_sockets_programming.htm

# Python Select Module
# Based on Doc  | https://docs.python.org/3/library/select.html



# RFCs used for reference

# SOCKS Protocol Version 5
# Based on RFC 1928 | https://www.rfc-editor.org/rfc/rfc1928

# Username/Password Authentication for SOCKS V5
# Based on RFC 1929 | https://www.rfc-editor.org/rfc/rfc1929

# GSS-API Authentication Method for SOCKS Version 5
# Based on RFC 1961 | https://www.rfc-editor.org/rfc/rfc1961

# Assigned Numbers
# Based on RFC 1700 | https://www.rfc-editor.org/rfc/rfc1700


import socket
import threading
import select
import netifaces
import requests


# Socks5 Format:
# socks5://user:pass@host:port
def socks5_format(username, password, host, port):
    return "socks5://{}:{}@{}:{}".format(username, password, host, port)


def get_ip_address():
    ip_addresses = [netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr'] for iface in netifaces.interfaces() if
                    netifaces.AF_INET in netifaces.ifaddresses(iface)]
    ip_address = [ip for ip in ip_addresses if ip.startswith("192.168.1.")]
    if ip_address:
        return ip_address[0]
    else:
        print("[WARNING] - Can only run locally.")
        return "localhost"


def parse_incorrect_values(value):
    """ Running on raspberry pi sometimes gives random errors which doesnt format value received in the way we want it."""
    if type(value) == int:
        print("not incorrect", value)
        return value
    try:
        return int.from_bytes(value, 'big', signed=False)
    except Exception as e:
        print("Error parsing incorrect values:", e, value)
        return value

class ProxyServer:
    def __init__(self, host=None, port=10696, username=None, password=None, max_clients=3, secure=True):
        self.socks_version = 5
        self.secure = secure
        if not host:
            self.host = get_ip_address()
        else:
            self.host = host
        self.port = port
        self.username = ""
        self.password = ""

        if username and password:
            self.username = username
            self.password = password
        else:
            self.username = ""
            self.password = ""

        self.max_clients = max_clients
        if not self.secure:
            self.methods_supported = [0x00, 0x02, 0xFF]  # No auth, username/password.
        elif self.secure:
            self.methods_supported = [0x02, 0xFF]  # username/password only.

        # Initialise
        self.sock = None
        self.start_server()

    def start_server(self):
        # Initialising proxy server.
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((self.host, self.port))
        self.sock.listen(self.max_clients)
        print(f"[INFO] - Listening on {self.host}:{self.port}")

        # Start listening for connections.
        while True:
            client_socket, address = self.sock.accept()
            print(f"[INFO] - Client connected from {address}")
            threading.Thread(target=self.proxy_connection_thread, args=(client_socket,)).start()

    def proxy_connection_thread(self, client_socket):

        # Handshake with client.
        # The client connects to the server, and sends a version identifier/method selection message:
        #  +----+----------+----------+
        #  |VER | NMETHODS | METHODS  |
        #  +----+----------+----------+
        #  | 1  |    1     | 1 to 255 |
        #  +----+----------+----------+
        version, nmethods = client_socket.recv(2)

        # print("N Methods: ", nmethods)
        # print("Version: ", version)
        if version != 5:
            print("[ERROR] - Version is not 5.")
            client_socket.close()
            return
        if nmethods == 0:
            print("[ERROR] - Client doesn't support any methods!.")
            client_socket.close()
            return

        # Method Numbers (in Octets):
        # X'00' NO AUTHENTICATION REQUIRED
        # X'01' GSSAPI
        # X'02' USERNAME/PASSWORD
        # X'03' to X'7F' IANA ASSIGNED
        # X'80' to X'FE' RESERVED FOR PRIVATE METHODS
        # X'FF' NO ACCEPTABLE METHODS


        methods = [ord(client_socket.recv(1)) for _ in range(nmethods)]
        # print("Methods: ", methods)


        if not self.username and not self.password:
            if 0x00 in methods:
                client_socket.send(bytes([5, 0x00]))
                print("[INFO] - No authentication required.")
            else:
                print("[ERROR] - Username/Password was not found.")
                client_socket.close()
                return

        elif 0x02 in methods:
            client_socket.send(bytes([5, 0x02]))  # Send accepting username/password authentication.
            # print("[INFO] - Username/Password authentication required.")

            # +----+------+----------+------+----------+
            # |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
            # +----+------+----------+------+----------+
            # | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
            # +----+------+----------+------+----------+

            version = parse_incorrect_values(client_socket.recv(1))  # This should be X'01'

            username_len = parse_incorrect_values(client_socket.recv(1))

            username = client_socket.recv(username_len).decode('utf-8')

            password_len = parse_incorrect_values(client_socket.recv(1))
            password = client_socket.recv(password_len).decode('utf-8')

            if username == self.username and password == self.password:
                print("[INFO] - Username/Password authentication successful.")

                # +----+--------+
                # |VER | STATUS |
                # +----+--------+
                # | 1  |   1    |
                # +----+--------+

                client_socket.send(bytes([1, 0x00]))

            else:
                print("[ERROR] - Username/Password authentication failed.")
                client_socket.send(bytes([1, 0x01]))
                client_socket.close()
                return

            # Requests
            # Once the method-dependent sub-negotiation has completed, the client
            # sends the request details.
            # +----+-----+-------+------+----------+----------+
            # |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
            # +----+-----+-------+------+----------+----------+
            # | 1  |  1  | X'00' |  1   | Variable |    2     |
            # +----+-----+-------+------+----------+----------+

            request_protocol_version = parse_incorrect_values(client_socket.recv(1))
            # CMD Types:
            # o  CONNECT X'01'
            # o  BIND X'02'
            # o  UDP ASSOCIATE X'03'

            request_cmd = parse_incorrect_values(client_socket.recv(1))
            request_reserve = parse_incorrect_values(client_socket.recv(1))
            request_address_type = parse_incorrect_values(client_socket.recv(1))

            # Address Types:
            # o  IP V4 address: X'01'
            # o  DOMAINNAME: X'03'
            # o  IP V6 address: X'04'

            ip_address = None

            if request_address_type == 1:
                # IPv4 Address Found.

                #  socket.inet_ntoa(packed_ip)
                #
                #     Convert a 32-bit packed IPv4 address (a bytes-like object four bytes in length)
                #     to its standard dotted-quad string representation (for example, ‘123.45.67.89’).
                #     This is useful when conversing with a program that uses the standard C library
                #     and needs objects of type struct in_addr,
                #     which is the C type for the 32-bit packed binary data this function takes as an argument.
                #     If the byte sequence passed to this function is not exactly 4 bytes in length,
                #     OSError will be raised. inet_ntoa() does not support IPv6,
                #     and inet_ntop() should be used instead for IPv4/v6 dual stack support.



                ip_address = socket.inet_ntoa(client_socket.recv(4))
                print(f"[Request] IPv4: {ip_address}")

            elif request_address_type == 3:
                print("[INFO] Client is using remote DNS.")
                # Domain Name Found.
                domain_name_len = parse_incorrect_values(client_socket.recv(1))
                domain_name = client_socket.recv(domain_name_len)
                print(f"[Request] Domain Name: {domain_name}")
                ip_address = socket.gethostbyname(domain_name)  # Convert domain_name to ip_address. If using REMOTE DNS.
                print(f"[Request] IP Address: {ip_address}")

            elif request_address_type == 4:
                # IPv6 Address Found.
                ip_address = socket.inet_ntop(socket.AF_INET6, client_socket.recv(16))
                print(f"[Request] IPv6: {ip_address} ")


            if ip_address is None:
                print("[ERROR] - IP Address is None.")
                client_socket.close()
                return


            # +----+-----+-------+------+----------+----------+




            # DST.PORT desired destination port in network octet order. RFC 1700 defines the format to be Big Endian.
            # Given the range a port number is 0-2^16 it cannot be negative and thus unsigned.
            request_port = int.from_bytes(client_socket.recv(2), 'big', signed=False)
            print(f"[PORT]: {request_port}")

            # Replies
            # The SOCKS request information is sent by the client as soon as it has
            # established a connection to the SOCKS server, and completed the
            # authentication negotiations.  The server evaluates the request, and
            # returns a reply formed as follows:

            # +----+-----+-------+------+----------+----------+
            # |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
            # +----+-----+-------+------+----------+----------+
            # | 1  |  1  | X'00' |  1   | Variable |    2     |
            # +----+-----+-------+------+----------+----------+

            try:
                if not request_cmd == 1:
                    print("[ERROR] - Unknown/unsupported request command.")
                    client_socket.close()
                    return

                else:
                    # Connect Option of the SOCKS protocol.
                    # The SOCKS server will typically evaluate the request based on source
                    # and destination addresses, and return one or more reply messages, as
                    # appropriate for the request type.

                    # Now we have been given a destination address and port that wants to be connected to,
                    # We will create a socket for this and then start acting as a proxy between user and target host.

                    # Depending on whether it is IPv4 or IPv6, we will create a socket accordingly.

                    # We are creating a low level socket interface specifying the transport protocol.
                    # We are using the SOCK_STREAM for TCP and SOCK_DGRAM for UDP.

                    if request_address_type == 4:
                        # Error: A socket operation was attempted to an unreachable host
                        pass
                        """
                        # IPv6 Address Found.
                        target_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                        target_socket.connect((ip_address, request_port))
                        print(f"[INFO] - Connected to {ip_address}:{request_port} via type: {request_address_type}")

                        """

                    else:
                        target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        target_socket.connect((ip_address, request_port))
                        print(f"[INFO] - Connected to {ip_address}:{request_port} via type: {request_address_type}")

                    # We need internal IP and port of current connection.

                    local_ip, local_port = target_socket.getsockname()
                    # +----+-----+-------+------+----------+----------+

                    # Need to convert IP address string into 32 bits integer.
                    if request_address_type == 4:
                        local_ip_int = socket.inet_pton(socket.AF_INET6, local_ip)
                        address_type = 0x04
                    else:
                        local_ip_int = socket.inet_aton(local_ip)
                        address_type = 0x01

                    print(f"[INFO] - Local IP Bytes: {local_ip_int}")

                    # Send success reply.
                    success_reply = b''.join([
                        self.socks_version.to_bytes(1, "big"),  # Protocol Version.
                        0x00.to_bytes(1, 'big'),  # Reply Code.
                        0x00.to_bytes(1, 'big'),  # Reserved.
                        address_type.to_bytes(1, 'big'),  # Address Type.
                        local_ip_int,  # IP Address.
                        local_port.to_bytes(2, 'big')  # Port number.

                    ])

                    print(f"[INFO] - Sending success reply. {success_reply}")

                    client_socket.sendall(success_reply)



                    # Given we have successfully connected to the remote, and we have successfully connected to host,
                    # We are ready to exchange data.

                    # Start forwarding data.
                    self.forward_data(client_socket, target_socket)

            except Exception as e:
                # Connection Refused for some reason.
                print(f"[ERROR] Connection Refused - {e}")
                # Reply options.
                # o REP Reply field:
                #   o  X'00' succeeded
                #   o  X'01' general SOCKS server failure
                #   o  X'02' connection not allowed by ruleset
                #   o  X'03' Network unreachable
                #   o  X'04' Host unreachable
                #   o  X'05' Connection refused
                #   o  X'06' TTL expired
                #   o  X'07' Command not supported
                #   o  X'08' Address type not supported
                #   o  X'09' to X'FF' unassigned

                error_reply = b''.join([
                    self.socks_version.to_bytes(1, 'big'),  # Protocol version.
                    0x05.to_bytes(1, 'big'),  # Reply code.
                    0x00.to_bytes(1, 'big'),  # Reserved.
                    0x01.to_bytes(1, 'big'),  # Address type.
                    0x00.to_bytes(4, 'big'),  # IPV4 Address.
                    0x00.to_bytes(2, 'big'),  # Port.
                ])

                # Blocking recursive function of client_socket.send().
                client_socket.sendall(error_reply)



    def forward_data(self, client, target):
        """ Reading and writing data from/to client and target socket. """

        # Heavy reliance on reading documentation for socket interface and understanding how to use it.

        #  select.select(rlist, wlist, xlist[, timeout])
        #
        #     This is a straightforward interface to the Unix select() system call. The first three arguments are iterables of ‘waitable objects’: either integers representing file descriptors or objects with a parameterless method named fileno() returning such an integer:
        #
        #         rlist: wait until ready for reading
        #
        #         wlist: wait until ready for writing
        #
        #         xlist: wait for an “exceptional condition” (see the manual page for what your system considers such a condition)
        #
        #     Empty iterables are allowed, but acceptance of three empty iterables is platform-dependent. (It is known to work on Unix but not on Windows.)
        #     The optional timeout argument specifies a time-out as a floating point number in seconds. When the timeout argument is omitted the function blocks until at least one file descriptor is ready.
        #     A time-out value of zero specifies a poll and never blocks.
        #
        #     The return value is a triple of lists of objects that are ready: subsets of the first three arguments.
        #     When the time-out is reached without a file descriptor becoming ready, three empty lists are returned.
        #
        #     Among the acceptable object types in the iterables are Python file objects (e.g. sys.stdin, or objects returned by open() or os.popen()),
        #     socket objects returned by socket.socket(). You may also define a wrapper class yourself,
        #     as long as it has an appropriate fileno() method (that really returns a file descriptor, not just a random integer).

        # This function can take socket object and wait for when they are ready to be read from aka received data in its buffer.
        # We will use select.select() to wait for when the socket is ready to be read from.

        print("[INFO] - Starting to exchange data.")

        while True: # Run forever until we see a socket has closed.
            # Wait for client socket to be ready to be read from.
            rlist, wlist, xlist = select.select([client, target], [], [])


            # Check if client socket is ready to be read from and send to target remote host.
            if client in rlist:
                # Read data from client socket, the client is not allowed to send more than 4096 bytes, using a SOCKS5 proxy.
                data = client.recv(4096)

                if data == 0:
                    # Client socket has closed.
                    break

                else:
                    target.send(data)



            # Check if target socket is ready to be read from and send to client host.
            if target in rlist:
                # Read data from target socket.
                data = target.recv(4096)
                # Write data to client socket.
                if client.send(data) <= 0:
                    # Socket has closed.
                    break



# Util functions.
def get_public_ip():
    """ Get current public ip for network."""
    # Get public ip for network.
    ip = requests.get('https://api.ipify.org').text
    return ip


def get_pi_temp():
    """ Return CPU temp of Raspberry Pi to 1 decimal point."""
    import gpiozero as gz
    cpu_temp = gz.CPUTemperature().temperature
    cpu_temp = round(cpu_temp, 1)
    print(f"CPU Temp: {cpu_temp} C")
    return cpu_temp


def get_pi_cpu_usage():
    """ Return CPU usage of Raspberry Pi to 1 decimal point."""
    import psutil
    cpu_usage = psutil.cpu_percent()
    cpu_usage = round(cpu_usage, 1)
    print(f"CPU Usage: {cpu_usage} %")
    return cpu_usage


def status_format_string():
    """ Format status string including public ip, current time, pi temp and pi cpu usage. """
    # Get current time.
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # Get public ip.
    public_ip = get_public_ip()
    # Get pi temp.
    pi_temp = get_pi_temp()
    # Get pi cpu usage.
    pi_cpu_usage = get_pi_cpu_usage()
    # Format status string.
    status_string = f"{current_time} - {public_ip} - {pi_temp} C - {pi_cpu_usage} %"
    return status_string




if __name__ == "__main__":

    print("Running Proxy5 script. ")
    ProxyServer(username="maki", password="password", port=10696).run()


