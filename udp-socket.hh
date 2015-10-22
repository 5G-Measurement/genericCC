#ifndef UDP_SOCKET_HH
#define UDP_SOCKET_HH

#include <string>

#include <netinet/in.h>
#include <sys/poll.h>
#include <sys/socket.h>

class UDPSocket{
public:
	typedef sockaddr_in SockAddress;
private:
	int udp_socket;

	std::string ipaddr;
	int port;

	bool bound;
public:
	UDPSocket() : udp_socket(-1), ipaddr(), port(), bound(false) {
		udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
	}

	int bindsocket(std::string ipaddr, int port, std::string myaddr, int myport);
	int bindsocket(int port);
	// Sends data to the desired address. Returns number of bytes sent if
	// successful, -1 if not.
	ssize_t senddata(const char* data, ssize_t size, SockAddress *s_dest_addr);
	ssize_t senddata(const char* data, ssize_t size, std::string dest_ip, int dest_port);
	// Modifies buffer to contain a null terminated string of the received 
	// data and returns the received buffer size (or -1 or 0, see below)
	//
	// Takes timeout in milliseconds. If timeout, returns -1 without 
	// changing the buffer. If data arrives before timeout, modifies buffer
	// with the received data and returns the places the sender's address
	// in other_addr
	// 
	// If timeout is negative, infinite timeout will be used. If it is 0,
	// function will return immediately. Timeout will be rounded up to 
	// kernel time granularity, and kernel scheduling delays may cause 
	// actual timeout to exceed what is specified
	int receivedata(char* buffer, int bufsize, int timeout, SockAddress &other_addr);

	static void decipher_socket_addr(SockAddress addr, std::string& ip_addr, int& port);
	static std::string decipher_socket_addr(SockAddress addr);
};

#endif