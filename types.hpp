#include <iostream>
#include <stdio.h>
#include <fstream>
#include <sstream>
#include <vector>
#include <sys/socket.h>
#include <cerrno>
#include <cstdlib>
#include <netinet/in.h>
#include <cstring>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netdb.h>
#include <unistd.h>

constexpr unsigned int myTrue  = 1;
constexpr unsigned int myFalse = 0;
constexpr unsigned int tablesize = 100;
using key_value = std::pair<unsigned int, unsigned int>;

struct Put_Forward_msg
{
    unsigned int k;
    std::string IPAddress;
    unsigned int portNumber;
};

enum class messageIDs
{
    PUT_FORWARD,
    WHAT_X,
    PUT_REPLY_X
};

struct node
{
	int data;
	struct node *link;
};

struct machine_id
{
	char *ip_address;
	int tcpportno;
	int udpportno;
} node[20];

struct HTEntry
{
	int data;
	struct node *link;
};

struct HTEntry Htable[tablesize];
