#include "types.hpp"

const unsigned int N = 6;
const std::string filePath = "table";
std::vector<key_value> hashTable;
std::vector<std::string> nodeParameters;
std::vector<std::string> nextNodeParameters;
// ============================================================================//
int masterSocketFD, socketUDP, maxFD, new_socket;
struct sockaddr_in address, serverAddrUDP, clientAddr;
unsigned int addr_len, addrlen;
int transferValue = 0;
char buffer[1024], replyBuffer[1024];
fd_set readfds;
int num = 1;

// ============================================================================//
unsigned int algorithm(unsigned int k)
{
    return (k % N) + 1;
}

void printHashTable()
{
    for (auto i : hashTable)
    {
        std::cout << "Key:" << i.first << "Value:" << i.second << std::endl;
    }
}

int extractKeyFromPut(char request[]) // method for extracting key from put request.
{

    char *b = strstr(request, "("), *c = strstr(request, ",");
    int position = b - request, position1 = c - request, k;
    char to[4];
    strncpy(to, request + position + 1, position1 - position); // for extracting the first integer no. k of put(k,x)

    k = atoi(to); // converting to int
    fflush(stdout);
    return k;
}

int extractKeyFromGet(char request[]) // method for extracting key from get request.
{

    char *b = strstr(request, "("), *c = strstr(request, ")");
    int position = b - request, position1 = c - request, k;
    char to[4];
    strncpy(to, request + position + 1, position1 - position); // for extracting the first integer no. k of put(k,x)
    k = atoi(to);
    fflush(stdout);
    return k;
}

int extractValueFromPut(char request[])
{

    char *b = strstr(request, ","), *c = strstr(request, ")");
    int position = b - request, position1 = c - request, k;
    char to[16];
    memset(to, 0, 16);
    strncpy(to, request + position + 1, position1 - position); // for extracting the first integer no. k of put(k,x)
    k = atoi(to);
    return k;
}

void itoa(int n, char buff[])
{
    int i = 0, j;

    if (n == 0)
    {

        buff[0] = '0';
        buff[1] = '\0';
        i = 1;
    }

    while (n > 0)
    {

        int rem = n % 10;
        n = n / 10;
        buff[i] = rem + 48;
        i++;
    }

    buff[i] = '\0';

    for (j = 0; j < i / 2; j++)
    {

        char temp = buff[j];
        buff[j] = buff[i - j - 1];
        buff[i - j - 1] = temp;
    }
}

char *extractIpaddress(char *buff, char a, char b)
{

    char *ptr = (char *)malloc(20);
    int i = 0, j = 0;

    while (buff[i] != a)
    {
        i++;
    }
    i = i + 1;

    while (buff[i] != b)
    {

        ptr[j++] = buff[i];
        i++;
    }
    ptr[j] = '\0';
    return ptr;
}

int getOrPut(char rec_buff[]) // method to check  whether put or get request.
{

    if (rec_buff[0] == 'g' || rec_buff[0] == 'G')
        return 1;
    else
        return 0;
}

int forYou(int num, char request[]) // check whether request is for current node or not
{

    int k;
    if (getOrPut(request) == 1) // check whether request is get or put

        k = extractKeyFromGet(request);
    else
        k = extractKeyFromPut(request);

    if ((k % N) == num)

        return 1; // return 1 if for current node
    else
        return 0; // return 0 if not for current node
}

int extractNodeno(char *buff)
{

    char *nodeno = extractIpaddress(buff, ')', '[');
    return atoi(nodeno);
}

int readfile(std::string filePath, unsigned int nodeNumber)
{
    std::fstream file(filePath, std::ios::in | std::ios::out);
    std::string nodeName = 'N' + std::to_string(nodeNumber);
    std::string nextNodeName = "N1";
    bool activated = 0;
    unsigned int pos = 0;

    if (!file.is_open())
    {
        std::cerr << "Error: Could not open the file " << filePath << std::endl;
        return -1;
    }
    std::string line;

    while (std::getline(file, line))
    {
        size_t found = line.find(nodeName);
        if (found != std::string::npos)
        {
            pos = file.tellg() - std::streampos(line.length() - found);
            break;
        }
    }

    // Node parameters
    std::istringstream iss(line);
    std::string param;

    while (iss >> param)
    {
        nodeParameters.push_back(param);
    }

    // check current node status
    activated = std::stoi(nodeParameters[1]);

    if (activated == 0)
    {
        file.clear();
        file.seekp(pos + 2);
        file << "1";
    }
    else
    {
        std::cout << "Node already started before" << std::endl;
    }

    // Next Node parameters
    if (nodeParameters[0].compare("N6"))
    {
        unsigned int nodeNumber = static_cast<int>(nodeParameters[0].back() - '0');
        nextNodeName = 'N' + std::to_string(nodeNumber + 1);
        std::cout << "next node: " << nextNodeName << std::endl;
    }

    // find next node data
    while (std::getline(file, line))
    {
        size_t found = line.find(nextNodeName);
        if (found != std::string::npos)
        {
            pos = file.tellg() - std::streampos(line.length() - found);
            break;
        }
    }
    iss.clear();
    param.clear();
    iss.str(line);

    while (iss >> param)
    {
        nextNodeParameters.push_back(param);
    }

    file.close();
    return 0;
}

void forwardUDP(int destination_node, char sendString[])
{

    destination_node = destination_node % N; // destination node to which data is to be forwaded
    int sock;
    struct sockaddr_in server_addr;

    struct hostent *host;                                                      // hostent predefined structure use to store info about host
    host = (struct hostent *)gethostbyname(node[destination_node].ip_address); // gethostbyname returns a pointer to hostent
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    {
        perror("socket");
        exit(1);
    }

    // destination address structure
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(node[destination_node].udpportno);
    server_addr.sin_addr = *((struct in_addr *)host->h_addr); // host->h_addr gives address of host
    bzero(&(server_addr.sin_zero), 8);
    sendto(sock, sendString, strlen(sendString), 0, (struct sockaddr *)&server_addr, sizeof(struct sockaddr));

    // sendto() function shall send a message through a connectionless-mode socket.
    printf("\nFORWARD REQUEST : '%s' has been forwarded to node ---->%d\n", sendString, destination_node);
    close(sock);
}

char *forwardedData(char inputbuff[], char flag) // Called to prepare data to be forwaded to next node
{

    int key, tcpportno;
    char keybuff[5], portbuff[5], fl[2];
    fl[0] = flag;
    fl[1] = '\0';
    char *outputbuff = (char *)malloc(sizeof(char) * 40), nodebuff[3];

    if (getOrPut(inputbuff) == 1)
        key = extractKeyFromGet(inputbuff); // extract key from data get before preparing sending data
    else
        key = extractKeyFromPut(inputbuff); // extract key from data get before preparing sending data

    tcpportno = node[num].tcpportno;

    itoa(tcpportno, portbuff); // convert integer port number to character array

    itoa(key, keybuff); // convert integer key to character array

    strcpy(outputbuff, "xxx("); // start forwarding data with xxx(

    strcat(outputbuff, keybuff);

    strcat(outputbuff, ",");

    strcat(outputbuff, portbuff);

    strcat(outputbuff, ")");

    itoa(num, nodebuff); // convert integer node number to character array

    strcat(outputbuff, nodebuff);

    strcat(outputbuff, "[");

    strcat(outputbuff, node[num].ip_address);

    strcat(outputbuff, ",");

    strcat(outputbuff, fl);

    strcat(outputbuff, "]");

    outputbuff[strlen(outputbuff) + 1] = '\0'; // end

    return outputbuff; // return the address of data in memory which is to be forwaded
}

int fetchValueFromHT(int key) // fun() to retrieve value corresponding to a key from hash table
{

    int relativeIndex = (key - num) / N, return_value; // calculate index of key  in hash table

    if (Htable[relativeIndex].link == NULL) // first value in the list
        return_value = Htable[relativeIndex].data;

    else
    {
        struct node *start = Htable[relativeIndex].link;
        while (start->link != NULL)
            start = start->link;    // progess pointer to last element
        return_value = start->data; // assign last element
    }
    return return_value;
}

void initialiseHashtable()
{

    int i = 0;

    for (i = 0; i < tablesize; i++)
    {
        Htable[i].data = 0;
        Htable[i].link = NULL;
    }
}

void appendNode(struct node *start, int data)
{

    while (start->link != NULL)
    {

        start = start->link;
    }
    start->link = (struct node *)malloc(sizeof(struct node));
    start = start->link;
    start->link = NULL;
    start->data = data;
}

int addToHashtable(int key, int data)
{

    int maxlimit_key = (tablesize - 1) * N + num;
    int relativeIndex, returnvalue;

    if (key % N == num && key <= maxlimit_key && key > -1)
    {
        // Key must satisfy the eqn K % N = num then only its for current node

        relativeIndex = (key - num) / N;

        // case 1 : if hash table entry is empty

        if (Htable[relativeIndex].data == 0)
        {

            Htable[relativeIndex].data = data;
            returnvalue = 1;
        }

        // case 2 : if exactly one entry in particular entry of hashtable (Ist Collision)

        else if (Htable[relativeIndex].data != 0 && Htable[relativeIndex].link == NULL)
        {

            Htable[relativeIndex].link = (struct node *)malloc(sizeof(struct node));
            Htable[relativeIndex].link->data = data;
            Htable[relativeIndex].link->link = NULL;
            returnvalue = 1;
        }

        // case 3: Subsequent Collisions

        else
        {
            appendNode(Htable[relativeIndex].link, data);
            returnvalue = 1;
        }

        std::cout << "\nRESULT: AT KEY : " << key << ", VALUE INSERTED : " << data << " IN HASH TABLE SUCCESS\nENTER NEW GET/PUT REQUEST :";
    }

    else
    {
        std::cout << "\nERROR:KEY = " << key << ",VALUE = " << data << " CANNOT ADD IN TABLE, MAX KEY LIMIT = " << maxlimit_key << "\nENTER NEW GET/PUT 				REQUEST :", key, data, maxlimit_key;

        returnvalue = 0;
    }
    return returnvalue;
}
// ============================================================================//
void initSocket()
{
    int ret = 0;
    int opt = myTrue;
    // Socket UDP
    socketUDP = socket(AF_INET, SOCK_DGRAM, 0);
    if (socketUDP == -1)
    {
        std::cerr << " UDP socket error" << std::endl;
        std::exit(EXIT_FAILURE);
    }

    serverAddrUDP.sin_family = AF_INET;
    serverAddrUDP.sin_port = htons(std::stoi(nodeParameters[4]));
    serverAddrUDP.sin_addr.s_addr = INADDR_ANY;
    bzero(&(serverAddrUDP.sin_zero), 8);

    // bind
    ret = bind(socketUDP, (struct sockaddr *)&serverAddrUDP, sizeof(struct sockaddr));
    if (ret == -1)
    {
        std::cerr << "UDP bind error" << std::endl;
        std::exit(EXIT_FAILURE);
    }
    addr_len = sizeof(struct sockaddr);

    // Socket TCP
    masterSocketFD = socket(AF_INET, SOCK_STREAM, 0);
    if (!masterSocketFD)
    {
        std::cerr << " TCP socket error" << std::endl;
        std::exit(EXIT_FAILURE);
    }

    // Master socket
    ret = setsockopt(masterSocketFD, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt));
    if (ret < 0)
    {
        std::cerr << "master socket error" << std::endl;
        std::exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_port = htons(std::stoi(nodeParameters[3]));
    address.sin_addr.s_addr = INADDR_ANY;
    // std::cout << "node data: " << htons(std::stoi(nodeParameters[3])) << std::endl;
    ret = bind(masterSocketFD, (struct sockaddr *)&address, sizeof(address));

    if (ret < 0)
    {
        std::cerr << "TCP bind error " << std::endl;
        std::exit(EXIT_FAILURE);
    }

    ret = listen(masterSocketFD, 5);
    if (ret < 0)
    {
        std::cerr << " listen error" << std::endl;
        std::exit(EXIT_FAILURE);
    }
}

void displayHtable()
{

    int from_key = num, to_key = (tablesize - 1) * N + num;

    if (from_key > to_key)
    {

        int temp = from_key;
        from_key = to_key;
        to_key = temp;
    }

    std::cout << "\n-----Hash Table Contents(" << from_key << "--" << to_key << " )------------\n", from_key, to_key;

    if (from_key % N == num && to_key % N == num)
    {

        int i, from = (from_key - num) / N, to = (to_key - num) / N, fetchValue, key;

        for (i = from; i <= to; i++)
        {

            key = i * N + num;
            fetchValue = fetchValueFromHT(key);
            if (fetchValue != 0)
                std::cout << "\nkey : " << key << " ===== value : " << fetchValueFromHT(key) << std::endl;
        }
    }
    else
        std::cout << "invalid keys , hash table cannot be displayed\n";

    std::cout << "-----------------------------------------------------\nENTER NEW GET/PUT REQUEST:";
}

void runNode()
{
    int ret = 0;

    std::cout << "1.put  2.get 3.r " << std::endl;
    std::cout << "=================================================";
    // clear fd at begining
    FD_ZERO(&readfds);

    // add udp to fd_set
    FD_SET(socketUDP, &readfds);

    // Adds master scoket to file descriptor
    FD_SET(masterSocketFD, &readfds);

    FD_SET(0, &readfds);

    if (masterSocketFD > socketUDP)
    {
        maxFD = masterSocketFD;
    }
    else
    {
        maxFD = socketUDP;
    }

    // Select
    select(maxFD + 1, &readfds, NULL, NULL, NULL);
    // Check master socket
    if (FD_ISSET(masterSocketFD, &readfds))
    {
        addrlen = sizeof(address);
    }

    new_socket = accept(masterSocketFD, (struct sockaddr *)&address, &addrlen);

    if (new_socket < 0)
    {
        std::cerr << " Accept error" << std::endl;
        std::exit(EXIT_FAILURE);
    }

    // check if request was made before
    if (transferValue != 0)
    {
        itoa(transferValue, replyBuffer);
        send(new_socket, replyBuffer, strlen(replyBuffer), 0);
        read(new_socket, buffer, 1024);
        std::cout << '\n'
                  << buffer << '\n';
        transferValue = 0;
        close(new_socket);
    }
    else
    {
        // Receive value from client
        ret = read(new_socket, buffer, 1024);
        std::cout << "read " << std::endl;
        if (ret < 0)
        {
            close(new_socket);
        }
        else
        {
            buffer[ret] = 0;
            std::cout << '\n'
                      << buffer << '\n';
        }
        close(new_socket);
    }

    // check UDP
    if (FD_ISSET(socketUDP, &readfds))
    {
        char rec_buff[5000];
        int len = recvfrom(socketUDP, rec_buff, 5000, 0, (struct sockaddr *)&clientAddr, &addr_len);
        rec_buff[len] = '\0';
        std::cout << "-------UDP packet received from IP:" << inet_ntoa(clientAddr.sin_addr) << ntohs(clientAddr.sin_port) << extractNodeno(rec_buff);
        std::cout << rec_buff << std::endl;

        ret = forYou(num, rec_buff);
        if (ret == 0)
        {
            forwardUDP(num + 1, rec_buff);
            std::cout << "Enter new get / put request:";
        }
        else
        {
            std::cout << "processing request on current node" << std::endl;
            int key = extractKeyFromPut(rec_buff);
            int nodeno = extractNodeno(rec_buff);

            int sock, bytes_recieved;
            char send_data[1024], recv_data[1024];
            char flag = rec_buff[strlen(rec_buff) - 2]; // extracted flag value from request
            struct hostent *host;
            struct sockaddr_in server_addr;
            host = gethostbyname(extractIpaddress(rec_buff, '[', ',')); // extracting originator IP from request

            if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1)
            {
                std::cerr << " Socket error" << std::endl;
                exit(EXIT_FAILURE);
            }
            server_addr.sin_family = AF_INET;
            server_addr.sin_port = htons(extractValueFromPut(rec_buff));
            server_addr.sin_addr = *((struct in_addr *)host->h_addr);
            bzero(&(server_addr.sin_zero), 8);

            ret = connect(sock, (struct sockaddr *)&server_addr, sizeof(struct sockaddr));
            if (ret == -1)
            {
                std::cerr << " Connect error" << std::endl;
                exit(EXIT_FAILURE);
            }
            if (flag == 's')
            {
                int valuefetched = fetchValueFromHT(key);
                if (valuefetched != 0)
                {

                    strcpy(send_data, "value = ");
                    char valuebuff[6], nodebuff[4];
                    itoa(valuefetched, valuebuff);
                    strcat(send_data, valuebuff);
                    strcat(send_data, ". Value retrieved from node no : ");
                    itoa(num, nodebuff);
                    strcat(send_data, nodebuff);
                    strcat(send_data, "\n-------------------\nENTER NEW GET/PUT REQUEST:");
                }
                else
                {
                    strcpy(send_data, "RESULT: No hash entry to this key on node no : ");
                    char nodebuff[4];
                    itoa(num, nodebuff);
                    strcat(send_data, nodebuff);
                    strcat(send_data, "\n--------------------\nENTER NEW GET/PUT REQUEST :");
                }
                send(sock, send_data, strlen(send_data), 0); // Send the fetched value
                std::cout << "\n KEY RECIEVED " << key << ",\nREQUEST ORIGINALLY INVOKED ON NODE" << nodeno << " , flag recieved = " << rec_buff[strlen(rec_buff) - 2] << " . VALUE SUPPLIED BACK ON TCP CONNECTION.\nENTER NEW GET/PUT REQUEST:";
            }
            else
            {
                bytes_recieved = recv(sock, recv_data, 1024, 0); // Receiving Put value
                recv_data[bytes_recieved] = '\0';
                std::cout << "\n KEY RECIEVED IS:" << key << ",\nREQUEST ORIGINALLY INVOKED ON NODE " << nodeno << " flag recieved = " << rec_buff[strlen(rec_buff) - 2];

                std::cout << "\nVALUE RECIEVED (ON TCP CONNECTION) FROM NODE NO" << nodeno << '=' << recv_data;
                // now insert the key,value in hash table of this node and send confirmation message 						back to parent node
                // on which the request was originallly invoked by the  user

                if (addToHashtable(key, atoi(recv_data)))
                    strcpy(send_data, "RESULT: put operation has been done successfully.  Value added on node no :");
                else
                    strcpy(send_data, "RESULT: put operation failed. Maximum key limit Exceeded on node number  ");
                char nodebuff[4];
                itoa(num, nodebuff);
                strcat(send_data, nodebuff);
                strcat(send_data, ".\n------------------------------------\nENTER NEW GET/PUT REQUEST :");
                send(sock, send_data, strlen(send_data), 0);
            }
            close(sock);
            std::cout << std::endl;
        }
    }

    // Console
    // FD_ISSET()Returns a non-zero value if the bit for the file descriptor
    if (FD_ISSET(0, &readfds))
    {
        std::cout << "console " << std::endl;
        char rec_buff[4500];
        // std::cin >> rec_buff;
        auto ret = 0;
        ret = forYou(num, rec_buff);
        if (rec_buff[0] == 'r' || rec_buff[0] == 'R')
        {
            displayHtable();
        }
        else if (ret == 0)
        {
            char outputbuff[40], *out, flag;
            int i = 0;
            ret = getOrPut(rec_buff);
            if (ret == 0) // fun() return 1 for get, 0 for put
            {
                // value from put to be transferred at last
                transferValue = extractValueFromPut(rec_buff);
                flag = 'r'; // indicates that last node has to receive a value
            }
            else
                flag = 's'; // indicates that last node will send a value

            out = forwardedData(rec_buff, flag); // fun() to prepare the data to be forwaded

            for (i = 0; i < strlen(out); i++)
            {
                outputbuff[i] = *(out + i);
            } // data to be forwaded is assigned to outputbuff

            outputbuff[i] = '\0';

            forwardUDP(num + 1, outputbuff); // forwading method called
            free(out);
        }
        else
        {
            std::cout << "\nPROCESSING THE REQUEST HERE:\n-------------------\n";
            ret = getOrPut(rec_buff);
            if (ret == 1) // fun() return 1 for get, 0 for put
            {
                // extract key from get request
                int key = extractKeyFromGet(rec_buff), value;
                int maxkeylimit = (tablesize - 1) * N + num; // Compute maximum key limit

                if (key <= maxkeylimit)
                {
                    value = fetchValueFromHT(key); // call fun() to fetch value from hash table
                    if (value == 0)
                    {
                        std::cout << "\nError - No value in Hash table for this key on Current node. 								\n---------------------\nEnter NEW GET/PUT REQUEST :";
                    }
                    else
                    {
                        std::cout << "\n key = " << key << ", value = " << value << " on same node \n----------------------- 								-\nEnter GET/PUT REQUEST :";
                    }
                }
                else
                {
                    std::cout << "\n Result :  Error - value cannot be fetched , maximum key is " << maxkeylimit << " 							\n----------------------\nEnter NEW GET/PUT REQUEST :";
                }
            }
            else
            {
                // processing put request on the same node
                addToHashtable(extractKeyFromPut(rec_buff), extractValueFromPut(rec_buff));
            }
        }
        std::cout << std::endl;
    }
}

// ============================================================================//
// arguments are:
// node number
int main(int argc, char *argv[])
{
    system("clear");
    std::cout << "\t\tNode N" << argv[1] << "\t\t\t\t\t\t";
    int nodeNumber = std::stoi(argv[1]);
    if (readfile(filePath, nodeNumber))
    {
        std::cout << "error with the file " << filePath << std::endl;
    }
    initialiseHashtable();

    std::cout << "Node parameters: ";
    for (auto i : nodeParameters)
    {
        std::cout << i << " ";
    }
    std::cout << "\t";

    std::cout << "Next Node parameters: ";
    for (auto i : nextNodeParameters)
    {
        std::cout << i << " ";
    }
    std::cout << std::endl;

    // Socket initialization
    initSocket();

    // start listening for requests
    while (1)
    {
        runNode();
    }

    // std::cout << algorithm(5) << std::endl;
    return 0;
}