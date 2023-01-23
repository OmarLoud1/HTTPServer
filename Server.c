/*
A command line based web server that takes http requests and responds to them aporopriately
it also supports sending files over a TCP connection
*/

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdbool.h>

#define OPTSTRING "p:r:t:"
#define REQUIRED_ARGC 3
#define PORT_POS 1
#define MSG_POS 2
#define ERROR 1
#define QLEN 1
#define PROTOCOL "tcp"
#define BUFLEN 4098
#define SHORT 1024

bool pOption = false;
char *port;
bool rOption = false;
char *rootDirectory;
bool tOption = false;
char *authToken;

unsigned int addrlen;
int sd, sd2;

FILE *fileToSend;

char receivedtext[BUFLEN];
bool isGETCommand = false;
char *httpRequ;
char *filePath;
char *filePathToken;
char buffer[BUFLEN];
char pathForCommand[SHORT];

bool isMalformed = false;
bool badProtocol = false;
bool badMethod = false;
bool shuttingDown = false;
bool notAuthed = false;
bool invalidName = false;
bool okResponse = false;
bool notFound = false;

int errexit(char *format, char *arg)
{
    fprintf(stderr, format, arg);
    fprintf(stderr, "\n");
    exit(ERROR);
}

void resetVariables()
{ //resets every error flag for each new request
    isMalformed = false;
    isGETCommand = false;
    badProtocol = false;
    badMethod = false;
    shuttingDown = false;
    notAuthed = false;
    invalidName = false;
    okResponse = false;
    notFound = false;
}

void sendMessage(char *message)
{ /* write message to the connection */
    if (write(sd2, message, strlen(message)) < 0)
        errexit("error writing message: %s", message);
}

void sendFile(FILE *file)
{ // sends the whole file buffer by buffer throught the socket
    int read1 = 0;
    while (true)
    {
        memset(buffer, 0, BUFLEN);
        read1 = fread(buffer, sizeof(char), BUFLEN, file);
        if (write(sd2, buffer, read1) < 0)
            errexit("error writing buffer: %s", buffer);
        if (read1 < BUFLEN)
        {
            fclose(fileToSend);
            break;
        }
    }
}

void checkRequest()
{//method to handle the request in the order specified
    if (isMalformed)
    {
        sendMessage("HTTP/1.1 400 Malformed Request\r\n\r\n");
    }
    else if (badProtocol)
    {
        sendMessage("HTTP/1.1 501 Protocol Not Implemented\r\n\r\n");
    }
    else if (badMethod)
    {
        sendMessage("HTTP/1.1 405 Unsupported Method\r\n\r\n");
    }
    else if (shuttingDown)
    {
        sendMessage("HTTP/1.1 200 Server Shutting Down\r\n\r\n");
        close(sd);
        close(sd2);
        exit(0);
    }
    else if (notAuthed)
    {
        sendMessage("HTTP/1.1 403 Operation Forbidden\r\n\r\n");
    }
    else if (invalidName)
    {
        sendMessage("HTTP/1.1 406 Invalid Filename\r\n\r\n");
    }
    else if (okResponse)
    {
        sendMessage("HTTP/1.1 200 OK\r\n\r\n");
        sendFile(fileToSend);
    }
    else if (notFound)
    {
        sendMessage("HTTP/1.1 404 File Not Found\r\n\r\n");
    }
}

void terminate(char *argument)
{//checks if the auth token is the same
    if (strcmp(authToken, argument) == 0)
    {
        shuttingDown = true;
    }
    else
    {
        notAuthed = true;
    }
}

void parseReceived(char *recvd)
{
    char *CopyOfReceived = strdup(recvd);
    //series of strtok to parse the commands, first is the method
    char *commandptr = strtok(CopyOfReceived, " ");

    if (strcmp(commandptr, "GET") == 0)
    {
        isGETCommand = true;
    }
    else if (strcmp(commandptr, "TERMINATE") == 0)
    {
        char *argument = strtok(NULL, " ");
        terminate(argument);
    }
    else if (strcmp(commandptr, "TERMINATE") != 0 && strcmp(commandptr, "GET") != 0)
    {
        badMethod = true;
    }
    //second strtok gets the path
    filePathToken = strtok(NULL, " ");
    //stored elsewhere
    filePath = strdup(filePathToken);

    if (filePath[0] != '/')
    {
        invalidName = true;
    }
    if (strcmp(filePath, "/") == 0)
    {
        strcat(filePath, "homepage.html");
    }
    //third strtok is the HTTP version
    httpRequ = strtok(NULL, " ");
    char *httptext = strstr(recvd, "HTTP");
    if (httptext == NULL)
    {
        badProtocol = true;
    }
    // makes sure the file ends in a double rnrn
    char *endline = strstr(recvd, "\r\n\r\n");
    if (endline == NULL)
    {
        isMalformed = true;
    }
}

void openFile(char *filedir)
{//checks the file exists and can open
    fileToSend = fopen(filedir, "rb");
    if (fileToSend == NULL)
    {
        notFound = true;
    }
    else
    {
        okResponse = true;
    }
}

void handleGetCommand()
{// opens a file when the get method is called correctly
     if (isGETCommand)
        {
            memset(pathForCommand, 0, SHORT);
            strcat(pathForCommand, rootDirectory);
            strcat(pathForCommand, filePath);
            openFile(pathForCommand);
        }
}

void openPort(char port[])
{
    struct sockaddr_in sin;
    struct sockaddr addr;
    struct protoent *protoinfo;

    /* determine protocol */
    if ((protoinfo = getprotobyname(PROTOCOL)) == NULL)
        errexit("cannot find protocol information for %s", PROTOCOL);

    /* setup endpoint info */
    memset((char *)&sin, 0x0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = htons((u_short)atoi(port));

    /* allocate a socket */
    /*   would be SOCK_DGRAM for UDP */
    sd = socket(PF_INET, SOCK_STREAM, protoinfo->p_proto);
    if (sd < 0)
        errexit("cannot create socket", NULL);

    if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0)
        errexit("setsockopt(SO_REUSEPORT) failed", port);

    if (setsockopt(sd, SOL_SOCKET, SO_REUSEPORT, &(int){1}, sizeof(int)) < 0)
        errexit("setsockopt(SO_REUSEPORT) failed", port);

    /* bind the socket */
    if (bind(sd, (struct sockaddr *)&sin, sizeof(sin)) < 0)
        errexit("cannot bind to port %s", port);

    /* listen for incoming connections */
    if (listen(sd, QLEN) < 0)
        errexit("cannot listen on port %s\n", port);

    /* accept a connection */
    addrlen = sizeof(addr);
    int readError;
    //loop to keep accepting HTTP requests serailly
    while (readError >= 0)
    {
        memset(receivedtext, 0, sizeof(receivedtext));
        sd2 = accept(sd, &addr, &addrlen);
        if (sd2 < 0)
        {
            errexit("error accepting connection", NULL);
        }
        readError = read(sd2, receivedtext, sizeof(receivedtext));
        if (readError < 0)
        {
            errexit("cannot read", NULL);
        }
        //parse the request
        parseReceived(receivedtext);
        // if it's a get command open a file
        handleGetCommand();
        //check if the request was correct/ file exists, return appropirate code or file
        checkRequest();
        //after this request is done, the flags must be reset
        resetVariables();
        close(sd2);
    }
}

int main(int argc, char **argv)
{
    char option;
    while ((option = getopt(argc, argv, OPTSTRING)) != EOF)
    {
        switch (option)
        {
        case 'p':
            pOption = true;
            port = optarg;
            break;
        case 'r':
            rOption = true;
            rootDirectory = optarg;

            break;

        case 't':
            tOption = true;
            authToken = optarg;
            break;

        case '?':
            errexit("correct usage ./proj3 -p port -r document_directory -t auth_token", NULL);
            break;

        case ':':
            errexit("correct usage ./proj3 -p port -r document_directory -t auth_token", NULL);
            break;

        default:

            break;
        }
    }
    if (!pOption && !port)
        errexit("correct usage ./proj3 -p port -r document_directory -t auth_token, -p missing ", NULL);
    if (!rOption && !rootDirectory)
        errexit("correct usage ./proj3 -p port -r document_directory -t auth_token, -r missing ", NULL);
    if (!tOption && !authToken)
        errexit("correct usage ./proj3 -p port -r document_directory -t auth_token, -t missing ", NULL);
    openPort(port);

}
