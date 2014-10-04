#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/types.h>

#include <sys/errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#define	QLEN		32	/* maximum connection queue length	*/
#define	BUFSIZE		4096
#define SERVERCERT  "server.cert"
#define SERVERKEY   "server_priv.key"
#define PASSWORD    "netsys_2014"

extern int	errno;
int		errexit(const char *format, ...);
int		passivesock(const char *portnum, int qlen);
int		echo(SSL* fd);
static int pem_passwd_cb(char *buf, int size, int rwflag, void *userdata);

/*------------------------------------------------------------------------
 * main - Concurrent TCP server for ECHO service
 *------------------------------------------------------------------------
 */
int main(int argc, char *argv[]){
	char *portnum = "5004";	               // Standard server port number
	struct sockaddr_in fsin;	               // the from address of a client
	int msock;			                       // master server socket
	fd_set rfds;			                   // read file descriptor set
	fd_set afds;			                   // active file descriptor set
	unsigned int alen;		                   // from-address length
	int fd, nfds;                              // For file desriptor table
    //map<int, SSL*> ssl_connections;            // Map to store chat messages
    char *pass = "netsys_2014";
    char *server_key = "server_priv.key";
    char *server_cert = "server.cert";
    char *cypher = "AES128-SHA";
    
    // SSL Variables
    SSL *ssl;
    SSL_CTX *ctx;
    SSL_METHOD *method;
	
	switch (argc) {
	case	1:
		break;
	case	2:
		portnum = argv[1];
		break;
	default:
		errexit("usage: TCPmechod [port]\n");
	}

    // Initialize SSL library and crypto suite
    SSL_library_init();
    SSL_load_error_strings();

    // Intialize CTX state
    method = SSLv23_method();
    ctx = SSL_CTX_new(method);

    if (SSL_CTX_set_cipher_list(ctx, cypher) <= 0) {
        printf("Error setting the cipher list.\n");
        fflush(stdout);
        exit(0);
    }
    
    // Set password callback
    //SSL_CTX_set_default_passwd_cb_userdata(ctx, pass);
    //SSL_CTX_set_default_passwd_cb(ctx, pem_passwd_cb);

    // Load the server certificate
    if (SSL_CTX_use_certificate_file(ctx, server_cert, SSL_FILETYPE_PEM) != 1){
        exit(1);
    }

    // Load the local private key from the location specified by keyFile
    if ( SSL_CTX_use_PrivateKey_file(ctx, server_key, SSL_FILETYPE_PEM) != 1 ){
        exit(1);
    }

	msock = passivesock(portnum, QLEN);

    listen(msock, 5);
    int ssock = accept(msock, (struct sockaddr *)&fsin, &alen);
    close(msock);

    // Ensure ctx not null
    if ( ctx == NULL ){
        exit(0);
    }

    // Initialize an ssl connection state
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, ssock);

    // Connect the SSL socket or error out
    if ( SSL_accept(ssl) == -1 ){
        errexit("socket read failed: %s\n", strerror(errno));
    }

    while (1){
        // Call echo with SSL port
        echo(ssl);
    }


	/*nfds = getdtablesize();
	FD_ZERO(&afds);
	FD_SET(msock, &afds);

	while (1) {
		memcpy(&rfds, &afds, sizeof(rfds));

		if (select(nfds, &rfds, (fd_set *)0, (fd_set *)0,
				(struct timeval *)0) < 0)
			errexit("select: %s\n", strerror(errno));
		if (FD_ISSET(msock, &rfds)) {
			int	ssock;

            // Accept TCP Connection
			alen = sizeof(fsin);
			ssock = accept(msock, (struct sockaddr *)&fsin, &alen);
			if (ssock < 0){
				errexit("accept: %s\n", strerror(errno));
            }
            
            // Initialize an ssl connection state
            SSL *ssl = SSL_new(ctx);
            SSL_set_fd(ssl, ssock);

            // Connect the SSL socket or error out
            if ( SSL_accept(ssl) == -1 ){
                errexit("socket read failed: %s\n", strerror(errno));
            }

            // Set socket to active file descriptor
            FD_SET(ssock, &afds);

            // Store sll in map
            ssl_connections[ssock] = ssl;
		}
		for (fd=0; fd<nfds; ++fd){
			if (fd != msock && FD_ISSET(fd, &rfds)){
				if (echo(ssl_connections[fd]) == 0) {
					// Store for use
                    SSL *ssl = ssl_connections[fd];

                    // Close SSL and TCP connections
                    (void) SSL_shutdown(ssl);
                    (void) close(fd);
                    SSL_free(ssl);

                    // Remove from tracking structures
                    FD_CLR(fd, &afds);
                    ssl_connections.erase(fd);
				}
            }
        }
	}*/
}

/*------------------------------------------------------------------------
 * echo - echo one buffer of data, returning byte count
 *------------------------------------------------------------------------
 */
int echo(SSL* ssl) {
	char	buf[BUFSIZE];
	int	    cc;

	cc = SSL_read(ssl, buf, sizeof(buf) );
	if (cc < 0)
		errexit("echo read: %s\n", strerror(errno));
	if (cc && SSL_write(ssl, buf, cc) < 0)
		errexit("echo write: %s\n", strerror(errno));
	return cc;
}

/*------------------------------------------------------------------------
 * errexit - print an error message and exit
 *------------------------------------------------------------------------
 */
int errexit(const char *format, ...){
        va_list args;

        va_start(args, format);
        vfprintf(stderr, format, args);
        va_end(args);
        exit(1);
}

/*------------------------------------------------------------------------
 * passivesock - allocate & bind a server socket using TCP
 *------------------------------------------------------------------------
 */
int passivesock(const char *portnum, int qlen){
/*
 * Arguments:
 *      portnum   - port number of the server
 *      qlen      - maximum server request queue length
 */
    struct sockaddr_in sin; /* an Internet endpoint address  */
    int     s;              /* socket descriptor             */

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;

    /* Map port number (char string) to port number (int) */
    if ((sin.sin_port=htons((unsigned short)atoi(portnum))) == 0)
            errexit("can't get \"%s\" port number\n", portnum);

    /* Allocate a socket */
    s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s < 0)
        errexit("can't create socket: %s\n", strerror(errno));

    /* Bind the socket */
    if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        fprintf(stderr, "can't bind to %s port: %s; Trying other port\n",
            portnum, strerror(errno));
        sin.sin_port=htons(0); /* request a port number to be allocated
                               by bind */
        if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) < 0)
            errexit("can't bind: %s\n", strerror(errno));
        else {
            socklen_t socklen = sizeof(sin);

            if (getsockname(s, (struct sockaddr *)&sin, &socklen) < 0)
                    errexit("getsockname: %s\n", strerror(errno));
            printf("New server port number is %d\n", ntohs(sin.sin_port));
        }
    }

    if (listen(s, qlen) < 0)
        errexit("can't listen on %s port: %s\n", portnum, strerror(errno));
    return s;
}

/*------------------------------------------------------------------------
 * pem_passwd_cb - password callback
 *------------------------------------------------------------------------
 */
static int pem_passwd_cb(char *buf, int size, int rwflag, void *password){
  strncpy(buf, (char *)(password), size);
  buf[size - 1] = '\0';
  return(strlen(buf));
}