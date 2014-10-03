
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/errno.h>
#include <netinet/in.h>
#include <netdb.h>

#include <stdarg.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

#define	QLEN		  32	/* maximum connection queue length	*/
#define	BUFSIZE		4096

extern int	errno;
int		errexit(const char *format, ...);
int		passivesock(const char *portnum, int qlen);
int		echo(SSL* fd);
int     loadCerts(SSL_CTX* ctx, char* certFile, char* keyFile);

/*------------------------------------------------------------------------
 * main - Concurrent TCP server for ECHO service
 *------------------------------------------------------------------------
 */
int
main(int argc, char *argv[])
{
	char	*portnum = "5004";	/* Standard server port number	*/
	struct sockaddr_in fsin;	/* the from address of a client	*/
	int	msock;			/* master server socket		*/
	fd_set	rfds;			/* read file descriptor set	*/
	fd_set	afds;			/* active file descriptor set	*/
	unsigned int	alen;		/* from-address length		*/
	int	fd, nfds;

    // Added variables for SSL connection
    char certFile[] = "server.cert";
    char keyFile[] = "server_priv.key";
    SSL_CTX *ctx;
    SSL *ssl;
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

    // Initialize SSL library
    SSL_library_init();

    // Intialize CTX state
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    method = SSLv3_server_method();
    ctx = SSL_CTX_new(method);

    // Get and verify certficates
    if ( loadCerts(ctx, certFile, keyFile) == -1){
        errexit("Certificate error: %s\n", strerror(errno));
    }

	msock = passivesock(portnum, QLEN);

	nfds = getdtablesize();
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
			ssock = accept(msock, (struct sockaddr *)&fsin,
				&alen);
			if (ssock < 0)
				errexit("accept: %s\n",
					strerror(errno));
            
            // Initialize an ssl connection state
            ssl = SSL_new(ctx);
            SSL_set_fd(ssl, ssock);

            // Connect the SSL socket or error out
            if ( SSL_connect(ssl) == -1 ){
                errexit("socket read failed: %s\n", strerror(errno));
            }

            // SSL Handshake
            if(SSL_get_peer_certificate(ssl) != NULL){
                if(SSL_get_verify_result(ssl) != X509_V_OK){
                    printf("%s\n", "Client verification with SSL_get_verify_result() failed, exiting");
                    continue;
                }
            }
            else{
                printf("%s\n", "Client certificate was not presented, exiting");
                continue;
            }

			SSL_set_fd(ssl, &afds);
		}
		for (fd=0; fd<nfds; ++fd){
			if (fd != msock && FD_ISSET(fd, &rfds)){
				if (echo(fd) == 0) {
					(void) SSL_shutdown(fd);
					SSL_fd(fd, &afds);
				}
            }
        }
	}
}

/*------------------------------------------------------------------------
 * echo - echo one buffer of data, returning byte count
 *------------------------------------------------------------------------
 */
int echo(SSL* fd) {
	char	buf[BUFSIZ];
	int	cc;

	cc = SSL_read(fd, buf, sizeof buf);
	if (cc < 0)
		errexit("echo read: %s\n", strerror(errno));
	if (cc && SSL_write(fd, buf, cc) < 0)
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
            int socklen = sizeof(sin);

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
 * loadCerts - load certificates into ctx
 *------------------------------------------------------------------------
 */
int loadCerts(SSL_CTX* ctx, char* certFile, char* keyFile){
    // Load the local private key from the location specified by keyFile
    if ( SSL_CTX_use_PrivateKey_file(ctx, keyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        return -1;
    }

    // Load the CA certificate for verification
    if (SSL_CTX_load_verify_locations(ctx, certFile, NULL) <= 0){
        return -1;
    }

    // Verify the private key, if incorrect return -1 as error
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        return -1;
    }
    return 1;
}