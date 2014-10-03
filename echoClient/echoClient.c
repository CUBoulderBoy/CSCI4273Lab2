#include <sys/types.h>
#include <sys/socket.h>

#include <sys/errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
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

#ifndef INADDR_NONE
#define INADDR_NONE     0xffffffff
#endif  /* INADDR_NONE */

extern int	errno;

int	TCPecho(const char *host, const char *portnum);
int	errexit(const char *format, ...);
int	connectsock(const char *host, const char *portnum);
int loadCerts(SSL_CTX* ctx, char* certFile, char* keyFile);

#define	LINELEN		128

/*------------------------------------------------------------------------
 * main - TCP client for ECHO service
 *------------------------------------------------------------------------
 */
int
main(int argc, char *argv[])
{
	char	*host = "localhost";	/* host to use if none supplied	*/
	char	*portnum = "5004";	/* default server port number	*/

	switch (argc) {
	case 1:
		host = "localhost";
		break;
	case 3:
		host = argv[2];
		/* FALL THROUGH */
	case 2:
		portnum = argv[1];
		break;
	default:
		fprintf(stderr, "usage: TCPecho [host [port]]\n");
		exit(1);
	}
	TCPecho(host, portnum);
	exit(0);
}

/*------------------------------------------------------------------------
 * TCPecho - send input to ECHO service on specified host and print reply
 *------------------------------------------------------------------------
 */
int TCPecho(const char *host, const char *portnum) {
	char	buf[LINELEN+1];		/* buffer for one line of text	*/
	int	s, n;			/* socket descriptor, read count*/
	int	outchars, inchars;	/* characters sent and received	*/
    
    // Added variables for SSL connection
    char certFile[] = "cacert.pem";
    char keyFile[] = "cakey.pem";
    SSL_CTX *ctx;
    SSL *ssl;
    SSL_METHOD *method;

    // Initialize SSL library
    SSL_library_init();

    // Intialize CTX state
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    method = SSLv3_client_method();
    ctx = SSL_CTX_new(method);

    // Get and verify certficates
    if ( loadCerts(ctx, certFile, keyFile) == -1){
        errexit("Certificate error: %s\n", strerror(errno));
    }

    // Start a TCP socket
	s = connectsock(host, portnum);

    // Initialize an ssl connection state
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, s);

    // Connect the SSL socket or error out
    if ( SSL_connect(ssl) == -1 ){
        errexit("socket read failed: %s\n", strerror(errno));
    }

    // SSL Handshake
    if(SSL_get_peer_certificate(ssl) != NULL){
        if(SSL_get_verify_result(ssl) != X509_V_OK){
            printf("%s\n", "Client verification with SSL_get_verify_result() failed, exiting");
            exit(1);
        }
    }
    else{
        printf("%s\n", "Server certificate was not presented, exiting");
        exit(1);
    }

	while (fgets(buf, sizeof(buf), stdin)) {
		buf[LINELEN] = '\0';	/* insure line null-terminated	*/
		outchars = strlen(buf);

        // Write the text from the console the server via SSL
        SSL_write(ssl, buf, outchars); 

		// Read the reply back
		for (inchars = 0; inchars < outchars; inchars+=n ) {
            // Read and decrypt reply via SSL connection
            n = SSL_read(ssl, &buf[inchars], outchars - inchars);
			
            // If no characters read, then error out
            if (n < 0)
				errexit("socket read failed: %s\n", strerror(errno));
		}
        // Print the echo to the console
		fputs(buf, stdout);

        // Free the SSL connection
        SSL_free(ssl); 
	}
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
 * connectsock - allocate & connect a socket using TCP 
 *------------------------------------------------------------------------
 */
int connectsock(const char *host, const char *portnum){
/*
 * Arguments:
 *      host      - name of host to which connection is desired
 *      portnum   - server port number
 */
        struct hostent  *phe;   /* pointer to host information entry    */
        struct sockaddr_in sin; /* an Internet endpoint address         */
        int     s;              /* socket descriptor                    */


        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;

    /* Map port number (char string) to port number (int)*/
        if ((sin.sin_port=htons((unsigned short)atoi(portnum))) == 0)
                errexit("can't get \"%s\" port number\n", portnum);

    /* Map host name to IP address, allowing for dotted decimal */
        if ( (phe = gethostbyname(host)) ){
            memcpy(&sin.sin_addr, phe->h_addr, phe->h_length);
        }
        else if ( (sin.sin_addr.s_addr = inet_addr(host)) == INADDR_NONE ){
            errexit("can't get \"%s\" host entry\n", host);    
        }

    /* Allocate a socket */
        s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s < 0)
                errexit("can't create socket: %s\n", strerror(errno));

    /* Connect the socket */
        if (connect(s, (struct sockaddr *)&sin, sizeof(sin)) < 0)
                errexit("can't connect to %s.%s: %s\n", host, portnum,
                        strerror(errno));
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