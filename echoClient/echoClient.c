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

#ifndef INADDR_NONE
#define INADDR_NONE     0xffffffff
#endif  /* INADDR_NONE */

extern int	errno;

int	    TCPecho(const char *host, const char *portnum);
int	    errexit(const char *format, ...);
int	    connectsock(const char *host, const char *portnum);
static int pem_passwd_cb(char *buf, int size, int rwflag, void *userdata);

#define	LINELEN		128
#define CACERT      "cacert.pem"
#define CL_PRIV     "cakey.pem"
#define PASSWORD    "netsys_2014"

/*------------------------------------------------------------------------
 * main - TCP client for ECHO service
 *------------------------------------------------------------------------
 */
int main(int argc, char *argv[]){
	char	*host = "localhost";	  /* host to use if none supplied	*/
	char	*portnum = "5004";       /* default server port number	*/

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
	char buf[LINELEN+1];		/* buffer for one line of text	*/
    char rebuf[LINELEN+1];
	int	s, n;			/* socket descriptor, read count*/
    char *pass = "netsys_2014";
    char *cl_priv = "cakey.pem";
    char *ca_cert = "cacert.pem";
    char *cypher = "AES128-SHA";

    // SSL Variables
    SSL *ssl;
    SSL_CTX *ctx;
    SSL_METHOD *method;

    // Initialize SSL library and crypto suite
    SSL_library_init();
    SSL_load_error_strings();

    // Intialize CTX state
    method = SSLv23_method();
    ctx = SSL_CTX_new(method);
    
    if (SSL_CTX_set_cipher_list(ctx, cypher) <= 0) {
        printf("Error setting the cipher list.\n");
        exit(0);
    }
    
    // Set password callback
    SSL_CTX_set_default_passwd_cb_userdata(ctx, pass);

    // Load the local private key from the location specified by keyFile
    if ( SSL_CTX_use_PrivateKey_file(ctx, cl_priv, SSL_FILETYPE_PEM) <= 0 ){
        exit(1);
    }

    /*Make sure the key and certificate file match*/
    if (SSL_CTX_check_private_key(ctx) == 0) {
        printf("Private key does not match the certificate public key\n");
        exit(0);
    }

    // Load the CA certificate for verification
    if (SSL_CTX_load_verify_locations(ctx, ca_cert, NULL) <= 0){
        exit(0);
    }   

    // Require verification
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    // Ensure ctx not null
    if ( ctx == NULL ){
        exit(0);
    }

    // Initialize an ssl connection state
    ssl = SSL_new(ctx);

    // Start a TCP socket
    s = connectsock(host, portnum);

    // Map ssl to socket
    SSL_set_fd(ssl, s);

    // Connect the SSL socket or error out
    if ( SSL_connect(ssl) < 1 ){
        errexit("socket read failed: %s\n", strerror(errno));
        exit(1);
    }

    printf("SSL connection on socket %x,Version: %s, Cipher: %s\n",
       s,
       SSL_get_version(ssl),
       SSL_get_cipher(ssl));

	/*while (1) {
        // Read from command line
        fgets(buf, sizeof(buf), stdin);

        // Ensure buffer is null terminated
		buf[LINELEN] = '\0';

        // Write the text from the console the server via SSL
        SSL_write(ssl, buf, sizeof(buf));

        // Clear send buffer
        memset(&buf, 0, sizeof(buf));

        // Read and decrypt reply via SSL connection
        n = SSL_read(ssl, &rebuf, sizeof(rebuf));
			
        // If no characters read, then error out
        if (n < 0)
			errexit("socket read failed: %s\n", strerror(errno));

        // Print the echo to the console
		fputs(rebuf, stdout);

        // Clear recieve buffer
        memset(&rebuf, 0, sizeof(rebuf));
	}*/
    return 0;
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
 * pem_passwd_cb - password callback
 *------------------------------------------------------------------------
 */
static int pem_passwd_cb(char *buf, int size, int rwflag, void *password){
  strncpy(buf, (char *)(password), size);
  buf[size - 1] = '\0';
  return(strlen(buf));
}