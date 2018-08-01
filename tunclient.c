#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <sys/socket.h>

#define BUFF_SIZE 2000
#define PORT_NUMBER 55555
#define SERVER_IP "10.0.2.4"
#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }
#define CA_DIR "ca_client" 

int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    char  buf[300];

    X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    X509_NAME_oneline(X509_get_subject_name(cert), buf, 300);
    printf("subject= %s\n", buf);

    if (preverify_ok == 1) {
       printf("Verification passed.\n");
    } else {
       int err = X509_STORE_CTX_get_error(x509_ctx);
       printf("Verification failed: %s.\n",
                    X509_verify_cert_error_string(err));
    }
}

SSL* setupTLSClient(const char* hostname)
{
    // Step 0: OpenSSL library initialization 
   // This step is no longer needed as of version 1.1.0.
   SSL_library_init();
   SSL_load_error_strings();
   SSLeay_add_ssl_algorithms();

   SSL_METHOD *meth;
   SSL_CTX* ctx;
   SSL* ssl;

   meth = (SSL_METHOD *)TLSv1_2_method();
   ctx = SSL_CTX_new(meth);
//printf("hello:%s",hostname);
   SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
   if(SSL_CTX_load_verify_locations(ctx,NULL, CA_DIR) < 1){
	printf("Error setting the verify locations. \n");
	exit(0);
   }
   ssl = SSL_new (ctx);
//printf("1\n");
   X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl); 
//printf("1\n");

   X509_VERIFY_PARAM_set1_host(vpm, hostname, 0);

   return ssl;
}
//struct sockaddr_in peerAddr;

int setupTCPClient(const char* hostname, int port)
{
   struct sockaddr_in server_addr;

   // Get the IP address from hostname
   struct hostent* hp = gethostbyname(hostname);

   // Create a TCP socket
   int sockfd= socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

   // Fill in the destination information (IP, port #, and family)
   memset (&server_addr, '\0', sizeof(server_addr));
   memcpy(&(server_addr.sin_addr.s_addr), hp->h_addr, hp->h_length);
//   server_addr.sin_addr.s_addr = inet_addr ("10.0.2.14"); 
   server_addr.sin_port   = htons (port);
   server_addr.sin_family = AF_INET;

   // Connect to the destination
   connect(sockfd, (struct sockaddr*) &server_addr,
           sizeof(server_addr));

   return sockfd;
}




int createTunDevice() {
   int tunfd;
   struct ifreq ifr;
   memset(&ifr, 0, sizeof(ifr));

   ifr.ifr_flags = IFF_TUN | IFF_NO_PI;  

   tunfd = open("/dev/net/tun", O_RDWR);
   ioctl(tunfd, TUNSETIFF, &ifr);       

   return tunfd;
}


void tunSelected(int tunfd, int sockfd,SSL* ssl){
    int  len;
    char buff[BUFF_SIZE];

    //printf("Got a packet from TUN\n");

    bzero(buff, BUFF_SIZE);
    len = read(tunfd, buff, BUFF_SIZE);
	printf("got packet from TUN0: %d\n",len);
    SSL_write(ssl,buff,sizeof(buff));
}
//Command on terminal
static void run(char *cmd) {
  printf("Execute `%s`\n", cmd);
  if (system(cmd)) {
    perror(cmd);
    exit(1);
  }
}
void TunRoute(char *ip)
{
	char cmd[1024];
	char cmd2[1024];
	snprintf(cmd,sizeof(cmd),"ifconfig tun0 %s/24 up",ip);
	run(cmd);
	run("route add -net 192.168.60.0/24 tun0");
	//run(cmd2);
}
void socketSelected (int tunfd, int sockfd,SSL* ssl){
    int  len;
    char buff[BUFF_SIZE];

//    printf("Got a packet from the tunnel\n");

    bzero(buff, BUFF_SIZE);
    len = SSL_read(ssl,buff,sizeof(buff)-1);
if(buff[strlen(buff)-1] == 'p' && buff[strlen(buff)-2] == 'i')
{printf("rec ip: %s\n",buff);
char *ip = malloc(14);
strncpy(ip,buff,12); 
printf("IP : %s\n",ip);
TunRoute(ip);
}
else
    write(tunfd, buff, len);

}
int main(int argc, char *argv[])
{
   char *hostname = "yahoo.com";
   int port = 443;
int tunfd;
   if (argc > 1) hostname = argv[1];
   if (argc > 2) port = atoi(argv[2]);


   /*----------------TLS initialization ----------------*/
   SSL *ssl   = setupTLSClient(hostname);
	printf("TLSCLIENT SETUP DONE!--\n");
   /*----------------Create a TCP connection ---------------*/
   int sockfd = setupTCPClient(hostname, port);
printf("TcpCLIENT SETUP DONE!--\n");
   /*----------------TLS handshake ---------------------*/
   SSL_set_fd(ssl, sockfd);
   int err = SSL_connect(ssl); CHK_SSL(err);
   printf("SSL connection is successful\n");
   printf ("SSL connection using %s\n", SSL_get_cipher(ssl));

   /*----------------Send/Receive data --------------------*/
   char buf[9000];
   char sendBuf[200];
   char uid[20];
   char *pwd = malloc(20);
char *comb = malloc(strlen(uid)+strlen(pwd)+10);
   	tunfd  = createTunDevice();
printf("Enter UID:");

   fgets(uid,20,stdin);
printf("ENter Pwd:");
pwd = getpass("Enter Pwd:");
   
strcpy(comb,"auth:i:");
strcat(comb,uid);
strcat(comb,",p:");
   strcat(comb,pwd);   
//sprintf(sendBuf, "", hostname);
   memcpy(sendBuf,comb,strlen(comb));
	printf("%s",comb);
   SSL_write(ssl, sendBuf, strlen(sendBuf));

   int len;
 while (1) {
     fd_set readFDSet;

     FD_ZERO(&readFDSet);
     FD_SET(sockfd, &readFDSet);
     FD_SET(tunfd, &readFDSet);
     select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

     if (FD_ISSET(tunfd,  &readFDSet)) tunSelected(tunfd, sockfd,ssl);
     if (FD_ISSET(sockfd, &readFDSet)) socketSelected(tunfd, sockfd,ssl);
  }
   }
