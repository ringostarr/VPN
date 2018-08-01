#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <netdb.h>

#include <crypt.h>
#include <shadow.h>
#include <stdio.h>
#include <stdlib.h>
//#include <cstdlib.h>
#define PORT_NUMBER 55555
#define BUFF_SIZE 2000
#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
struct sockaddr_in peerAddr;
struct sockaddr_in sa_server;
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

    printf("Got a packet from TUN\n");

    bzero(buff, BUFF_SIZE);
    len = read(tunfd, buff, BUFF_SIZE);
    SSL_write(ssl,buff,sizeof(buff));//ssl write
}
static void run(char *cmd) {
  printf("Execute `%s`\n", cmd);
  if (system(cmd)) {
    perror(cmd);
    exit(1);
  }
}
//struct for assigning ip addresses
struct iplookup{
char *ip;
int avail;
SSL *ssl;
pid_t pid;
};
struct iplookup iplook[3];
int  setupTCPServer();                   // Defined in Listing 19.10
void processRequest(SSL* ssl, int sock,int tunfd); // Defined in Listing 19.12
void socketSelected(int tunfd,int sockfd,SSL* ssl);
//login shadow file
int login(char *user, char *passwd)
{	
	struct spwd *pw;
	char *epasswd;
	pw = getspnam(user);
	if (pw == NULL) {
		return -1;
	}
	printf("Login name: %s\n", pw->sp_namp);
	printf("Passwd : %s\n", pw->sp_pwdp);
	epasswd = crypt(passwd, pw->sp_pwdp);
printf("recieved pwd : %s\n",epasswd);		
		
if (strcmp(epasswd,"$6$wDRrWCQz$IsBXp9.9wz9SGrF.nbihpoN5w.zQx02sht4cTY8qI7YKh00wN/")) {
//printf("match!\n");
	return -1;
	}
//printf("no match!\n");
	return 1;
}
//get ip address from lookup
char* getip()
{
int i=0;
for(i=0;i<4;i++)
{
	if(iplook[i].avail==1){
	iplook[i].avail=0;
	return iplook[i].ip;}
}
return "busy";
}
//initialize lookup
void initip()
{
 iplook[0].ip = "192.168.53.2";
iplook[1].ip = "192.168.53.3";
iplook[2].ip = "192.168.53.4";
iplook[3].ip = "192.168.53.5";
iplook[0].avail=1;
iplook[1].avail=1;
iplook[2].avail=1;
iplook[3].avail=1;
}

int main(){

 
  SSL_METHOD *meth;
  SSL_CTX* ctx;
  SSL *ssl;
  int err;

  // Step 0: OpenSSL library initialization 
  // This step is no longer needed as of version 1.1.0.
  SSL_library_init();
  SSL_load_error_strings();
  SSLeay_add_ssl_algorithms();

  // Step 1: SSL context initialization
  meth = (SSL_METHOD *)TLSv1_2_method();
  
ctx = SSL_CTX_new(meth);
  SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
  // Step 2: Set up the server certificate and private key
  SSL_CTX_use_certificate_file(ctx, "./cert_server/servercrt.pem", SSL_FILETYPE_PEM);
  SSL_CTX_use_PrivateKey_file(ctx, "./cert_server/serverkey.pem", SSL_FILETYPE_PEM);
  // Step 3: Create a new SSL structure for a connection
  ssl = SSL_new (ctx);
  initip();
  struct sockaddr_in sa_client;
  size_t client_len;
  int listen_sock = setupTCPServer();
int tunfd = createTunDevice();


  
    //while (1) {
        int sockfd = accept(listen_sock, (struct sockaddr*)&sa_client, &client_len);
        //if (fork() == 0) { // The child process
            SSL_set_fd (ssl, sockfd);
             err = SSL_accept (ssl);
            CHK_SSL(err);
            printf ("SSL connection established!\n");
            while(1){
                fd_set readFDSet;

                FD_ZERO(&readFDSet);
                FD_SET(sockfd, &readFDSet);
                FD_SET(tunfd, &readFDSet);
                select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

                if (FD_ISSET(tunfd,  &readFDSet)) tunSelected(tunfd, sockfd, ssl);
                if (FD_ISSET(sockfd, &readFDSet)) socketSelected(tunfd, sockfd, ssl);
            }
            close(sockfd);
        //    return 0;
        //} else { // The parent process
        //    close(sockfd);
        //}
    //}
  
//   while(1){
//     int sock = accept(listen_sock, (struct sockaddr*)&sa_client, &client_len);
//     if (fork() == 0) { // The child process
//        close (listen_sock);
// 
//        SSL_set_fd (ssl, sock);
//        int err = SSL_accept (ssl);
//        CHK_SSL(err);
//        printf ("SSL connection established!\n");
// 
//        processRequest(ssl, sock);
//        close(sock);
//        return 0;
//     } else { // The parent process
//         close(sock);
//     }
//   }
}
int setupTCPServer()
{
    
    int listen_sock;

    listen_sock= socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHK_ERR(listen_sock, "socket");
    memset (&sa_server, '\0', sizeof(sa_server));
    sa_server.sin_family      = AF_INET;
    sa_server.sin_addr.s_addr = INADDR_ANY;
    sa_server.sin_port        = htons (4433);
    int err = bind(listen_sock, (struct sockaddr*)&sa_server, sizeof(sa_server));
    CHK_ERR(err, "bind");
    err = listen(listen_sock, 5);
    peerAddr = sa_server;
    CHK_ERR(err, "listen");
    return listen_sock;
}
char* substring(const char* str, size_t begin, size_t len) 
{ 
  if (str == 0 || strlen(str) == 0 || strlen(str) < begin || strlen(str) < (begin+len)) 
    return 0; 

  return strndup(str + begin, len); 
} 
void socketSelected (int tunfd, int sockfd, SSL* ssl){
    int  len;
    char buf[BUFF_SIZE];

    //printf("Got a packet from the tunnel\n");

    bzero(buf, BUFF_SIZE);
    
    //len = recvfrom(sockfd, buff, BUFF_SIZE, 0, NULL, NULL);
    len = SSL_read(ssl, buf, sizeof(buf));
	buf[len] = '\0';
    printf("Received: %s\n",buf);
if(buf[0]=='a' && buf[1]=='u' &&buf[2] == 't' && buf[3]=='h')
	{
	char *uid=strstr(buf,",p:");
	int position= uid-buf;
	char* uid2 = substring(buf,7,4);
	char* pwd = substring(buf,position+3,4);
	printf("uid:%s",uid2);
	printf("pwd:%s",pwd);
	int l=login(uid2,pwd);
	printf("login---%d",l);
	if(l==-1)
		{
  		printf("Login success ,send free ipaddress!\n");
		char *ip = getip();
		const char* ext = "ip";
		char* ipext = malloc(strlen(ip)+3);
		strcpy(ipext,ip);
		strcat(ipext,ext);
		printf("sending ip :%s\n",ipext);
		SSL_write(ssl,ipext,strlen(ipext));//write to tun
		return;

		}
	}    
    write(tunfd, buf, len);

}
void processRequest(SSL* ssl, int sock,int tunfd)
{
    char buf[1024];
    int len = SSL_read (ssl, buf, sizeof(buf) - 1);
    buf[len] = '\0';
    printf("Received: %s\n",buf);
if(buf[0]=='a' && buf[1]=='u' &&buf[2] == 't' && buf[3]=='h')
	{
	char *uid=strstr(buf,",p:");
	int position= uid-buf;
	char* uid2 = substring(buf,7,4);
	char* pwd = substring(buf,position+3,4);
	printf("uid:%s",uid2);
	printf("pwd:%s",pwd);
	int l=login(uid2,pwd);
	printf("login---%d",l);
	if(l==-1)
		{
  		printf("Login success ,send free ipaddress!\n");
		char *ip = getip();
		const char* ext = "ip";
		char* ipext = malloc(strlen(ip)+3);
		strcpy(ipext,ip);
		strcat(ipext,ext);
		printf("sending ip :%s\n",ipext);
		SSL_write(ssl,ipext,strlen(ipext));//write to tun
		//write(tunfd,buf,sizeof(buf));
//run("route add -net 192.168.60.0 netmask 255.255.255.0 dev tun0");
		return;

		}
	else
		{
		printf("login fail!\n");
char *html =
	"Login Failed . Try again with proper UID/Password";
    SSL_write(ssl, html, strlen(html));
    SSL_shutdown(ssl);  SSL_free(ssl);
		
		}}
	else
	{
	write(tunfd,buf,len);

    // Construct and send the HTML page
    
}
}



