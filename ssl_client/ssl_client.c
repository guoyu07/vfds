#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <resolv.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "protocol.h"

void ShowCerts(SSL * ssl)
{
	X509 *cert;
	char *line;
	cert = SSL_get_peer_certificate(ssl);
	if (cert != NULL) 
	{
		printf("数字证书信息:\n");
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		printf("证书: %s\n", line);
		free(line);
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		printf("颁发者: %s\n", line);
		free(line);
		X509_free(cert);
	} else
		printf("无证书信息！\n");
}

int main(int argc, char **argv)
{
	int sockfd, len;
	struct sockaddr_in dest;
	SSL_CTX *ctx;
	SSL *ssl;
	if (argc != 3) {
		printf("usage:%s ip port\n", argv[0]);
		exit(0);
	}
	//init ssl
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	ctx = SSL_CTX_new(SSLv23_client_method());
	if (ctx == NULL) {
		ERR_print_errors_fp(stdout);
		exit(1);
	}
	printf("ssl ctx created\n");

	//create socket
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("Socket");
		exit(errno);
	}
	printf("socket created\n");

	//init address
	bzero(&dest, sizeof(dest));
	dest.sin_family = AF_INET;
	dest.sin_port = htons(atoi(argv[2]));
	if (inet_aton(argv[1], (struct in_addr *) &dest.sin_addr.s_addr) == 0) {
		perror(argv[1]);
		exit(errno);
	}
	printf("address created\n");

	//connect server
	if (connect(sockfd, (struct sockaddr *) &dest, sizeof(dest)) != 0) {
		perror("Connect ");
		exit(errno);
	}
	printf("server connected\n");

	//bind fd to ssl
	ssl = SSL_new(ctx);
	SSL_set_fd(ssl, sockfd);
	if (SSL_connect(ssl) == -1)
		ERR_print_errors_fp(stderr);
	else {
		printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
		ShowCerts(ssl);
	}

	int n = 0;
	char buf[2048] = {0x0};
	sig_head oh;
	sig_body ob;
	while(1)
	{
		memset(buf, 0, sizeof(buf));
		memset(&oh, 0, sizeof(sig_head));
		memset(&ob, 0, sizeof(sig_body));

		//printf("input:");
		//scanf("%s", ob.body);
		sprintf(ob.body, "process:%d, my test id %d", getpid(), rand());

		n = create_sig_msg(0x01, 0x01, &ob, buf, strlen(ob.body));
		printf("消息长度%d\n", n);
		
		len = SSL_write(ssl, buf, n);
		if (len < 0)
			printf("发送失败！错误代码是%d，错误信息是'%s'\n", errno, strerror(errno));
		else
			printf("发送成功，共发送了%d个字节！\n", len);


		memset(buf, 0, sizeof(buf));
		memset(&oh, 0, sizeof(sig_head));
		memset(&ob, 0, sizeof(sig_body));

		len = SSL_read(ssl, buf, sizeof(buf));
		if (len > 0)
		{
			printf("接收消息成功, 共%d个字节的数据\n", len);
			if(parse_sig_msg(&oh, &ob, buf, len) == 0)
			{
				printf("cmdid:%x, status:%x, bodylen:%d, body:%s\n", oh.cmdid, oh.status, oh.bodylen, ob.body);
			}
			else
			{
				printf("解析出错！\n");
			}
		}
		else {
			printf("消息接收失败！错误代码是%d，错误信息是'%s'\n", errno, strerror(errno));
			goto finish;
		}
		sleep(1);
	}
finish:
	SSL_shutdown(ssl);
	SSL_free(ssl);
	close(sockfd);
	SSL_CTX_free(ctx);
	return 0;
}
