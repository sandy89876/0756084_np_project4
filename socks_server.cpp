#include <iostream>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <strings.h>
#include <fstream>

using namespace std;

#define buffersize 20000
#define byte 4

int socketfd;
int cli_socketfd;

//variable for sock4 request
unsigned char VN, CD, buffer[buffersize+1];
unsigned int dest_ip, dest_port;
char* user_id;


void sig_handler(int signo){
    int status;
    
    //for waiting child process
    if(signo == SIGCHLD){
        waitpid(0, &status, WNOHANG);
    }
}

void parse_socks4_request(char *buf){
    VN = buf[0];
    CD = buf[1];
    dest_port = buf[2] << 8 | buf[3];
    dest_ip = buf[4] << 24 | buf[5] << 16 | buf[6] << 8 | buf[7];
    user_id = buf + 8;
}

bool pass_firewall(){
    fstream file;
    char buf[100];

    file.open("socks.conf", ios::in);
    if(!file){
        cout << "open file failed." << endl;
    }else{
        while(!file.eof()){
            file.getline(buf, sizeof(buf));
            string line(buf);
            
        }
    }
    
}

void client_handler(){
	int n;
	char buf[buffersize];
	n = read(cli_socketfd,buf,sizeof(buf));
    if(n < 8){
        printf("read sock4 error\n");
        return;
    }
    
    parse_socks4_request(buf);
    if(pass_firewall()){

    }
	if(CD == 1){
        //connection mode
    }else if(CD == 2){

    }else{
        //mode??
        //send reply
    }
	// if(check_firewall(dest_ip,dest_port)){

	// }
	
}

int main(int argc, const char * argv[]){
	int port = atoi(argv[1]);

	struct sockaddr_in serv_addr, cli_addr;
	socketfd = socket(AF_INET, SOCK_STREAM, 0);
    if(socketfd == -1) puts("Server : Could not create Internet stream socket");
    printf("Server: create socket\n");
    
    //Prepare the sockaddr_in structure
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(port);
    
    int reuse = 1;
    if (setsockopt(socketfd, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0)
            perror("setsockopt(SO_REUSEADDR) failed");
     
    #ifdef SO_REUSEPORT
        if (setsockopt(socketfd, SOL_SOCKET, SO_REUSEPORT, (const char*)&reuse, sizeof(reuse)) < 0) 
            perror("setsockopt(SO_REUSEPORT) failed");
    #endif

    //Bind
    if(bind(socketfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0){
        puts("Server : Could not bind local address");
        return 1;
    }
    printf("Server: bind address\n");

    //Listen
    int tmp = listen(socketfd, 10);
    printf("Server: listen\n");

    signal(SIGCHLD, sig_handler);

    while(1){
    	size_t clilen = sizeof(cli_addr);
        cli_socketfd = accept(socketfd, (struct sockaddr *)&cli_addr, (socklen_t*)&clilen);
        
        if (cli_socketfd < 0){
            puts("Server : Accept failed");
            return 1;
        }

        int p_id = fork();
        if(p_id < 0){
        	puts("Server : fork failed");
            return -1;
        }else if(p_id == 0){
        	client_handler();
        	exit(0);
        }else{
        	close(cli_socketfd);
        	waitpid(-1, NULL, WNOHANG);
        }
    }
}