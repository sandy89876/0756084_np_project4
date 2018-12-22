#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/types.h>

#include <strings.h>
#include <string.h>
#include <fstream>
#include <vector>

using namespace std;

#define buffersize 20000

int socketfd;
int browser_socket;
int client_port;
string client_ip;

//variable for sock4 request
unsigned char VN, CD, buffer[buffersize+1];
unsigned int dest_ip, dest_port;
uint16_t dest_bind_port;
string dest_ip_arr[4];//['140','113','x','x']
string formatted_dest_ip;//140.113.x.x
char* user_id;
string cur_mode;
string reply;

vector<string> split_line(string input,char* delimeter);
void sig_handler(int signo);
int create_conn_to_dest();
void send_reply(unsigned char cd);
int redirect_msg(int src_fd, int dest_fd);
void connect_mode_handler();
void browser_handler();
void relay_traffic(int src_socket, int dest_socket, int fdmax, fd_set all_fds);
void bind_mode_handler();
int create_bind_mode_sock();
bool pass_firewall();
void parse_socks4_request(char *buf);

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
        browser_socket = accept(socketfd, (struct sockaddr *)&cli_addr, (socklen_t*)&clilen);
        
        client_ip = inet_ntoa(cli_addr.sin_addr);
        client_port = (int)ntohs(cli_addr.sin_port);

        if (browser_socket < 0){
            puts("Server : Accept failed");
            return 1;
        }

        int p_id = fork();
        if(p_id < 0){
        	puts("Server : fork failed");
            return -1;
        }else if(p_id == 0){
        	browser_handler();
        	exit(0);
        }else{
        	close(browser_socket);
        	waitpid(-1, NULL, WNOHANG);
        }
    }
}

vector<string> split_line(string input,char* delimeter){
    char *comm = new char[input.length()+1];
    strcpy(comm, input.c_str());
    
    char* token = strtok(comm, delimeter);
    vector<string> result;
    while(token != NULL){
        result.push_back(token);
        token = strtok(NULL, delimeter);
    }
    return result;
}

void sig_handler(int signo){
    int status;
    
    //for waiting child process
    if(signo == SIGCHLD){
        waitpid(0, &status, WNOHANG);
    }
}

void show_server_message(){
    cout << "<S_IP>\t:" << client_ip << endl;
    cout << "<S_PORT>\t:" << to_string(client_port) << endl;
    cout << "<D_IP>\t:" << formatted_dest_ip << endl;
    cout << "<D_PORT>\t:" << to_string(dest_port) << endl;
    if(cur_mode == "c"){
        cout << "<Command>\t:CONNECT" << endl;
    }else if(cur_mode == "b"){
        cout << "<Command>\t:BIND" << endl;
    }
    cout << "<Reply>\t:" << reply << endl;
}

int create_conn_to_dest(){
    struct sockaddr_in client_sin;
    int client_fd;

    client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(client_fd < 0){
        printf("create local client error\n");
        return -1;
    }

    bzero(&client_sin, sizeof(client_sin));
    client_sin.sin_family = AF_INET;
    client_sin.sin_addr.s_addr = inet_addr(formatted_dest_ip.c_str());
    client_sin.sin_port = htons(dest_port);

    if(connect(client_fd, (struct sockaddr *)&client_sin, sizeof(client_sin)) < 0){
        printf("connect error\n");
        return -1;
    }

    return client_fd;
}

void parse_socks4_request(char *buf){
    VN = buf[0];
    CD = buf[1];
    dest_port = buf[2] << 8 | buf[3];
    dest_ip = buf[4] << 24 | buf[5] << 16 | buf[6] << 8 | buf[7];
    user_id = buf + 8;
    
    if(CD == 1){
        cur_mode = "c";
    }else if(CD == 2){
        cur_mode = "b";
    }

    cout << "dest_ip = ";
    for(int i=0; i<4; i++){
        dest_ip_arr[i] = to_string((dest_ip >> (24-8*i)) & 0xff);
        formatted_dest_ip += (dest_ip_arr[i] + ".");
        cout << dest_ip_arr[i] << " ";
    }
    formatted_dest_ip = formatted_dest_ip.substr(0,formatted_dest_ip.length()-1);
    cout << "formatted_dest_ip= " << formatted_dest_ip << endl;
    cout << endl;
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
            cout << "rule:" << line << endl;

            vector<string> rule_arg = split_line(line, " ");
            string rule = rule_arg[0];
            string rule_mod = rule_arg[1];
            string rule_ip = rule_arg[2];
            if(rule_mod != cur_mode){
                continue;
            }

            //check ip
            vector<string> rule_ips = split_line(rule_ip, ".");
            bool ip_passed = true;
            for(vector<string>::iterator it = rule_ips.begin(); it != rule_ips.end(); ++it){
                if(*it != "*" && *it != dest_ip_arr[it - rule_ips.begin()]){
                    ip_passed = false;
                    break;
                }
            }
            if(ip_passed){
                reply = "Accept";
                return true;
            }
        }
    }
    reply = "Reject";
    return false;
}

void send_reply(unsigned char cd){
    unsigned char package[8];
    package[0] = VN;
    package[1] = cd;
    if(cur_mode == "c"){
        package[2] = dest_port / 256;
        package[3] = dest_port % 256;
        package[4] = dest_ip >> 24;
        package[5] = (dest_ip >> 16) & 0xFF;
        package[6] = (dest_ip >> 8) & 0xFF;
        package[7] = dest_ip & 0xFF;
    }else if(cur_mode == "b"){
        package[2] = (dest_bind_port / 256) & 0xff;
        package[3] = (dest_bind_port % 256) & 0xff;
        package[4] = 0;
        package[5] = 0;
        package[6] = 0;
        package[7] = 0;
    }else{
        package[2] = 0;
        package[3] = 0;
        package[4] = 0;
        package[5] = 0;
        package[6] = 0;
        package[7] = 0;
    }
    
    write(browser_socket, package, 8);
}

int redirect_msg(int src_fd, int dest_fd){
    int n;
    n = read(src_fd, buffer, buffersize);
    if(n <= 0) {
        cout << "src_fd read error" << endl;
        return -1;
        //continue;
    }
    cout << "<Content>\t:" << buffer;

    //write back to browser client
    n = write(dest_fd, buffer, sizeof(unsigned char)*n);
    if(n <= 0){
        printf("dest_fd write error\n");
        return -1;
    }
    return 0;
}

void relay_traffic(int src_socket, int dest_socket, int fdmax, fd_set all_fds){
    fd_set tmp_fds;
    FD_ZERO(&tmp_fds);
    while(1){
        tmp_fds = all_fds;
        if(select(fdmax+1, &tmp_fds, NULL, NULL, NULL) == -1){
            if(errno == EINTR){
                continue;
            }else{
                perror("select");
                return;
            }
        }

        if(FD_ISSET(dest_socket, &tmp_fds)){
            //redirect msg from dest_host to browser
            int status = redirect_msg(dest_socket, src_socket);
            if(status < 0)  break;
        }
        
        if(FD_ISSET(src_socket, &tmp_fds)){
            //recv msg from browser
            int status = redirect_msg(src_socket, dest_socket);
            if(status < 0)  break;
        }
    }
    close(dest_socket);
}

void connect_mode_handler(){
    cout << "=====connect mode start=====" << endl;
    int dest_host_socket = create_conn_to_dest();

    fd_set all_fds;
    // fd_set tmp_fds;
    int fdmax;

    FD_ZERO(&all_fds);
    // FD_ZERO(&tmp_fds);
    FD_SET(browser_socket, &all_fds);
    FD_SET(dest_host_socket,&all_fds);

    if(dest_host_socket > browser_socket){
        fdmax = dest_host_socket;
    }else{
        fdmax = browser_socket;
    }

    show_server_message();
    relay_traffic(browser_socket, dest_host_socket, fdmax, all_fds);
    cout << "=====connect mode end=====" << endl;
}

int create_bind_mode_sock(){
    struct sockaddr_in bind_addr;

    int bind_mode_sock = socket(AF_INET, SOCK_STREAM, 0);
    if(bind_mode_sock < 0){
        printf("caanot create bindmode socket\n");
        return -1;
    }
    printf("create bindmode socket\n");

    bzero((char *)&bind_addr, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = INADDR_ANY;
    bind_addr.sin_port = htons(INADDR_ANY);

    int reuse = 1;
    if (setsockopt(bind_mode_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0)
            perror("setsockopt(SO_REUSEADDR) failed");
    #ifdef SO_REUSEPORT
        if (setsockopt(bind_mode_sock, SOL_SOCKET, SO_REUSEPORT, (const char*)&reuse, sizeof(reuse)) < 0) 
            perror("setsockopt(SO_REUSEPORT) failed");
    #endif

    if(bind(bind_mode_sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0){
        printf("can't bind any port\n");
        return -1;
    }
    printf("bind port success\n");

    if(listen(bind_mode_sock, 5) < 0){
        printf("can't listen on port\n");
        return -1;
    }

    printf("bindmode server wait for connection\n\n");
    return bind_mode_sock;
}


void bind_mode_handler(){
    cout << "=====bind mode start=====" << endl;

    //create bind_mode socket for ftp connection and send reply to browser
    int bind_mode_sock;
    bind_mode_sock = create_bind_mode_sock();
    if(bind_mode_sock < 0) return;
    struct sockaddr_in tmp_addr, ftp_addr;
    size_t len = sizeof(tmp_addr);
    if(getsockname(bind_mode_sock, (struct sockaddr *)&tmp_addr, (socklen_t*)&len) < 0){
        printf("getsockname fail\n");
        return;
    }
    dest_bind_port = ntohs(tmp_addr.sin_port);
    send_reply(90);

    //accept connection from ftp server and send reply to browser again
    int ftp_sock;
    ftp_sock = accept(bind_mode_sock, (struct sockaddr *)&ftp_addr, (socklen_t*)&len);
    if (ftp_sock < 0){
        puts("Server : Accept ftp connection failed");
        return;
    }
    send_reply(90);

    //start relaying traffic
    fd_set all_fds;
    int fdmax;

    FD_ZERO(&all_fds);
    FD_SET(browser_socket, &all_fds);
    FD_SET(ftp_sock,&all_fds);

    if(ftp_sock > browser_socket){
        fdmax = ftp_sock;
    }else{
        fdmax = browser_socket;
    }
    relay_traffic(browser_socket, ftp_sock, fdmax, all_fds);
    cout << "=====bind mode end=====" << endl;
}

void browser_handler(){
    int n;
    char buf[buffersize];
    n = read(browser_socket,buf,sizeof(buf));
    if(n < 8){
        printf("read sock4 error\n");
        return;
    }
    
    parse_socks4_request(buf);
    if(!pass_firewall()){
        //send reject reply
        send_reply(91);
        return;
        
    }else{
        if(cur_mode == "c"){
            //connection mode
            send_reply(90);
            connect_mode_handler();
        }else if(cur_mode == "b"){
            bind_mode_handler();
        }else{
            //mode??
            //send reply
            send_reply(90);
            cout << "browser_handler strange mode??" << endl;
        }
    }
}
