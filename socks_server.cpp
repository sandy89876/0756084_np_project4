#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/types.h>
#include <netdb.h>
#include <errno.h>

#include <strings.h>
#include <string.h>
#include <fstream>
#include <vector>

using namespace std;

#define BUFFER_SIZE 20000

int socketfd;
int browser_socket;
int client_port;
string client_ip;

//variable for sock4 request
uint8_t test[2];
unsigned char VN, CD;
char buffer[BUFFER_SIZE];
uint8_t dest_ip[4];
uint16_t dest_bind_port,dest_port;
string dest_ip_arr[4];//['140','113','x','x']
string formatted_dest_ip;//140.113.x.x
char* user_id;
string cur_mode;
string reply;

vector<string> split_line(string input,string delimeter);
int create_conn_to_dest();
void send_reply(unsigned char cd);
int redirect_msg(int src_fd, int dest_fd);
void connect_mode_handler();
void browser_handler();
void relay_traffic(int src_socket, int dest_socket, int fdmax, fd_set &all_fds);
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
        }
    }
}

vector<string> split_line(string input,string delimeter){
    char *_delimeter = new char[delimeter.length() + 1];
    strcpy(_delimeter, delimeter.c_str());

    char *comm = new char[input.length()+1];
    strcpy(comm, input.c_str());
    
    char* token = strtok(comm, _delimeter);
    vector<string> result;
    while(token != NULL){
        result.push_back(token);
        token = strtok(NULL, _delimeter);
    }
    return result;
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
    // cout << "dest_ip= " <<formatted_dest_ip << " dest_port = " << dest_port << endl;
    if(connect(client_fd, (struct sockaddr *)&client_sin, sizeof(client_sin)) < 0){
        printf("connect error\nerrorno=%d",errno);
        return -1;
    }
    return client_fd;
}

void parse_socks4_request(char *buf){
    VN = buf[0];
    CD = buf[1];
    test[0] = buf[2];
    test[1] = buf[3];
    dest_port = test[0] * 256 + test[1];
    user_id = buf + 8;
    cout << "dest_port= " << dest_port << endl;
    if(CD == 1){
        cur_mode = "c";
    }else if(CD == 2){
        cur_mode = "b";
    }
    cout << "cur_mode = " << cur_mode << endl;
    for(int i=0; i<4; i++){
        dest_ip[i] = buf[4+i];
        dest_ip_arr[i] = to_string(dest_ip[i]);
        formatted_dest_ip += (dest_ip_arr[i] + ".");
    }
    formatted_dest_ip = formatted_dest_ip.substr(0,formatted_dest_ip.length()-1);
    cout << "formatted_dest_ip= " << formatted_dest_ip << endl;
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
            // cout << "rule:" << line << endl;

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
                // cout << "*it = " << *it << " and dest_ip_arr[it - rule_ips.begin()] = " << dest_ip_arr[it - rule_ips.begin()] << endl;
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
    package[0] = 0;
    package[1] = cd;
    if(cur_mode == "c"){
        package[2] = dest_port / 256;
        package[3] = dest_port % 256;
        package[4] = dest_ip[0];
        package[5] = dest_ip[1];
        package[6] = dest_ip[2];
        package[7] = dest_ip[3];
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
    memset(buffer, 0, BUFFER_SIZE);
    n = read(src_fd, buffer, sizeof(buffer));
    if(n <= 0) {
        // cout << "src_fd read <=0" << endl;
        // perror("read eerr");
        return -1;
    }

    // cout << "<Content>\t:" << buffer;

    //write back to browser client
    n = write(dest_fd, buffer, sizeof(unsigned char)*n);
    if(n <= 0){
        printf("dest_fd write error\n");
        return -1;
    }
    return 1;
}

void relay_traffic(int src_socket, int dest_socket, int fdmax, fd_set &all_fds){
    // cout << "*** start relay traffic between " << src_socket << " and " << dest_socket << endl;
    fd_set tmp_fds;
    int conn = 2;
    while(conn > 0){
        // tmp_fds = all_fds;
        FD_ZERO(&tmp_fds);
        memcpy(&tmp_fds, &all_fds, sizeof(tmp_fds));
        int dest_status, browser_status;
        if(select(fdmax+1, &tmp_fds, NULL, NULL, NULL) == -1){
            perror("select");
            return;
        }

        if(FD_ISSET(dest_socket, &tmp_fds)){
            //redirect msg from dest_host to browser
            dest_status = redirect_msg(dest_socket, src_socket);
            if(dest_status <= 0){
                conn--;
                FD_CLR(dest_socket, &all_fds);
            }
        }
        
        if(FD_ISSET(src_socket, &tmp_fds)){
            //recv msg from browser
            browser_status = redirect_msg(src_socket, dest_socket);
            if(browser_status <= 0){
                conn--;
                FD_CLR(src_socket, &all_fds);
            }
        }
    }
    
    close(dest_socket);
}

void connect_mode_handler(){
    cout << "=====connect mode start=====" << endl;
    int dest_host_socket = create_conn_to_dest();

    fd_set all_fds;
    int fdmax;

    FD_ZERO(&all_fds);
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


    if(listen(bind_mode_sock, 5) < 0){
        printf("can't listen on port\n");
        return -1;
    }

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

    show_server_message();
    relay_traffic(browser_socket, ftp_sock, fdmax, all_fds);
    cout << "=====bind mode end=====" << endl;
}

void browser_handler(){
    int n;
    char buf[BUFFER_SIZE];
    n = recv(browser_socket,buf,sizeof(buf),0);

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
