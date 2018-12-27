#include <iostream>
#include <stdlib.h>
#include <cstring>
#include <vector>
#include <sys/types.h>
#include <sys/socket.h>
#include "boost_util.h"
using namespace std;


//function def
void server_setting(string query_string);
io_service global_io_service;

//global var
int client_num = 0;

string html_content = R"(Content-Type:text/html

<!DOCTYPE html>
<html lang=\"en\">
    <head>
        <meta charset="UTF-8" />
        <title>NP Project 3 Console</title>
        <link
          rel="stylesheet"
          href="https://stackpath.bootstrapcdn.com/bootstrap/4.1.3/css/bootstrap.min.css"
          integrity="sha384-MCw98/SFnGE8fJT3GXwEOngsV7Zt27NXFoaoApmYm81iuXoPkFOJwJ8ERdknLPMO"
          crossorigin="anonymous"
        />
        <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.3.1/jquery.min.js"></script>
        <style>
            table{
                white-space: pre-wrap;
            }
            html{
                font-family: Monospace, Times;
            }
        </style>
    </head>
    <body>
        <table class="table table-dark">
            <tr id="server_title">
            </tr>
            <tr id="console_frame">
            </tr>
        </table>
    </body>
</html>
)";


int main(int argc, const char * argv[]){
    cout << html_content;

    string query_string = getenv("QUERY_STRING");
    server_setting(query_string);

}   

void server_setting(string query_string){
    //todo:create single socket to sock server, and pass to each shellSession?
    //set remote server ip and port to sock request dst ip and port
    cout << "<script>console.log(\"query_string = " << query_string << "\");</script>" << flush;
    string sockIP;
    string sockPort;

    string sock_setting_substr = query_string.substr(query_string.find("sh=")+3);
    cout << "<script>console.log(\"sock_setting_substr =" << sock_setting_substr << "\");</script>" << flush;

    sockIP = sock_setting_substr.substr(0, sock_setting_substr.find("&"));
    sockPort = sock_setting_substr.substr(sock_setting_substr.find("&")+4);
    cout << "<script>console.log(\"sockIP = " << sockIP << "\");</script>" << flush;
    cout << "<script>console.log(\"sockPort = " << sockPort << "\");</script>" << flush;

    string remote_server_substr = query_string.substr(0, query_string.find("sh="));

    vector<string> parameters = split_line(remote_server_substr,"&");
    for(vector<string>::iterator it = parameters.begin(); it != parameters.end(); it = it+3){
        string host_name = (*it).substr((*it).find("=") +1);
        if(host_name != ""){
            client_num++;

            string ip = (*it).substr((*it).find("=") +1);
            string port = (*(it+1)).substr((*(it+1)).find("=") +1);
            string index = (*it).substr(0,(*it).find("="));
            string fileName = "test_case/"+(*(it+2)).substr((*(it+2)).find("=") +1);
            

            //<td>nplinux1</td>
            cout << "<script>$('#server_title').append(\"<td>" << ip << ":" << port << "</td>\");</script>";
            //<td id='h0'></td>
            cout << "<script>$('#console_frame').append(\"<td id=\'" << index << "\'></td>\");</script>";
            
            shared_ptr<shellSession> cur_session(new shellSession(global_io_service, ip, port, index, fileName, sockIP, sockPort));
            cur_session->start();
        }
    }
    global_io_service.run();
}
