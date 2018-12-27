#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <string>
#include <fstream>
#include <boost/algorithm/string/replace.hpp>

using namespace std;
using namespace boost::asio;
using namespace boost::asio::ip;

string format_output(string line){
    int i = line.find("\r");
    if(i != -1){
        line = line.substr(0,i);
    }
    string tmp =R"(\")";
    boost::replace_all(line, "\"", tmp);
    return line;
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

class shellSession: public enable_shared_from_this<shellSession>{
  private:
    string ip;
    string port;
    string index;//h0
    fstream file;
    string _sock_ip;
    string _sock_port;
    uint8_t rs_ip[4];
    uint16_t rs_port;
    bool exit = false;

    tcp::resolver _resolver;
    tcp::socket _socket;
    array<char, 10240> _data;

  public:
    shellSession(io_service& global_io_service, string i, string p, string ind, string f_name, string sock_ip, string sock_port)
    : _socket(global_io_service), _resolver(global_io_service){
        ip = i;
        port = p;
        index = ind;
        _sock_ip = sock_ip;
        _sock_port = sock_port;

        file.open(f_name, ios::in);
        if(!file){
            cout << "<script>console.log(\"cannot open file\");</script>" << flush; 
        }
        cout << "<script>console.log(\"shellSession construct\");</script>" << flush;
    }
    void start(){
        cout << "<script>console.log(\"start called\");</script>" << flush;
        resolve_remote_control_addr();
        
    }
    shared_ptr<shellSession> get_ptr(){
        return shared_from_this();
    }

  private:
    
    void resolve_remote_control_addr(){
        auto self(shared_from_this());
        cout << "<script>console.log(\"ip = " << ip << " and port = " << port << "\");</script>" << flush; 
        tcp::resolver::query query(ip, port);

        _resolver.async_resolve(query, [this,self](boost::system::error_code ec, tcp::resolver::iterator it){
            if(!ec){
                auto self(shared_from_this());
                tcp::endpoint ep = *it;
                vector<string> split_ip = split_line(ep.address().to_string(), ".");

                for(vector<string>::iterator it = split_ip.begin(); it != split_ip.end(); ++it){
                    rs_ip[it - split_ip.begin()] = static_cast<uint8_t>(stoi(*it));
                    // printf("<script>console.log(\"rs_ip[i] = %u\");</script>",rs_ip[it - split_ip.begin()]);
                    // cout << flush;
                } 
                rs_port = static_cast<uint16_t>(stoi(port));
                printf("<script>console.log(\"rs_port = %u\");</script>",rs_port);
                connect_to_sock_server();
            }
        });
    }

    void connect_to_sock_server(){
        //resolve sock server and connect
        auto self(shared_from_this());
        cout << "<script>console.log(\"connect_to_sock_server called\");</script>" << flush;
        tcp::resolver::query query(_sock_ip, _sock_port);

        _resolver.async_resolve(query, [this,self](boost::system::error_code ec, tcp::resolver::iterator it){
            if(!ec){
                auto self(shared_from_this());
                tcp::endpoint ep = *it;
                _socket.async_connect(ep, [this,self](boost::system::error_code ec){
                    send_sock4_request();
                });
            }
        });
    }

    void send_sock4_request(){
        cout << "<script>console.log(\"send_sock4_request called\");</script>" << flush;
        char buff[10240];
        buff[0] = 4;
        buff[1] = 1;
        buff[2] = rs_port / 256;
        buff[3] = rs_port % 256;
        buff[4] = rs_ip[0];
        buff[5] = rs_ip[1];
        buff[6] = rs_ip[2];
        buff[7] = rs_ip[3];
        buff[8] = 0;
        buff[9] = 0;

        string tmp(buff);
        auto self(shared_from_this());
        _socket.async_send(buffer(tmp),[this, self](boost::system::error_code ec, std::size_t length) {
            if(!ec){
                receive_sock4_reply();
            }
        });
    }

    void receive_sock4_reply(){
        cout << "<script>console.log(\"receive_sock4_reply called\");</script>" << flush;
        auto self(shared_from_this());
        _data = {{}};
        _socket.async_read_some(buffer(_data),[this,self](boost::system::error_code ec, size_t length) {
            string tmp(_data.begin(), _data.end());
            if(tmp[0] == 0 && tmp[1] == 90){
                //proxy server accept connection
                //do read and write to remote server
                do_read(ec);
            }
        });
    }
    void do_read(boost::system::error_code ec){
        auto self(shared_from_this());
        if(!ec){
            cout << "<script>console.log(\"do_read called\");</script>" << flush;
            
            _data = {{}};
            // The connection was successful
            _socket.async_read_some(buffer(_data),[this,self](boost::system::error_code ec, size_t length) {
                if (!ec){
                    string tmp(_data.begin(), _data.end());
                    vector<string> msg_lines = split_line(tmp,"\n");
                    for(vector<string>::iterator it = msg_lines.begin(); it != msg_lines.end(); ++it){
                        if((*it).find("\r\r") != 0){
                            if((*it) != "% "){
                                string tmp = format_output(*it);
                                cout << "<script>$('#" << index << "\').text($('#" << index << "\').text() + \"" << tmp << "\\n\");</script>" << flush;
                            }else{
                                cout << "<script>$('#" << index << "\').text($('#" << index << "\').text() + \"" << (*it) << "\");</script>" << flush;
                            }
                        }
                    }
                    if(tmp.find("% ") != -1){
                        do_send();
                    }
                    if(!exit){
                        do_read(ec);
                    }
                }
            });
        }
    }
    void do_send(){
        auto self(shared_from_this());
        string cmd;

        getline(file, cmd);
        int i = cmd.find("\r");
        if(i != -1){
            cmd = cmd.substr(0,i);
        }
        cout << "<script>$('#" << index << "\').text($('#" << index << "\').text() + \"" << cmd << "\\n\");</script>" << flush;
        cmd += "\n";

        if(cmd.find("exit") != string::npos){
            exit = true;
        }
        _socket.async_send(buffer(cmd),[this, self](boost::system::error_code ec, std::size_t length) {
        });
    }
};
