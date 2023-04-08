/* C++ standard include files first */
#include <iostream>
#include <iomanip>
#include <string>

using namespace std;

/* C system include files next */
#include <arpa/inet.h>
#include <netdb.h>

/* C standard include files next */
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>

/* your own include last */
#include "my_socket.h"
#include <ctime>
#include <sys/time.h>
#include "my_timestamp.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <thread>
#include <mutex>
#include <memory>
#include <queue>
#include <condition_variable>
#include <unordered_map>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unordered_set>
#include <fcntl.h>
#include <sys/ioctl.h>

// function to flush socket
void flush_socket(int sockfd) {
    // Set the socket to non-blocking mode
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags == -1) {
        std::cerr << "Error getting socket flags: " << errno << std::endl;
        return;
    }
    
    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) == -1) {
        std::cerr << "Error setting socket to non-blocking: " << errno << std::endl;
        return;
    }

    char buffer[1024];
    ssize_t bytesRead = 0;

    // Continuously read from the socket until there is no more data
    do {
        bytesRead = recv(sockfd, buffer, sizeof(buffer), 0);

        if (bytesRead == -1 && errno != EAGAIN && errno != EWOULDBLOCK) {
            std::cerr << "Error reading from socket: " << errno << std::endl;
            break;
        }
    } while (bytesRead > 0);

    // Restore the original socket flags
    if (fcntl(sockfd, F_SETFL, flags) == -1) {
        std::cerr << "Error restoring socket flags: " << errno << std::endl;
    }
}

// set the socket to blocking or non-blocking mode
bool set_blocking_mode(int socket_fd, bool blocking) {
    int flags = fcntl(socket_fd, F_GETFL, 0);
    if (flags == -1) {
        perror("Error: fcntl(F_GETFL)");
        return false;
    }

    cout << "Before change, socket flags: " << flags << endl;

    if (blocking) {
        flags &= ~O_NONBLOCK;
    } else {
        flags |= O_NONBLOCK;
    }

    int ioctl_result = ioctl(socket_fd, FIONBIO, &flags);
    if (ioctl_result == -1) {
        perror("Error: ioctl(FIONBIO)");
        return false;
    }

    cout << "After change, socket flags: " << flags << endl;
    cout << "ioctl_result: " << ioctl_result << endl;

    return true;
}

static
int non_ASCII(char ch)
{
    if (ch >= 0x20 && ch < 0x7f) return 0;
    switch (ch) {
    case '\r': return 0;
    case '\n': return 0;
    case '\t': return 0;
    default: break;
    }
    return 1;
}

int my_debug_header_lines = 0;
int read_a_line(int socket_fd, string& line)
{
    string s = "";
    int idx = 0;
    char ch = '\0';
    int debug = 1; /* not a good idea to change this! */

    for (;;) {
        cout << "Before calling read() in read_a_line()" << endl;
        int bytes_read = read(socket_fd, &ch, 1);
        cout << "After calling read() in read_a_line(), n = " << bytes_read << endl;
        if (bytes_read < 0) {
            if (errno == EINTR) {
                /* not a real error, must retry */
                continue;
            }
            /* a real error, no need to return a line */
            return (-1);
        } else if (bytes_read == 0) {
            /*
             * according to man pages, 0 means end-of-file
             * if we don't break here, read() will keep returning 0!
             */
            if (idx == 0) {
                /* if no data has been read, just treat end-of-file as an error */
                return (-1);
            }
            /*
             * the last line does not terminate with '\n'
             * return the last line (which does not end with '\n')
             */
            break;
        } else {
            /*
             * being super paranoid and harsh here
             * if you are expecting binary data, you shouldn't be calling read_a_line()
             */
            if (debug && non_ASCII(ch)) {
                /*
                 * if you don't want to abort and crash your program here, you can set debug = 0 above
                 * although I would strongly encourage you not to do that and fix your bugs instead
                 */
                cerr << "Encountered a non-ASCII character (0x" << setfill('0') << setw(2) << hex << (int)ch << ") in read_a_line().  Abort program!" << endl;
                shutdown(socket_fd, SHUT_RDWR);
                close(socket_fd);
                exit(-1);
            }
            s += ch;
            idx++;
            if (ch == '\n') {
                break;
            }
        }
    }
    line = s;
    {   /* [BC: added 1/16/2023 to improve debugging */
        if (my_debug_header_lines) {
            cout << "\t" << line;
            cout.flush();
        }
    }
    cout << "Returning from read_a_line(), line = " << line << endl;

    return idx;
}


int better_write(int fd, const char *buf, int bytes_to_write)
{
    int bytes_remaining = bytes_to_write;

    while (bytes_remaining > 0) {
        int bytes_written = write(fd, buf, bytes_remaining);

        if (bytes_written > 0) {
            bytes_remaining -= bytes_written;
            buf += bytes_written;
        } else if (bytes_written == (-1)) {
            if (errno == EINTR) {
                continue;
            }
            /* a real error, abort write() */
            return (-1);
        }
    }
    return bytes_to_write;
}

// function to parse INI file
string parse_ini(string key_name, string section_name, string filename){
    string line;
    string value;
    ifstream file(filename);

    if (!file) {
        cout << "Cannot open file " << filename << endl;
        return "";
     }
    bool in_section = false;

    while (getline(file, line)) {
        if (line.empty() || line[0] == ';') {
            continue;
        }
        if (line[0] == '[') {
            size_t end = line.find(']');
            if (end != string::npos) {
                in_section = (line.substr(1, end - 1) == section_name);
            }
        } 
        else if (in_section) {
            size_t pos = line.find('=');
            if (pos != string::npos) {
                string key = line.substr(0, pos);
                if (key == key_name) {
                    value = line.substr(pos + 1);
                    break;
                }
            }
        }
    }
    file.close();
    if (value.empty()) {
        // value is empty
        return "";
    } else {
        // value is not empty
        return value;
    }
}

/* GLOBAL VARIABLES */

mutex m; // Initialize a mutex

int listen_socket_fd = (-1); /* there is nothing wrong with using a global variable */
string logfile_name;
string ini_file_name;

int neighbor_retry_interval;
int msg_lifetime;
int max_ttl;

string NodeID;

bool log_in_file_SAYHELLO;
bool log_in_file_LSUPDATE;


/* END OF GLOBAL VARIABLES */

class Message{
public:
    string command; // Command (i.e SAYHELLO, LSUPDATE, etc.)
    string from; // NodeID of the sender

    int ttl; // Time to live
    int flood; // Flood ID
    int content_length; // Length of the message body

    Message() {}
};

class Connection {
public:
    int socket_fd; /* -1 means closed by connection-handling thread, -2 means close by console thread and connection may still be active */
    int orig_socket_fd; /* copy of the original socket_fd */
    int bytes_sent; /* number of bytes of response body written into the socket */
    int response_body_length; /* size of the response body in bytes, i.e., Content-Length */

    shared_ptr<thread> read_thread_ptr; /* shared pointer to a socket-reading thread */
    shared_ptr<thread> write_thread_ptr; /* shared pointer to a socket-writing thread */

    string neighbor_nodeid; /* nodeid of the neighbor node to whom we are connected to */

    /* the next 3 objects are for the socket-reading thread to send work to the corresponding socket-writing thread */
    shared_ptr<mutex> m; /* this is a "2nd-level" mutex */ 
    shared_ptr<condition_variable> cv;
    queue<shared_ptr<Message> > q;

    Connection() : socket_fd(-1), read_thread_ptr(NULL), write_thread_ptr(NULL), m(NULL), cv(NULL) { q = queue<shared_ptr<Message> >(); }
    Connection(int s, shared_ptr<thread> tr, shared_ptr<thread> tw) {
        socket_fd = orig_socket_fd = s;
        read_thread_ptr = tr;
        write_thread_ptr = tw;
        bytes_sent = response_body_length = 0;
        m = make_shared<mutex>();
        cv = make_shared<condition_variable>();
        q = queue<shared_ptr<Message> >();
        cout << "Connection object created" << endl << std::flush;
    }
    ~Connection() {
        cout << "Connection object destroyed" << endl << std::flush;
    }

    void add_work(shared_ptr<Message> msg) { 
        this->m->lock();
        this->q.push(msg);
        this->cv->notify_all();
        this->m->unlock();
     }

    shared_ptr<Message> wait_for_work() { 
        try {
            unique_lock<mutex> l(*this->m);

            while (q.empty()) {
                this->cv->wait(l);
            }
            shared_ptr<Message> msg = this->q.front();
            this->q.pop();

            return msg;
        } catch (const std::system_error& e) {
            cerr << "System error caught (wait_for_work): " << e.what() << " (" << e.code() << ")" << endl;
            throw; // Re-throw the exception if you want the program to terminate or handle it in another way
        }
     }
};


// Variables to control the behavior of the reaper thread
queue<shared_ptr<Connection> > q;
condition_variable cv;

// list of connections
vector<shared_ptr<Connection> > connection_list;

void reaper_add_work(shared_ptr<Connection> conn_ptr) {
  m.lock();
  q.push(conn_ptr);
  cv.notify_all();
  m.unlock();
}

shared_ptr<Connection> reaper_wait_for_work() {
  unique_lock<mutex> l(m);

  while (q.empty()) {
    cv.wait(l);
  }
  shared_ptr<Connection> conn_ptr = q.front();
  q.pop();

  return conn_ptr;
}

// create message
shared_ptr<Message> create_message(int socket_fd, string command) {
    if(command == "SAYHELLO"){
        shared_ptr<Message> msg = make_shared<Message>();
        msg->command = "SAYHELLO";
        msg->ttl = 1;
        msg->flood = 0;
        msg->from = NodeID;

        return msg;
    }
    else if(command == "LSUPDATE"){
        return nullptr;
    }
    return nullptr;
}

// retrieve message
shared_ptr<Message> read_message(shared_ptr<Connection> conn_ptr) {

    try{
        int bytes_received = 0;
        string line;
        string request;

        // Set socket to blocking mode
        m.lock();
        int flags = fcntl(conn_ptr->socket_fd, F_GETFL, 0);
        if (flags == -1) {
            int err = errno;
            cerr << "Error: fcntl() failed with error: " << strerror(err) << " (" << err << ")" << endl;
            return nullptr;
        }
        flags &= ~O_NONBLOCK;
        if (fcntl(conn_ptr->socket_fd, F_SETFL, flags) == -1) {
            int err = errno;
            cerr << "Error: fcntl() failed with error: " << strerror(err) << " (" << err << ")" << endl;
            return nullptr;
        }
        m.unlock();

        // Read header
        while (true) {

            timeval tv;
            tv.tv_sec = 5;
            tv.tv_usec = 0;

            fd_set read_fds;
            FD_ZERO(&read_fds);
            FD_SET(conn_ptr->socket_fd, &read_fds);
            int select_result = select(conn_ptr->socket_fd + 1, &read_fds, NULL, NULL, &tv);

            cout << "select_result: " << select_result << endl;
            cout << "socket_fd: " << conn_ptr->socket_fd << endl;

            if (select_result == -1) {
                int err = errno;
                cerr << "Error: select() failed with error: " << strerror(err) << " (" << err << ")" << endl;
                return nullptr;
            }
            else if (select_result == 0) {
                // No data available on the socket, keep waiting
                continue;
            }

            m.lock();
            cout << "Entering read_a_line()" << endl;
            bytes_received = read_a_line(conn_ptr->socket_fd, line);
            m.unlock();

            if (bytes_received < 0) {
                int err = errno;
                cerr << "Error: read_a_line() failed with error: " << strerror(err) << " (" << err << ")" << endl;
                return nullptr;
            }
            request += line;

            if (line.size() == 2 && line[0] == '\r') {
                break;
            }
        }

        // Set socket back to non-blocking mode
        flags |= O_NONBLOCK;
        if (fcntl(conn_ptr->socket_fd, F_SETFL, flags) == -1) {
            int err = errno;
            cerr << "Error: fcntl() failed with error: " << strerror(err) << " (" << err << ")" << endl;
            return nullptr;
        }

        if (request.empty()) {
            cerr << "Error: request is empty" << endl;
            return nullptr;
        }
        else{
            cout << "Request: " << request << endl;
        }

        shared_ptr<Message> message = make_shared<Message>();

        // Parse command type
        if (request.find("SAYHELLO") != string::npos) {
            message->command = "SAYHELLO";

            // Parse rest of the SAYHELLO message
            size_t pos = request.find("\r\n") + 2;
            while (pos < request.length() && request[pos] != '\r') {
                size_t end = request.find(": ", pos);
                if (end == string::npos) {
                    break;
                }
                string field_name = request.substr(pos, end - pos);
                pos = end + 2;
                end = request.find("\r\n", pos);
                if (end == string::npos) {
                    break;
                }
                string value = request.substr(pos, end - pos);
                pos = end + 2;
                if (field_name == "TTL") {
                    message->ttl = stoi(value);
                } else if (field_name == "Flood") {
                    message->flood = stoi(value);
                } else if (field_name == "From") {
                    message->from = value;
                } else if (field_name == "Content-Length") {
                    message->content_length = stoi(value);
                    break;
                }
            }
            
            // Flush the socket after reading the message
            flush_socket(conn_ptr->socket_fd);

            return message;
        }
    } 
    catch (const std::exception& e) {
        cerr << "An error occurred in read_message(): " << e.what() << endl;
        return nullptr;
    }
}

//  socket-reading thread
void read_from_client(shared_ptr<Connection> conn_ptr) {
    
    m.lock();
    m.unlock();

    try{
        if (!set_blocking_mode(conn_ptr->socket_fd, true)) {
            cerr << "Error: Failed to set socket to blocking mode" << endl;
            // Handle the error, close the socket, etc.
        }
        shared_ptr<Message> msg = read_message(conn_ptr);

        if (msg != nullptr && msg->command == "SAYHELLO") {
            // do something
            if(!log_in_file_SAYHELLO){
                struct timeval now;
                gettimeofday(&now, NULL);
                cout << "[" << format_timestamp(&now) << "] r SAYHELLO" << NodeID << " " << msg->ttl << " - 0\n";
            }
            else{
                ofstream logfile(logfile_name, ios::app);
                struct timeval now;
                gettimeofday(&now, NULL);
                logfile << "[" << format_timestamp(&now) << "] r SAYHELLO" << NodeID << " " << msg->ttl << " - 0\n";
                logfile.close();
            }

        } 
        else{
            cerr << "ERROR: first message not SAYHELLO" << endl;
            exit(1);
        }

        bool is_duplicate_connection = false;

        // this connection was created in MAIN THREAD
        if(conn_ptr->neighbor_nodeid == ""){
            m.lock();
            for(auto it = connection_list.begin(); it != connection_list.end(); it++){
                if( (*it)->neighbor_nodeid != "" && (*it)->neighbor_nodeid == msg->from){
                    is_duplicate_connection = true;
                    break;
                }
            }
            m.unlock();

            if(!is_duplicate_connection){
                conn_ptr->neighbor_nodeid = msg->from;
                auto w = create_message(conn_ptr->socket_fd, "SAYHELLO");
                conn_ptr->add_work(w);
            }
        }
        // this connection was created in NEIGHBOR THREAD
        else{
            for(auto it = connection_list.begin(); it != connection_list.end(); it++){
                if((*it)->neighbor_nodeid == msg->from && (*it)->neighbor_nodeid != ""){
                    is_duplicate_connection = true;
                    break;
                }
            }
        }

        if(!is_duplicate_connection){
            // do forever
            while(true){
                
                // reading message
                try{
                    int bytes_received = 0;
                    string line;
                    string request;

                    // Set socket to blocking mode
                    m.lock();
                    int flags = fcntl(conn_ptr->socket_fd, F_GETFL, 0);
                    if (flags == -1) {
                        int err = errno;
                        cerr << "Error: fcntl() failed with error: " << strerror(err) << " (" << err << ")" << endl;
                    }
                    flags &= ~O_NONBLOCK;
                    if (fcntl(conn_ptr->socket_fd, F_SETFL, flags) == -1) {
                        int err = errno;
                        cerr << "Error: fcntl() failed with error: " << strerror(err) << " (" << err << ")" << endl;
                    }

                    if (!set_blocking_mode(conn_ptr->socket_fd, true)) {
                        cerr << "Error: Failed to set socket to blocking mode" << endl;
                        // Handle the error, close the socket, etc.
                    }
                    m.unlock();

                    // Read header
                    while (true) {

                        timeval tv;
                        tv.tv_sec = 5;
                        tv.tv_usec = 0;

                        m.lock();
                        fd_set read_fds;
                        FD_ZERO(&read_fds);
                        FD_SET(conn_ptr->socket_fd, &read_fds);
                        int select_result = select(conn_ptr->socket_fd + 1, &read_fds, NULL, NULL, &tv);
                        m.unlock();

                        if (select_result == -1) {
                            int err = errno;
                            cerr << "Error: select() failed with error: " << strerror(err) << " (" << err << ")" << endl;
                            break;;
                        }
                        else if (select_result == 0) {
                            // No data available on the socket, keep waiting
                            continue;
                        }

                        m.lock();
                        cout << "Entering read_a_line()" << endl;
                        bytes_received = read_a_line(conn_ptr->socket_fd, line);
                        m.unlock();

                        if (bytes_received < 0) {
                            int err = errno;
                            cerr << "Error: read_a_line() failed with error: " << strerror(err) << " (" << err << ")" << endl;
                            break;
                        }
                        request += line;

                        if (line.size() == 2 && line[0] == '\r') {
                            break;
                        }
                    }

                    // Set socket back to non-blocking mode
                    flags |= O_NONBLOCK;
                    if (fcntl(conn_ptr->socket_fd, F_SETFL, flags) == -1) {
                        int err = errno;
                        cerr << "Error: fcntl() failed with error: " << strerror(err) << " (" << err << ")" << endl;
                    }

                    if (request.empty()) {
                        cerr << "Error: request is empty" << endl;
                        break;
                    }
                    else{
                        cout << "Request: " << request << endl;
                    }

                    shared_ptr<Message> message = make_shared<Message>();

                    // Parse command type
                    if (request.find("SAYHELLO") != string::npos) {
                        message->command = "SAYHELLO";

                        // Parse rest of the SAYHELLO message
                        size_t pos = request.find("\r\n") + 2;
                        while (pos < request.length() && request[pos] != '\r') {
                            size_t end = request.find(": ", pos);
                            if (end == string::npos) {
                                break;
                            }
                            string field_name = request.substr(pos, end - pos);
                            pos = end + 2;
                            end = request.find("\r\n", pos);
                            if (end == string::npos) {
                                break;
                            }
                            string value = request.substr(pos, end - pos);
                            pos = end + 2;
                            if (field_name == "TTL") {
                                message->ttl = stoi(value);
                            } else if (field_name == "Flood") {
                                message->flood = stoi(value);
                            } else if (field_name == "From") {
                                message->from = value;
                            } else if (field_name == "Content-Length") {
                                message->content_length = stoi(value);
                                break;
                            }
                        }
                    }

                    m.lock();
                    if(message == nullptr || listen_socket_fd < 0){
                        m.unlock();
                        break;
                    }
                    m.unlock();

                    // treat message


                } 
                catch (const std::exception& e) {
                    cerr << "An error occurred in while reading message in socket-reading: " << e.what() << endl;
                } catch (...) {
                    cerr << "An unknown error occurred while reading message in socket-reading" << endl;
                }                
            }
        }
    }
    catch (const std::system_error& e) {
        cerr << "System error caught in read_from_client: " << e.what() << " (" << e.code() << ")" << endl;
    } catch (const std::exception& e) {
        cerr << "Exception caught in read_from_client: " << e.what() << endl;
    } catch (...) {
        cerr << "Unknown exception caught in read_from_client" << endl;
    }

    m.lock();
    if (conn_ptr->socket_fd >= 0) {
        shutdown(conn_ptr->socket_fd, SHUT_RDWR);
    }
    conn_ptr->socket_fd = -1;
    m.unlock();

    // Signal the socket-writing thread to self-terminate
    conn_ptr->add_work(nullptr);

    // Join with the socket-writing thread
    conn_ptr->write_thread_ptr->join();

    // Add dead connection to the reaper work queue
    cerr << "Adding connection to reaper work queue" << endl;
    reaper_add_work(conn_ptr);
}

//  socket-writing thread
void write_to_client(shared_ptr<Connection> conn_ptr) {
    
    m.lock();
    m.unlock();

    try {
        while (true)
        {
            shared_ptr<Message> w = conn_ptr->wait_for_work();

            if(w == nullptr){
                break;
            }
            else if (w->command == "SAYHELLO")
            {
                stringstream message_data;
                message_data << "353NET/1.0 SAYHELLO\r\n";
                message_data << "TTL: " << w->ttl << "\r\n";
                message_data << "Flood: " << w->flood << "\r\n";
                message_data << "From: " << w->from << "\r\n";
                message_data << "Content-Length: 0\r\n";
                message_data << "\r\n";

                string response = message_data.str();

                if(!log_in_file_SAYHELLO){
                    struct timeval now;
                    gettimeofday(&now, NULL);
                    cout << "[" << format_timestamp(&now) << "] i SAYHELLO" << NodeID << " " << w->ttl << " - 0\n";
                }
                else{
                    ofstream logfile(logfile_name, ios::app);
                    struct timeval now;
                    gettimeofday(&now, NULL);
                    logfile << "[" << format_timestamp(&now) << "] i SAYHELLO" << NodeID << " " << w->ttl << " - 0\n";
                    logfile.close();
                }

                try {
                    conn_ptr->m->lock();
                    better_write(conn_ptr->socket_fd, response.c_str(), response.length());
                    conn_ptr->m->unlock();
                } catch (const std::system_error& e) {
                    cerr << "System error caught in write_to_client while doing better_write: " << e.what() << " (" << e.code() << ")" << endl;
                }
            }
        }
    } catch (const std::system_error& e) {
        cerr << "System error caught in write_to_client: " << e.what() << " (" << e.code() << ")" << endl;
    } catch (const std::exception& e) {
        cerr << "Exception caught in write_to_client: " << e.what() << endl;
    } catch (...) {
        cerr << "Unknown exception caught in write_to_client" << endl;
    }
}

// neighbors thread
void neighbors_thread(){

    // read CONFIGFILE to create a list of potential neighbors
    unordered_set<string> potential_neighbors;
    string neighbors_str = parse_ini(NodeID, "topology", ini_file_name );

    if (neighbors_str != "empty") {
        stringstream ss(neighbors_str);
        string neighbor;

        while (getline(ss, neighbor, ',')) {
            potential_neighbors.insert(neighbor);
        }
    }

    while(true){
        unordered_set<string> neighbors = potential_neighbors;

        m.lock();
        if (listen_socket_fd == (-1)) {
            m.unlock();
            break;
        }
        else{
            for(auto it = connection_list.begin(); it != connection_list.end(); it++){
                if((*it)->neighbor_nodeid != ""){
                    neighbors.erase((*it)->neighbor_nodeid);
                }
            }
        }
        m.unlock();

        // neighbors is now a list of inactive neighbors
        for(auto it = neighbors.begin(); it != neighbors.end(); it++){

            // retrieve substring of it before the first ":"
            string host = (*it).substr(0, (*it).find(":"));
            // if host is empty, set it to "localhost"
            if(host == ""){
                host = LOCALHOST;
            }
            // retrieve substring of it after the first ":"
            string port = (*it).substr((*it).find(":") + 1);

            int socket = create_client_socket_and_connect(host.c_str(), port.c_str());
            int flags = fcntl(socket, F_GETFL, 0);
            if (flags != -1) {
                flags = flags & ~O_NONBLOCK; // Clear O_NONBLOCK flag
                fcntl(socket, F_SETFL, flags);
            }

            if (socket >= 0)
            {
                // create a new connection object
                cout << "Creating new connection object in neighbors thread for " << *it << endl;

                m.lock();
                shared_ptr<Connection> conn_ptr = make_shared<Connection>();

                // set the socket_fd field of the connection object to the socket
                conn_ptr->socket_fd = socket;

                // set the m and cv fields of the connection object to new mutex and condition_variable objects
                conn_ptr->m = make_shared<mutex>();
                conn_ptr->cv = make_shared<condition_variable>();

                // create a new socket-writing thread
                conn_ptr->write_thread_ptr = make_shared<thread>(write_to_client, conn_ptr);
                // create a new socket-reading thread
                conn_ptr->read_thread_ptr = make_shared<thread>(read_from_client, conn_ptr);
                // set the neighbor_nodeid field of the connection object to n
                conn_ptr->neighbor_nodeid = *it;

                // send a SAYHELLO message to n
                shared_ptr<Message> w = create_message(conn_ptr->socket_fd, "SAYHELLO");
                conn_ptr->add_work(w);

                // add the connection object to the connection list
                connection_list.push_back(conn_ptr);
                m.unlock();
            }
        }

        // sleep for neighbor_retry_interval seconds
        this_thread::sleep_for(chrono::seconds(neighbor_retry_interval));
    }
}


// Console thread function
void console_thread(){

    string input;
    bool quit = false;

    while (!quit){
        cout << "> ";
        getline(cin, input);

        // neighbors command
        if (input == "neighbors"){

            m.lock();
            vector<string> active_neighbors;
            for(auto it = connection_list.begin(); it != connection_list.end(); it++){
                if((*it)->neighbor_nodeid != ""){
                    active_neighbors.push_back((*it)->neighbor_nodeid);
                }
            }

            if (active_neighbors.size() == 0) {
                cout << "\t" << NodeID << " has no active neighbors\n";
            }
            else {
                cout << "\tActive neighbors of " << NodeID << ":\n";
                cout << "\t";
                for (auto& nei : active_neighbors) {
                    cout << nei;
                    if (nei != active_neighbors.back()) {
                        cout << ", ";
                    }
                }
                cout << "\n";
            }
            m.unlock();

        }
        // quit command
        else if (input == "quit") {
            reaper_add_work(nullptr);
            quit = true;
        } 
        // print the help message if anything else was commanded
        else {
            cout << "Available commands are:\n"
                 << "\tneighbors\n"
                 << "\tquit\n";
        }

    }

    // close the listening socket (this will force my_accept() to return with an error code in the main thread), set the listening socket to be (-1)
    m.lock();

    shutdown(listen_socket_fd, SHUT_RDWR);
    close(listen_socket_fd);
    listen_socket_fd = -1;

    for (auto& conn_ptr : connection_list) {
        if (conn_ptr->socket_fd >= 0) {
            shutdown(conn_ptr->socket_fd, SHUT_RDWR);
            close(conn_ptr->socket_fd);
            conn_ptr->socket_fd = -2;
        }
    }

    m.unlock();

    return;
}

// Reaper thread function
void reaper_thread() {

    ofstream logfile(logfile_name, ios::app);

    // First do-while loop
    while (true) {
        shared_ptr<Connection> c = reaper_wait_for_work();
        if (c == nullptr || listen_socket_fd == -1) {
            break;
        } else {

            if (c->read_thread_ptr && c->read_thread_ptr->joinable()){
                c->read_thread_ptr->join();
            }

            m.lock();
            connection_list.erase(remove(connection_list.begin(), connection_list.end(), c), connection_list.end());
            m.unlock();
        }
    }

    // Second do-while loop
    while (true) {
        m.lock();
        if (connection_list.empty()) {
            m.unlock();
            break;
        }
        shared_ptr<Connection> c2 = connection_list.front();
        m.unlock();
        c2->read_thread_ptr->join();
        
        m.lock();
        connection_list.erase(connection_list.begin());
        m.unlock();
    }

    logfile.close();
}

int main(int argc, char *argv[])
{
    std::cout.setf(std::ios::unitbuf);

    // Retrieve the INI file_name from the command line
    if (argc != 2) {
        cout << "Usage: " << argv[0] << " <port> <logfile>\n";
        return 1;
    }

    ini_file_name = argv[1];

    // parse the INI file
    string host = parse_ini("host", "startup", ini_file_name);
    string port = parse_ini("port", "startup", ini_file_name);
    logfile_name = parse_ini("logfile", "startup", ini_file_name);

    NodeID = host + ":" + port;

    neighbor_retry_interval  = stoi(parse_ini("neighbor_retry_interval", "params", ini_file_name));
    max_ttl = stoi(parse_ini("max_ttl", "params", ini_file_name));
    msg_lifetime = stoi(parse_ini("msg_lifetime", "params", ini_file_name));

    // Deciding wether or not the log in file
    string log_for_SAYHELLO = parse_ini("SAYHELLO", "logging", ini_file_name);
    if(log_for_SAYHELLO == "0"){
        log_in_file_SAYHELLO = false;
    }else{
        log_in_file_SAYHELLO = true;
    }

    string log_for_LSUPDATE = parse_ini("LSUPDATE", "logging", ini_file_name);
    if(log_for_LSUPDATE == "0"){
        log_in_file_LSUPDATE = false;
    }else{
        log_in_file_LSUPDATE = true;
    }

    // Create a server listening socket 
    listen_socket_fd = create_listening_socket(port);

    if (listen_socket_fd != (-1)) {
        
        ofstream logfile(logfile_name, ios::app);

        // start console thread
        thread console(console_thread);

        // start reaper thread
        thread reaper(reaper_thread);

        // start the neighbor thread
        thread neighbor(neighbors_thread);

        for (;;) {
            int newsockfd = my_accept(listen_socket_fd);
            if (newsockfd == (-1)) break;
            int flags = fcntl(newsockfd, F_GETFL, 0);
            if (flags != -1) {
                flags = flags & ~O_NONBLOCK; // Clear O_NONBLOCK flag
                fcntl(newsockfd, F_SETFL, flags);
            }
                        
            m.lock();
            if (listen_socket_fd == (-1)){
                shutdown(newsockfd, SHUT_RDWR);
                close(newsockfd);
                m.unlock();
                break;
            } 

            cerr << "Accepted connection in main thread\n";
            shared_ptr<Connection> conn_ptr = make_shared<Connection>();

            conn_ptr->socket_fd = newsockfd;
            // set the m and cv fields of the connection object to new mutex and condition_variable objects
            conn_ptr->m = make_shared<mutex>();
            conn_ptr->cv = make_shared<condition_variable>();
            
            // Initialize the readn and write threads
            conn_ptr->read_thread_ptr = make_shared<thread>(read_from_client, conn_ptr);
            conn_ptr->write_thread_ptr = make_shared<thread>(write_to_client, conn_ptr);

            // set neighbor_nodeid to null
            conn_ptr->neighbor_nodeid = "";

            connection_list.push_back(conn_ptr);
            m.unlock();
        }

        // join console thread
        console.join();
        // join reaper thread
        reaper.join();
        // join neighbor thread
        neighbor.join();

        // Join with all connection-handling threads
        for (const auto& conn_ptr : connection_list) {
            if (conn_ptr->read_thread_ptr && conn_ptr->read_thread_ptr->joinable()) {
                conn_ptr->read_thread_ptr->join();
            }
            if (conn_ptr->write_thread_ptr && conn_ptr->write_thread_ptr->joinable()) {
                conn_ptr->write_thread_ptr->join();
            }
        }

    }
        
    
    return 0;
}
