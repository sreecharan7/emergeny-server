#include <iostream>
#include <vector>
#include <cstring>
#include <ifaddrs.h>   
#include <arpa/inet.h> 
#include <netinet/in.h> 
#include <sys/socket.h>
#include <cstdlib>
#include <sstream>
#include <unistd.h>
#include <thread>
#include <atomic>
#include <chrono>
#include <random>
#include <map>
#include <fcntl.h>  

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <memory>

#include <unordered_map>
#include <mutex>


using namespace std;

const int SPORT = 25642;
int CPORT = 25643; //stating port that will check

int currestTID=-1;
map<int, string> emergencyGID;

EVP_PKEY* publicKey;



class ExpiringMap {
public:
    ExpiringMap(int globalExpirationTime) : expirationTime_(globalExpirationTime) {
        expirationTimestamp_ = chrono::steady_clock::now() + chrono::seconds(globalExpirationTime);
    }

    void put(const string& key, const string& value) {
        lock_guard<mutex> lock(mutex_);
        map_[key] = value;
    }

    // Retrieve the value by key; returns a pointer to the string or nullptr
    string* get(const string& key) {
        lock_guard<mutex> lock(mutex_);
        // Check if the map has expired
        if (chrono::steady_clock::now() >= expirationTimestamp_) {
            map_.clear(); // Clear the map if expired
            return nullptr; // Indicate expiration
        }
        auto it = map_.find(key);
        if (it != map_.end()) {
            return &it->second; // Return pointer to the valid value
        }
        return nullptr; // Key not found
    }

    // Optional method to check if the map is expired
    bool isExpired() {
        lock_guard<mutex> lock(mutex_);
        return chrono::steady_clock::now() >= expirationTimestamp_;
    }

private:
    unordered_map<string, string> map_;
    mutex mutex_; // To protect shared data
    chrono::steady_clock::time_point expirationTimestamp_;
    int expirationTime_; // Global expiration time for all entries
};

ExpiringMap exmap(40);


EVP_PKEY* loadPublicKey(const string& publicKeyFile) {
    FILE* file = fopen(publicKeyFile.c_str(), "rb");
    if (!file) {
        cerr << "Failed to open public key file: " << publicKeyFile << endl;
        return nullptr;
    }

    EVP_PKEY* pkey = PEM_read_PUBKEY(file, nullptr, nullptr, nullptr);
    fclose(file);

    if (!pkey) {
        cerr << "Failed to load public key" << endl;
    }
    return pkey;
}

vector<unsigned char> base64Decode(const string& encoded) {
    BIO* bio = BIO_new_mem_buf(encoded.data(), encoded.size());
    BIO* b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    // Decode without expecting newlines
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    vector<unsigned char> decoded(encoded.size());
    int decodedLength = BIO_read(bio, decoded.data(), encoded.size());
    decoded.resize(decodedLength > 0 ? decodedLength : 0);

    BIO_free_all(bio);
    return decoded;
}

bool verifySignature(EVP_PKEY* pkey, const string& message, const string& base64Signature) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX* pkeyCtx = nullptr;

    if (EVP_DigestVerifyInit(ctx, &pkeyCtx, EVP_sha256(), nullptr, pkey) <= 0) {
        cerr << "Error initializing verification context" << endl;
        EVP_MD_CTX_free(ctx);
        return false;
    }

    if (EVP_DigestVerifyUpdate(ctx, message.c_str(), message.size()) <= 0) {
        cerr << "Error updating verification context" << endl;
        EVP_MD_CTX_free(ctx);
        return false;
    }

    // Decode the Base64 signature
    vector<unsigned char> decodedSignature = base64Decode(base64Signature);
    if (decodedSignature.empty()) {
        cerr << "Error decoding Base64 signature" << endl;
        EVP_MD_CTX_free(ctx);
        return false;
    }

    // Verify the decoded signature
    int verifyResult = EVP_DigestVerifyFinal(ctx, decodedSignature.data(), decodedSignature.size());
    EVP_MD_CTX_free(ctx);

    if (verifyResult == 1) {
        return true; // Signature is valid
    } else if (verifyResult == 0) {
        cerr << "Signature verification failed: Signature is invalid" << endl;
        return false;
    } else {
        cerr << "Signature verification failed: Error occurred during verification" << endl;
        return false;
    }
}


vector<vector<string>> getIPAndBroadcastAddresses() {
    vector<vector<string>> ipBroadcastList;
    try {
        struct ifaddrs *ifaddr, *ifa;
        void *addr_ptr;
        if (getifaddrs(&ifaddr) == -1) {
            perror("getifaddrs");
            return ipBroadcastList;
        }
        for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == nullptr) {
                continue;
            }
            if (ifa->ifa_addr->sa_family == AF_INET) {
                addr_ptr = &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, addr_ptr, ip, sizeof(ip));
                addr_ptr = &((struct sockaddr_in *)ifa->ifa_ifu.ifu_broadaddr)->sin_addr;
                char broadcast[INET_ADDRSTRLEN];
                if (ifa->ifa_flags & SO_BROADCAST) {
                    inet_ntop(AF_INET, addr_ptr, broadcast, sizeof(broadcast));
                    vector<string> ipBroadcastPair;
                    ipBroadcastPair.push_back(ip);
                    ipBroadcastPair.push_back(broadcast);
                    ipBroadcastList.push_back(ipBroadcastPair);
                }
            }
        }
        freeifaddrs(ifaddr);
    }catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        exit(2);
    }
    return ipBroadcastList;
}

void broadcastQuery(const string& query,atomic<bool>& running) {
    int sockfd;
    sockaddr_in broadcastAddr;
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        cerr << "Error: Could not create socket." << endl;
        return;
    }
    int broadcastEnable = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &broadcastEnable, sizeof(broadcastEnable)) < 0) {
        cerr << "Error: Could not set socket option." << endl;
        close(sockfd);
        return;
    }
    vector<vector<string>> address = getIPAndBroadcastAddresses();
    if (address.empty()) {
        cout << "There is no broadcasting address to broadcast to." << endl;
        cout << "Stopping the program." << endl;
        exit(3);
    }
    while(running){
        cout<<"contacting the server...."<<endl;
        for (const auto& pair : address) {
            memset(&broadcastAddr, 0, sizeof(broadcastAddr));
            broadcastAddr.sin_family = AF_INET;
            broadcastAddr.sin_port = htons(SPORT);
            broadcastAddr.sin_addr.s_addr = inet_addr(pair[1].c_str());
            stringstream ss;
            ss << "This is a message to request the emergency server, contact Information  IP:-" 
            << pair[0] <<", PORT:-"<<CPORT<<", Query:-" << query;
            string message = ss.str();
            int sendResult = sendto(sockfd, message.c_str(), message.length(), 0, 
                                    (struct sockaddr*)&broadcastAddr, sizeof(broadcastAddr));
            if (sendResult < 0) {
                cerr << "Error: Could not send broadcast message to " << pair[1] << endl;
            } 
            // else {
            //     cout << "Broadcasted to " << pair[1] << " at port " << SPORT << endl;
            // }
        }
        this_thread::sleep_for(chrono::seconds(3));
    }
    close(sockfd);
    // cout<<"closed connection broadcasting"<<endl;
}

void listenOnPort(atomic<bool>& running, atomic<bool>& broadcastrunning) {
    int sockfd, newsockfd;
    sockaddr_in serverAddr, clientAddr;
    char buffer[1024];
    socklen_t addrLen = sizeof(clientAddr);
    
    // Create a TCP socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        cerr << "Error: Could not create socket." << endl;
        return;
    }

    // Set the socket to non-blocking mode
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

    // Zero out the server address struct
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    // Bind to a port, incrementing if the port is already in use
    while (true) {
        serverAddr.sin_port = htons(CPORT);
        if (bind(sockfd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
            CPORT++;
        } else {
            break;
        }
    }

    // Start listening for incoming connections
    if (listen(sockfd, 5) < 0) {
        cerr << "Error: Could not listen on socket." << endl;
        close(sockfd);
        return;
    }

    // Accept incoming connections in a loop
    while (running) {
        // Accept a new connection (non-blocking call)
        newsockfd = accept(sockfd, (struct sockaddr*)&clientAddr, &addrLen);
        if (newsockfd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // No pending connections, continue the loop with a short pause
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }
            cerr << "Error: Could not accept connection." << endl;
            break;
        }

        // Set a timeout for the new socket
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        setsockopt(newsockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

        // Receive data from the connected client
        ssize_t receivedBytes = recv(newsockfd, buffer, sizeof(buffer) - 1, 0);
        if (receivedBytes < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                close(newsockfd);
                continue;
            }
            cerr << "Error: Could not receive message." << endl;
            close(newsockfd);
            break;
        }
        buffer[receivedBytes] = '\0';

        try {
            string str(buffer);
            size_t tidPos = str.find("TID=");
            if (tidPos == string::npos) {
                throw runtime_error("Error: TID not found");
            }
            size_t tidEndPos = str.find(',', tidPos);
            string tidStr = str.substr(tidPos + 4, tidEndPos - tidPos - 4);

            size_t idPos = str.find("Id=");
            if (idPos == string::npos) {
                throw runtime_error("Error: ID not found");
            }
            size_t idEndPos = str.find(',', idPos);
            string idStr = str.substr(idPos + 3, idEndPos - idPos - 3);

            size_t msgPos = str.find("msg=");
            if (msgPos == string::npos) {
                throw runtime_error("Error: Message not found");
            }
            size_t idSigPos = str.find(',', msgPos);
            string msg = str.substr(msgPos + 4, idSigPos - msgPos - 4);

            size_t sigPos = str.find("sign=");
            if (sigPos == string::npos) {
                throw runtime_error("Error: Signature not found");
            }
            string signature = str.substr(sigPos + 5);

            int tid = stoi(tidStr);
            int id = stoi(idStr);

            stringstream ss1;
            ss1 << "Id=" << id << ", msg=" << msg;

            if (!verifySignature(publicKey, ss1.str(), signature)) {
                throw runtime_error("Error: Signature is not valid");
            }

            if (tid == currestTID && emergencyGID.find(id) != emergencyGID.end()) {
                broadcastrunning = false;
                currestTID = -1;
                cout << "The contacted No.of " << emergencyGID[id] << " is " << msg << endl;
                ss1<<", sign="<<signature;
                // cout<<ss1.str()<<endl;
                exmap.put(idStr,ss1.str());
            }

        } catch (const runtime_error& e) {
            // cerr << e.what() << endl;
        } catch (const invalid_argument& e) {
            // cerr << "Error: Invalid number format." << endl;
        } catch (const out_of_range& e) {
            // cerr << "Error: Number out of range." << endl;
        }

        // Close the connection with the client
        close(newsockfd);
    }

    // Close the listening socket
    close(sockfd);
}

// listen on server port if possible and serve request
void lisenOnServerPort(atomic<bool>& running){
    int sockfd;
    sockaddr_in serverAddr, clientAddr;
    char buffer[1024];
    socklen_t addrLen = sizeof(clientAddr);
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        cerr << "Error: Could not create socket." << endl;
        return;
    }
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY; 
    serverAddr.sin_port = htons(SPORT);       
    if (bind(sockfd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        // cerr << "Error: Could not bind to port " << CPORT << endl;
        close(sockfd);
        return;
    }
    int send_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (send_sock < 0) {
        // cerr << "Error opening send socket" << endl
        return;
    }
    // cout << "Listening on port " << CPORT << "..." << endl;
    while (running) {
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
        ssize_t receivedBytes = recvfrom(sockfd, buffer, sizeof(buffer) - 1, 0,
                                          (struct sockaddr*)&clientAddr, &addrLen);
        if (receivedBytes < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            std::cerr << "Error: Could not receive message." << std::endl;
            break;
        }
        buffer[receivedBytes] = '\0';
        //suedo act like server 
        try {            
            string message(buffer);

            size_t ipPos = message.find("IP:-");
            if (ipPos == string::npos) {
                throw runtime_error("Error: IP not found");
            }
            size_t ipEndPos = message.find(',', ipPos);
            string ip = message.substr(ipPos + 4, ipEndPos - ipPos - 4); 

            size_t portPos = message.find("PORT:-");
            if (portPos == string::npos) {
                throw runtime_error("Error: PORT not found");
            }
            size_t portEndPos = message.find(',', portPos);
            string portStr = message.substr(portPos + 6, portEndPos - portPos - 6); 

            size_t idPos = message.find("Id:-");
            if (idPos == string::npos) {
                throw runtime_error("Error: ID not found");
            }
            size_t idEndPos = message.find(',', idPos);
            string idStr = message.substr(idPos + 4, idEndPos - idPos - 4);

            size_t tidPos = message.find("TID:-");
            if (tidPos == string::npos) {
                throw runtime_error("Error: TID not found");
            }
            string tidStr = message.substr(tidPos + 5); 

            int tid = stoi(tidStr);
            int cportcustom = stoi(portStr);

            // Connect to the client using TCP
            sockaddr_in client_addr;
            memset(&client_addr, 0, sizeof(client_addr));
            client_addr.sin_family = AF_INET;
            client_addr.sin_addr.s_addr = inet_addr(ip.c_str());
            client_addr.sin_port = htons(cportcustom);

            string* result =exmap.get(idStr);
            if(!result){
                continue;
            }

            stringstream ss;
            ss <<"TID="<<tid<<","<< *result;

            if (connect(send_sock, (sockaddr*)&client_addr, sizeof(client_addr)) < 0) {
                cerr << "Error: Could not connect to the client." << endl;
                continue;
            }

            string response =ss.str();

            if (send(send_sock, response.c_str(), response.size(), 0) < 0) {
                    cerr << "Error: Failed to send message to the client." << endl;
            }

            close(send_sock);

            send_sock = socket(AF_INET, SOCK_STREAM, 0);

            if (send_sock < 0) {
                cerr << "Error opening send socket" << endl;
                break;
            }

        } catch (const runtime_error& e) {
            // cerr << e.what() << endl;
        } catch (const invalid_argument& e) {
            // cerr << "Error: Invalid number format." << endl;
        } catch (const out_of_range& e) {
            // cerr << "Error: Number out of range." << endl;
        }
        // std::cout << "Received message: " << buffer << std::endl;
    }
    // std::cout << "Listening thread has stopped." << std::endl;
    close(sockfd);
}


void emergencyContact(){
    atomic<bool> listenRunning(true); 
    atomic<bool> broadcastRunning(true);
    atomic<bool> serverListenRunning(true);
    const string publicKeyFile = "public_key.pem";


    thread listenThread(listenOnPort, ref(listenRunning),ref(broadcastRunning));
    thread serverListenThread(lisenOnServerPort, ref(serverListenRunning));

    publicKey = loadPublicKey(publicKeyFile);

    if (!publicKey) {
        cerr << "Public key loading failed" << endl;
        return;
    }

    int totalQuery=6;
    int quitCode=999;
    emergencyGID[1] = "Police station number";
    emergencyGID[2] = "Ambulance Number";
    emergencyGID[3] = "Fire Station Number";
    emergencyGID[4] = "Vehicle repair Number";
    emergencyGID[5] = "Food delivery";
    emergencyGID[6] = "Blood bank Number";
    for (const auto& pair : emergencyGID) {
        cout << pair.first << ". " << pair.second << "\n";
    }

    cout<<"To Quit enter "<<quitCode<<"\n"<<endl;

    cout << "pick a number that requires your query"<<endl;
    int qno;

    random_device rd;
    mt19937 gen(rd()); 
    uniform_int_distribution<> distr(10000, 100000);

    while(1){
        cout<<"QueryNo>";
        cin>>qno;
        if(qno==quitCode){break;}
        if(qno<1||qno>totalQuery){
            cout<<"Enter the valid QueryNo"<<endl;
            continue;
        }
        currestTID=distr(gen);
        // cout<<currestTID<<endl;
        stringstream ss;
        ss << "The global emergency contact Id:-" 
        <<qno<<", TID:-"<<currestTID;
        string query = ss.str();
        broadcastRunning=true;
        thread broadcastThread(broadcastQuery,query, ref(broadcastRunning));
        if (broadcastThread.joinable()) {
            broadcastThread.join();
        }

    }
    listenRunning = false;
    serverListenRunning=false;
    if (listenThread.joinable()) {
        listenThread.join();
    }
    if (serverListenThread.joinable()) {
        serverListenThread.join();
    }
}

int main() {
    emergencyContact();
    return 0;
}