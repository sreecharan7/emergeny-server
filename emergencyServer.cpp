#include <iostream>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <string>
#include <atomic>
#include <vector>
#include <map>
#include <sstream>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <memory>


using namespace std;

const int SPORT = 25642;
const int BUFFER_SIZE = 1024;
const int MAX_THREADS = 20;

mutex output_mutex;
mutex queue_mutex;
condition_variable cv;
queue<pair<string, string>> message_queue;
atomic<bool> running{true};

map<int, string> emergencyGIDNum;

EVP_PKEY* privateKey;

EVP_PKEY* loadPrivateKey(const string& privateKeyFile) {
    FILE* file = fopen(privateKeyFile.c_str(), "rb");
    if (!file) {
        cerr << "Failed to open private key file: " << privateKeyFile << endl;
        return nullptr;
    }

    EVP_PKEY* pkey = PEM_read_PrivateKey(file, nullptr, nullptr, nullptr);
    fclose(file);

    if (!pkey) {
        cerr << "Failed to load private key" << endl;
    }
    return pkey;
}
string base64Encode(const unsigned char* data, size_t length) {
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    // Encode without adding newlines
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, data, length);
    BIO_flush(bio);

    BUF_MEM* bufferPtr;
    BIO_get_mem_ptr(bio, &bufferPtr);

    string encoded(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    return encoded;
}
string signMessage(EVP_PKEY* pkey, const string& message) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX* pkeyCtx = nullptr;

    if (EVP_DigestSignInit(ctx, &pkeyCtx, EVP_sha256(), nullptr, pkey) <= 0) {
        cerr << "Error initializing signing context" << endl;
        EVP_MD_CTX_free(ctx);
        return "";
    }

    if (EVP_DigestSignUpdate(ctx, message.c_str(), message.size()) <= 0) {
        cerr << "Error updating signing context" << endl;
        EVP_MD_CTX_free(ctx);
        return "";
    }

    size_t sigLen = 0;
    if (EVP_DigestSignFinal(ctx, nullptr, &sigLen) <= 0) {
        cerr << "Error finalizing signature length" << endl;
        EVP_MD_CTX_free(ctx);
        return "";
    }

    unsigned char* sig = new unsigned char[sigLen];
    if (EVP_DigestSignFinal(ctx, sig, &sigLen) <= 0) {
        cerr << "Error signing message" << endl;
        delete[] sig;
        EVP_MD_CTX_free(ctx);
        return "";
    }

    // Encode the signature in Base64
    string signature = base64Encode(sig, sigLen);
    delete[] sig;
    EVP_MD_CTX_free(ctx);
    return signature;
}



void handle_message() {
    int send_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (send_sock < 0) {
        cerr << "Error opening send socket" << endl;
        return;
    }

    while (running) {
        pair<string, string> message_pair;

        {
            unique_lock<mutex> lock(queue_mutex);
            cv.wait(lock, [] { return !message_queue.empty() || !running; });
            if (!running) break;
            message_pair = message_queue.front();
            message_queue.pop();
        }

        {
            lock_guard<mutex> lock(output_mutex);
            // cout << "Handling message from " << message_pair.second 
            //      << ": " << message_pair.first << endl;
        }

        try {
            // Extract and parse the message details
            string message = message_pair.first;
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

            int id = stoi(idStr);
            int tid = stoi(tidStr);
            int cportcustom = stoi(portStr);

            // Connect to the client using TCP
            sockaddr_in client_addr;
            memset(&client_addr, 0, sizeof(client_addr));
            client_addr.sin_family = AF_INET;
            client_addr.sin_addr.s_addr = inet_addr(ip.c_str());
            client_addr.sin_port = htons(cportcustom);

            if (connect(send_sock, (sockaddr*)&client_addr, sizeof(client_addr)) < 0) {
                cerr << "Error: Could not connect to the client." << endl;
                continue;
            }

            // Prepare and send the response if the ID is in emergencyGIDNum
            if (emergencyGIDNum.find(id) != emergencyGIDNum.end()) {
                stringstream ss, ss1;
                ss1 << "Id=" << id << ", msg=" << emergencyGIDNum[id];
                string signature = signMessage(privateKey, ss1.str());
                if (signature.empty()) {
                    throw runtime_error("Error: Signature failed to generate");
                }
                ss << "TID=" << tid << ",Id=" << id << ", msg=" 
                   << emergencyGIDNum[id] << ", sign=" << signature;
                string response = ss.str();

                // Send the response to the connected client
                if (send(send_sock, response.c_str(), response.size(), 0) < 0) {
                    cerr << "Error: Failed to send message to the client." << endl;
                }
            }

            // Close the connection after handling each message
            close(send_sock);

            // Re-create the socket for the next iteration
            send_sock = socket(AF_INET, SOCK_STREAM, 0);
            if (send_sock < 0) {
                cerr << "Error opening send socket" << endl;
                break;
            }
        } catch (const runtime_error& e) {
            cerr << e.what() << endl;
        } catch (const invalid_argument& e) {
            cerr << "Error: Invalid number format." << endl;
        } catch (const out_of_range& e) {
            cerr << "Error: Number out of range." << endl;
        }
    }

    close(send_sock);
}


int main() {
    int sockfd;
    sockaddr_in server_addr, client_addr;
    socklen_t client_len;
    char buffer[BUFFER_SIZE];
    const string privateKeyFile = "private_key.pem";

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        cerr << "Error opening socket" << endl;
        return 1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(SPORT);

    if (bind(sockfd, (sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        cerr << "Error on binding" << endl;
        close(sockfd);
        return 1;
    }

    privateKey = loadPrivateKey(privateKeyFile);

    if (!privateKey) {
        cerr << "Private key loading failed" << endl;
        close(sockfd);
        return 2;
    }

    cout << "UDP server listening on port " << SPORT << "..." << endl;

    emergencyGIDNum[1]="100";
    emergencyGIDNum[2]="108";
    emergencyGIDNum[3]="101";
    emergencyGIDNum[4]="200";
    emergencyGIDNum[5]="300";
    emergencyGIDNum[6]="500";


    vector<thread> workers;
    int num=0;
    for (int i = 0; i < MAX_THREADS; ++i) {
        workers.emplace_back(handle_message);
    }

    while (running) {
        client_len = sizeof(client_addr);
        ssize_t recv_len = recvfrom(sockfd, buffer, BUFFER_SIZE, 0,
                                     (sockaddr *)&client_addr, &client_len);
        if (recv_len < 0) {
            cerr << "Error on receive" << endl;
            running = false;
            break;
        }

        buffer[recv_len] = '\0';
        string message(buffer);
        string client_ip = inet_ntoa(client_addr.sin_addr);

        {
            lock_guard<mutex> lock(queue_mutex);
            message_queue.emplace(message, client_ip);
        }

        cv.notify_one();
    }

    running = false;
    cv.notify_all();
    for (thread &worker : workers) {
        worker.join();
    }

    close(sockfd);
    return 0;
}
