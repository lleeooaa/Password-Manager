#include <iostream>
#include <vector>
#include <fstream>
#include <filesystem>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <iomanip>
#include <algorithm>
#include <sstream>
using namespace std;

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

string encrypt(string plaintext) {
    unsigned char key[] = {0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                           0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
                           0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33,
                           0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31};

    unsigned char iv[] = {0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                          0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35};
    EVP_CIPHER_CTX* ctx;
    unsigned char ciphertext[plaintext.length() + EVP_MAX_BLOCK_LENGTH];
    int len, ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) 
        handleErrors();

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) 
        handleErrors();
    
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.length())) 
        handleErrors();

    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) 
        handleErrors();

    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return string(reinterpret_cast<char*>(ciphertext), ciphertext_len);
}

string decrypt(string ciphertext) {
    unsigned char key[] = {0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                           0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
                           0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33,
                           0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31};

    unsigned char iv[] = {0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                          0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35};
    EVP_CIPHER_CTX* ctx;
    unsigned char plaintext[ciphertext.length() + EVP_MAX_BLOCK_LENGTH];
    int len, plaintext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) 
        handleErrors();

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) 
        handleErrors();

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, reinterpret_cast<const unsigned char*>(ciphertext.c_str()), ciphertext.length())) 
        handleErrors();

    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) 
        handleErrors();
    
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return string(reinterpret_cast<char*>(plaintext), plaintext_len);
}

bool isValidPassword(string password) {
    string allowedSpecialChars = "!?.%+=^$&#-@";
    if (!password.compare("")) 
        return false;
    for (char c : password) {
        if (!isalnum(c) && allowedSpecialChars.find(c) == string::npos) {
            return false;
        }
    }
    return true;
}


bool search_user(string username, vector<string> files) {
    for (string file : files) {
        if (username.compare(file.substr(file.find_last_of("/\\") + 1)) == 0){
            return true;
        }
    }
    return false;
}

vector<string> list_files(std::filesystem::path path) {
    vector<string> files;
    for (auto & entry : std::filesystem::directory_iterator(path)) {
        files.push_back(entry.path().string());
    }
    return files;
}

void add_item(string filepath, vector<string> name_list) {
    string name;
    string username;
    string password;
    while (true) {
        cout << "Enter Name" << endl;
        cin >> name;
        if (find(name_list.begin(), name_list.end(), name) != name_list.end()) {
            cout << "Name Exists" << endl;
            continue;
        }
        break;
    }
    cout << "Enter Username" << endl;
    cin >> username;
    cout << "Password" << endl;
    cin >> password;
    ofstream MyFile;
    MyFile.open(filepath, ios_base::app);
    MyFile << endl << encrypt(name);
    MyFile << endl << encrypt(username);
    MyFile << endl << encrypt(password);
    MyFile.close();
}

void del_item(string filepath, vector<string> context, int num) {
    ofstream MyFile(filepath);
    for (int i=0;i<context.size();i++) {
        if ((i+2)/3==num) {
            continue;
        }
        MyFile << context[i] << endl;
    }
    
    MyFile.close();
}

vector<string> list_item(vector<string> context) {
    vector<string> name;
    string tmp;
    cout << "Item List: " << endl;
    for (int i=0;i<context.size()/3;i++) {
        tmp = decrypt(context[i*3+1]);
        name.push_back(tmp);
        cout << to_string(i+1) + ". " + tmp << endl;
    }
    if (name.empty()) {
        return {"empty"};
    }
    return name;
}

void show(vector<string> context, int num) {
    cout << decrypt(context[(num-1)*3+1]) << endl;
    cout << decrypt(context[(num-1)*3+2]) << endl;
    cout << decrypt(context[(num-1)*3+3]) << endl;
}

vector<string> get_context(string filepath) {
    ifstream MyFile(filepath);
    string myText;
    vector<string> context;
    while (getline (MyFile, myText)) {
        cout << decrypt(myText)<< endl;
        context.push_back(myText);
    }
    MyFile.close();
    return context;
} 

void login() {
    string username;
    string password;
    filesystem::path path = filesystem::current_path();
    vector<string> files=list_files(path);
    while (true) {
        cout << "Enter Username: " << endl;
        cin >> username;
        if (!search_user(username, files)) {
            cout << "User Not Exist" << endl;
            continue;
        }
        break;
    }
    string filepath=path.generic_string()+"/"+username;
    vector<string> context;
    context=get_context(filepath);
    string truepassword = decrypt(context[0]);
    while (true) {
        cout << "Enter Password: " << endl;
        cin >> password;
        if (password.compare(truepassword)) {
            cout << "Password Not Correct" << endl;
            continue;
        }
        break;
    }
    string mode;
    vector<string> name_list;
    vector<string> tokens;
    string token;
    
    while (true){
        mode = "";
        name_list = list_item(context);
        tokens = {};
        token = "";
        cin.ignore(numeric_limits<streamsize>::max(), '\n');
        cout << "Choose \"show\" or \"add\" or \"delete\"  or \"leave\"" << endl;
        getline(cin, mode);
        istringstream iss(mode);
        while (getline(iss, token, ' ')) {
            tokens.push_back(token);
        }
        if (tokens[0].compare("show")==0) {
            if (stoi(tokens[1])<1 || stoi(tokens[1])>size(name_list)) {
                cout << "No such Item" << endl;
                continue;
            }
            show(context, stoi(tokens[1]));
        }
        else if (tokens[0].compare("add")==0){
            add_item(filepath, name_list);
        } 
        else if (tokens[0].compare("delete")==0){
            if (stoi(tokens[1])<1 || stoi(tokens[1])>size(name_list)) {
                cout << "No such Item" << endl;
                continue;
            }
            del_item(filepath, context, stoi(tokens[1]));
        }
        else if (tokens[0].compare("leave")==0){
            break;
        }
        else {
            cout << "Please Enter Again" <<endl;
        }
        context=get_context(filepath);
    }
}

void reg() {
    string username;
    string password;
    filesystem::path path = filesystem::current_path();
    vector<string> files=list_files(path);
    while (true) {
        cout << "Create Username: " << endl;
        cin >> username;
        if (search_user(username, files)) {
            cout << "Username Exists" << endl;
            continue;
        }
        break;
    }
    while (true) {
        cout << "Create Password: (Allowed Special Characters: ! ? . % + = ^ $ & # - @)" << endl;
        cin >> password;
        if (!isValidPassword(password)) {
            cout << "Password Not Accepted" << endl;
            continue;
        }
        break;
    }
    string ciphertext = encrypt(password);
    ofstream MyFile(username);
    MyFile << ciphertext;
    MyFile.close();
    cout << "Successfully Registered" << endl;
}

void start_ui() {
    string mode;

    while (true){
        cout << "Choose \"login\" or \"register\" or \"leave\"" << endl;
        cin >> mode;
        if (mode.compare("login")==0) {
            login();
            break;
        } 
        else if (mode.compare("register")==0){
            reg();
        }
        else if (mode.compare("leave")==0){
            break;
        }
        else {
            cout << "Please Enter Again";
        }
    }
}

int main() {
    start_ui();
}

