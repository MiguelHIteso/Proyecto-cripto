// Proyecto Cripto.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <fstream>
#include <iostream>
#include "sodium.h"
#include <string>
using namespace std;


int main()
{
    if (sodium_init() < 0) {
        /* panic! the library couldn't be initialized, it is not safe to use */
        return-1;
    }


    std::fstream fs;
    fs.open("mensaje_con_firmas.txt", std::fstream::in);

    std::string str;

    fs >> str;
    printf("%s\n", str.c_str());
    char* cstr = new char[str.length() + 1];
    unsigned char* MESSAGE = new unsigned char[str.length() + 1];
    std::strncpy(cstr, str.c_str(), str.length() + 1);
    
    

    MESSAGE = (unsigned char*) cstr;
    int MESSAGE_LEN = str.length() + 1;

    //chacha20
    unsigned char key[crypto_stream_chacha20_KEYBYTES];
    unsigned char nonce[crypto_stream_chacha20_NONCEBYTES];
    unsigned char c[sizeof(MESSAGE)], decifrado[sizeof(MESSAGE)];
    unsigned long long clen = sizeof(MESSAGE);
    
    for (int i = 0; i < clen; i++)
    {
        printf("%c", cstr[i]);
    }
    printf("\n");
    crypto_secretbox_keygen(key);
    randombytes_buf(nonce, sizeof nonce);
    int resultado;

    resultado = crypto_stream_chacha20_xor(c, MESSAGE, clen, nonce, key);
    printf("cifrado:\n");
    for (int i = 0; i < clen; i++)
    {
        printf("%d", c[i]);
    }
    printf("\n");
    resultado = crypto_stream_chacha20_xor(decifrado, c, clen, nonce, key);
    printf("Descifrado:\n");
    for (int i = 0; i < clen; i++)
    {
        printf("%c", decifrado[i]);
    }



    unsigned char pk[crypto_sign_PUBLICKEYBYTES]; 
    unsigned char sk[crypto_sign_SECRETKEYBYTES]; 
    crypto_sign_keypair(pk, sk); 


    unsigned char* signed_message = new unsigned char[crypto_sign_BYTES + MESSAGE_LEN];
    unsigned long long signed_message_len; 

    unsigned char sig[crypto_sign_BYTES]; 
    crypto_sign_detached(sig, NULL, MESSAGE, MESSAGE_LEN, sk); 

    if (crypto_sign_verify_detached(sig, MESSAGE, MESSAGE_LEN, pk) != 0) 
    {    /* Incorrect signature! */ 
        printf("INVALIDO\n");
    }

    delete[] cstr;

    // Escribir archivo

    std::ofstream myfile ("mensaje_firmado.txt");
    myfile << sig;
    myfile.close();
    fs.close();
    return 0;
}

