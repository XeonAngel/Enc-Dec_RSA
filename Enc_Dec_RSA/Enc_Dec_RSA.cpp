#pragma comment(lib, "crypt32")
#pragma comment(lib, "ws2_32.lib")

#define _CRT_SECURE_NO_WARNINGS

#include <iostream>

#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define KEY_LENGTH       2048
#define PUBLIC_EXPONENT  3
#define PUBLIC_KEY_PEM   1
#define PRIVATE_KEY_PEM  0

void Encrypt();
void Decrypt();

int main()
{
	printf("%s\n", "Please select an operation:\n1.Encrypt.\n2.Decrypt.\n");

	int option;
	scanf("%d", &option);

	switch (option)
	{
	case 1:
		Encrypt();
		break;
	case 2:
		Decrypt();
		break;
	default:
		std::cout << "Error selecting operation!\n" << std::endl;
		break;
	}
}

RSA* create_RSA(RSA* keypair, int pem_type, char* file_name) {

	RSA* rsa = NULL;
	FILE* fp = NULL;

	if (pem_type == PUBLIC_KEY_PEM) {

		fp = fopen(file_name, "w");
		PEM_write_RSAPublicKey(fp, keypair);
		fclose(fp);

		fp = fopen(file_name, "rb");
		PEM_read_RSAPublicKey(fp, &rsa, NULL, NULL);
		fclose(fp);
	}
	else if (pem_type == PRIVATE_KEY_PEM) {

		fp = fopen(file_name, "w");
		PEM_write_RSAPrivateKey(fp, keypair, NULL, NULL, NULL, NULL, NULL);
		fclose(fp);

	}

	return rsa;
}

RSA* read_RSA_PrivKey(char* file_name) {

	RSA* rsa = NULL;
	FILE* fp = NULL;

	fp = fopen(file_name, "rb");
	PEM_read_RSAPrivateKey(fp, &rsa, NULL, NULL);
	fclose(fp);

	return rsa;
}

void Encrypt() {
	RSA* public_key;

	char message[KEY_LENGTH / 8] = "Batuhan AVLAYAN - OpenSSL_RSA demo";



	char* encrypt = NULL;

	char public_key_pem_filename[] = "PubKey.pub";
	char Encrypted_filename[] = "Encrypted_Text.bin";
	char private_key_pem_filename[] = "PrivKey.priv";

	RSA* keypair = RSA_generate_key(KEY_LENGTH, PUBLIC_EXPONENT, NULL, NULL);
	printf("%s", "Keys has been created.\n");

	create_RSA(keypair, PRIVATE_KEY_PEM, private_key_pem_filename);
	printf("%s", "Private key pem file has been created.\n");

	public_key = create_RSA(keypair, PUBLIC_KEY_PEM, public_key_pem_filename);
	printf("%s", "Public key pem file has been created.\n");

	encrypt = (char*)malloc(RSA_size(public_key));
	int encrypt_length = RSA_public_encrypt(strlen(message) + 1, (unsigned char*)message, (unsigned char*)encrypt, public_key, RSA_PKCS1_PADDING);
	if (encrypt_length == -1) {
		printf("%s", "An error occurred in public_encrypt() method\n");
	}
	printf("%s", "Data has been encrypted.\n");

	FILE* encrypted_file = fopen(Encrypted_filename, "w");
	fwrite(encrypt, sizeof(*encrypt), RSA_size(public_key), encrypted_file);
	fclose(encrypted_file);
	printf("%s", "Encrypted file has been created.\n");

}

void Decrypt() {

	RSA* private_key;

	char* decrypt = NULL;
	char* encrypt = NULL;

	char private_key_pem_filename[] = "PrivKey.priv";
	char Encrypted_filename[] = "Encrypted_Text.bin";
	char Decrypted_filename[] = "Decrypted_Text.txt";

	private_key = read_RSA_PrivKey(private_key_pem_filename);
	printf("%s", "Private key pem file has been opened.\n");

	encrypt = (char*)malloc(KEY_LENGTH/8);
	FILE* encrypted_file = fopen(Encrypted_filename, "rb");
	fread(encrypt, sizeof(char), KEY_LENGTH / 8, encrypted_file);
	fclose(encrypted_file);
	printf("%s", "Encrypted file has been opened.\n");

	decrypt = (char*)malloc(KEY_LENGTH / 8);
	int decrypt_length = RSA_private_decrypt(KEY_LENGTH / 8, (unsigned char*)encrypt, (unsigned char*)decrypt, private_key, RSA_PKCS1_PADDING);
	if (decrypt_length == -1) {
		printf("%s", "An error occurred in private_decrypt() method\n");
	}
	printf("%s", "Data has been decrypted.\n");

	FILE* decrypted_file = fopen(Decrypted_filename, "w");
	fwrite(decrypt, sizeof(*decrypt), decrypt_length - 1, decrypted_file);
	fclose(decrypted_file);
	printf("%s", "Decrypted file has been created.\n");

}