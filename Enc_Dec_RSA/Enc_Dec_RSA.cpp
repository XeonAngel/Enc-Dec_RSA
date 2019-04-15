#pragma comment(lib, "crypt32")
#pragma comment(lib, "ws2_32.lib")

#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define KEY_LENGTH       2048
#define PUBLIC_EXPONENT  3
#define PUBLIC_KEY_PEM   1
#define PRIVATE_KEY_PEM  0

void Init(char* private_key_pem_filename, char* public_key_pem_filename);
void Encrypt(char* message, char* public_key_pem_filename, char* Encrypted_filename);
void Decrypt(char* private_key_pem_filename, char* Encrypted_filename, char* Decrypted_filename);

int main()
{
	char message[KEY_LENGTH / 8 - 11] = {};

	char private_key_pem_filename[] = "PrivKey.priv";
	char public_key_pem_filename[] = "PubKey.pub";
	char Encrypted_filename[] = "Encrypted_Text.bin";
	char Decrypted_filename[] = "Decrypted_Text.txt";

	printf("%s", "Please select an operation:\n1.Encrypt with new generated key.\n2.Encrypt with already generated key(no password or encryption on them required).\n3.Decrypt.\n");

	int option;
	scanf("%d", &option);

	switch (option)
	{
	case 1:
		printf("%s", "Insert the text that you what to encrypt:\n");
		scanf("%s", message);
		Init(private_key_pem_filename, public_key_pem_filename);
		Encrypt(message, public_key_pem_filename, Encrypted_filename);
		break;
	case 2:
		printf("%s", "Insert the text that you what to encrypt:");
		scanf("%s", message);
		Encrypt(message, public_key_pem_filename, Encrypted_filename);
		break;
	case 3:
		Decrypt(private_key_pem_filename, Encrypted_filename, Decrypted_filename);
		break;
	default:
		printf("%s", "Error selecting operation!\n");
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
	}
	else if (pem_type == PRIVATE_KEY_PEM) {

		fp = fopen(file_name, "w");
		PEM_write_RSAPrivateKey(fp, keypair, NULL, NULL, NULL, NULL, NULL);
		fclose(fp);
	}

	return rsa;
}

RSA* read_RSA_PubKey(char* file_name) {

	RSA* rsa = NULL;
	FILE* fp = NULL;

	fp = fopen(file_name, "rb");
	PEM_read_RSAPublicKey(fp, &rsa, NULL, NULL);
	fclose(fp);

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

void Init(char* private_key_pem_filename, char* public_key_pem_filename) {

	RSA* keypair = RSA_generate_key(KEY_LENGTH, PUBLIC_EXPONENT, NULL, NULL);
	printf("%s", "Keys has been created.\n");

	create_RSA(keypair, PRIVATE_KEY_PEM, private_key_pem_filename);
	printf("%s", "Private key pem file has been created.\n");

	create_RSA(keypair, PUBLIC_KEY_PEM, public_key_pem_filename);
	printf("%s", "Public key pem file has been created.\n");

	RSA_free(keypair);
}

void Encrypt(char* message, char* public_key_pem_filename, char* Encrypted_filename) {

	RSA* public_key;
	char* encrypt = NULL;

	public_key = read_RSA_PubKey(public_key_pem_filename);

	encrypt = (char*)malloc(RSA_size(public_key));
	int encrypt_length = RSA_public_encrypt(strlen(message) + 1, (unsigned char*)message, (unsigned char*)encrypt, public_key, RSA_PKCS1_PADDING);
	if (encrypt_length == -1) {
		printf("%s", "An error occurred in public_encrypt() method\n");
	}
	printf("%s", "Data has been encrypted.\n");

	FILE* encrypted_file = fopen(Encrypted_filename, "wb");
	fwrite(encrypt, sizeof(*encrypt), encrypt_length, encrypted_file);
	fclose(encrypted_file);
	printf("%s", "Encrypted file has been created.\n");

	free(public_key);
	free(encrypt);

}

void Decrypt(char* private_key_pem_filename, char* Encrypted_filename, char* Decrypted_filename) {

	RSA* private_key;

	char* decrypt = NULL;
	char* encrypt = NULL;

	private_key = read_RSA_PrivKey(private_key_pem_filename);
	printf("%s", "Private key pem file has been opened.\n");

	encrypt = (char*)malloc(KEY_LENGTH / 8);
	FILE * encrypted_file = fopen(Encrypted_filename, "rb");
	fread(encrypt, sizeof(char), KEY_LENGTH / 8, encrypted_file);
	fclose(encrypted_file);
	printf("%s", "Encrypted file has been opened.\n");

	decrypt = (char*)malloc(KEY_LENGTH / 8);
	int decrypt_length = RSA_private_decrypt(KEY_LENGTH / 8, (unsigned char*)encrypt, (unsigned char*)decrypt, private_key, RSA_PKCS1_PADDING);
	if (decrypt_length == -1) {
		printf("%s", "An error occurred in private_decrypt() method\n");
	}
	printf("%s", "Data has been decrypted.\n");

	FILE* decrypted_file = fopen(Decrypted_filename, "wb");
	fwrite(decrypt, sizeof(*decrypt), decrypt_length - 1, decrypted_file);
	fclose(decrypted_file);
	printf("%s", "Decrypted file has been created.\n");

	free(private_key);
	free(decrypt);
	free(encrypt);
}