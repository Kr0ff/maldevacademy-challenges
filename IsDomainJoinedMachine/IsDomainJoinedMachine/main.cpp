#include <Windows.h>
#include <iostream>
#include <LM.h>

#pragma comment(lib, "Netapi32")

BOOL CheckDomainJoin();

static int wmain(void) {
	
	if (CheckDomainJoin() != TRUE) {
		printf("[-] Machine is not domain joined\n");
		return -99;
	}
	else {
		printf("[+] Machine is domain joined\n");
	}
	
	return 0;
}

BOOL CheckDomainJoin(void) {
	BOOL ret = FALSE;

	LPWSTR buffer = NULL;
	NET_API_STATUS out_status = 0;
	NETSETUP_JOIN_STATUS join_status{};

	out_status = NetGetJoinInformation(NULL, &buffer, &join_status);

	if (out_status != NERR_Success) {
		printf("[-] Failed to get domain join information -> %d\n", GetLastError());
		goto gocleanup;
	}

	/*
	NetSetupUnknownStatus = 0,
	NetSetupUnjoined,
	NetSetupWorkgroupName,
	NetSetupDomainName
	*/

	if (join_status != NULL) {
		switch (join_status) {
		case NETSETUP_JOIN_STATUS::NetSetupUnjoined:
			//printf("[*] Machine not domain joined (unjoined)\n");
			goto gocleanup;
			break;

		case NETSETUP_JOIN_STATUS::NetSetupWorkgroupName:
			//printf("[*] Machine not domain joined (workgroup only)\n");
			goto gocleanup;
			break;

		case NETSETUP_JOIN_STATUS::NetSetupDomainName:
			//printf("[+] Machine is domain joined\n");
			ret = TRUE;
			goto gocleanup;
			break;
		}
	}

gocleanup:
	NetApiBufferFree(buffer);

	return ret;
}