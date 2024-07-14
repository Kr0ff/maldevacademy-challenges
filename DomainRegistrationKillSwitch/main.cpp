#include <stdio.h>
#include <Windows.h>
#include <windns.h>

#pragma comment(lib, "Dnsapi")

BOOL CheckDomainIsValid(char* DNSname) {
	BOOL ret = FALSE;

	DNS_STATUS dnsStatus = NULL;
	PDNS_RECORD dnsRecord = NULL;

	if ((dnsStatus = DnsQuery_A(DNSname, DNS_TYPE_A, DNS_QUERY_BYPASS_CACHE, NULL, &dnsRecord, NULL)) != 0) {
		//printf("Last Error: %d\n", GetLastError());
		goto CLEANUP;
	}
	else {
		ret = TRUE;
		printf("[+] DnsQuery Successful !\n");

	}

	printf("[*] DNS Record information:\n\t-> Name: %s\n\n", dnsRecord->pName);

CLEANUP:
	if (dnsRecord) {
		DnsRecordListFree(dnsRecord, DnsFreeRecordList);
	}

	return ret;
}

int main(void) {

	if (!CheckDomainIsValid((char*)"mdsec.co.uk")) {
		printf("[-] Domain not registered !\n");
		return -1;
	}
	else {
		printf("[+] Domain is registered !\n");
	}

	return 0;


}
