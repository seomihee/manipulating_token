// TestofCreateProcessWithTokenW.cpp : 이 파일에는 'main' 함수가 포함됩니다. 거기서 프로그램 실행이 시작되고 종료됩니다.
//

#include <Windows.h>
#include <iostream>
#include <securitybaseapi.h>
#include <processthreadsapi.h>
#include <winbase.h>
#include <tchar.h>

#define usernamelength	256

int main()
{
	TOKEN_PRIVILEGES PrivToken;
	BOOL bResult = NULL;
	HANDLE hToken = NULL;

	ZeroMemory(&PrivToken, sizeof(PrivToken));
	PrivToken.PrivilegeCount = 1;
	OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken);
	LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &PrivToken.Privileges[0].Luid);

	PrivToken.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	bResult = AdjustTokenPrivileges(hToken, FALSE, &PrivToken, 0, NULL, NULL);
	if( NULL == bResult)
	{
		printf("Failed to call AdjustTokenPrivileges(SeDebugPrivilege) error (%d) \n", GetLastError());
	}

	OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken);
	LookupPrivilegeValueW(NULL, SE_IMPERSONATE_NAME, &PrivToken.Privileges[0].Luid);
	
	PrivToken.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	bResult = AdjustTokenPrivileges(hToken, FALSE, &PrivToken, 0, NULL, NULL);
	if( NULL == bResult)
	{
		printf("Failed to call AdjustTokenPrivileges(SeImpersonatePrivilege) error (%d) \n", GetLastError());
	}
	
	HANDLE hProcess, hPrimaryToken = NULL;
	int pid = 576;
	hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, TRUE, pid);
	if( NULL == hProcess )
	{
		printf("Failed to call OpenProcess error (%d) \n", GetLastError());
		return 0;
	}
	else
	{
		bResult = OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_DUPLICATE, &hPrimaryToken);
		if( NULL == bResult)
		{
			printf("Failed to call OpenProcessToken error (%d) \n", GetLastError());
		}
	}

	TCHAR strUsername[usernamelength+1] = {0,};
	DWORD dwUsernameLength = usernamelength+1;
	GetUserName((TCHAR*)strUsername, &dwUsernameLength);
	printf("current user : %S\n", strUsername);

	if( TRUE == ImpersonateLoggedOnUser( hPrimaryToken ) )
	{
		TCHAR strImpUsername[usernamelength+1] = {0,};
		DWORD dwImpUsernameLength = usernamelength+1;
		GetUserName((TCHAR*)strImpUsername, &dwImpUsernameLength);
		printf("current user : %S\n", strImpUsername);
	}

	HANDLE hDupToken = NULL;
	HANDLE phSessionToken = NULL;
	BOOL bDupTokenResult, ProcWithToken = NULL;
	SECURITY_IMPERSONATION_LEVEL SecImpLevel = SecurityImpersonation;
	TOKEN_TYPE TokenType = TokenPrimary;
	bDupTokenResult = DuplicateTokenEx(hPrimaryToken, MAXIMUM_ALLOWED, NULL, SecImpLevel, TokenType, &hDupToken);
	
	STARTUPINFO StartupInfo = {};
	PROCESS_INFORMATION ProcInfo = {};
	ProcWithToken = CreateProcessWithTokenW(hDupToken, 0, L"C:\\Windows\\system32\\cmd.exe", NULL, CREATE_NEW_CONSOLE, NULL, NULL, &StartupInfo, &ProcInfo);
	if( NULL == ProcWithToken )
	{
		printf("Failed to call CreateProcessWithTokenW error (%d) \n", GetLastError());
	}
	system("pause");

	return 1;
}
