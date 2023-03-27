// PasswordFilter.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "stdio.h"
#include "stdlib.h"
#include <time.h>
#include <regex> 
#include <windows.h>
#include <Mmsystem.h>             //timeGetTime()  
#pragma comment(lib, "Winmm.lib")   //timeGetTime() 
#include <ntsecapi.h> 

using namespace std;

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS  ((NTSTATUS)0x00000000L)
#endif

#define LOG_PATH "C:\\ebd6e4f00ae0491d91c27c06e6115922.txt"
#define INI_PATH L"C:\\ebd6e4f00ae0491d91c27c06e6115922.ini"
#define INI_TURE 1
/*
[Common]
Debug = 0               # 1 means enable, others mean disable
Log = 1                 # 1 means enable, others mean disable

[PasswordRule]
CheckPass4Type = 1		# 1 means enable, others mean disable
CheckPass3DupChr = 1    # 1 means enable, others mean disable, example: 111, aaa, @@@, etc...
CheckPassSubStr = 1     # 1 means enable, others mean disable, example: 123, abc, opq, jan, Jan, January, one, two, etc..., ignore case
CheckPassSubStrExt = 1  # 1 means enable, others mean disable
ExcludeString = "str1, str2, str3"
testKey = "er"
*/
#define TIME_BUFFER_SIZE 32
#define USER_BUFFER_SIZE 128
#define FULL_BUFFER_SIZE 128
#define PASSWORD_BUFFER_SIZE 256
#define LINE_BUFFER_SIZE USER_BUFFER_SIZE+FULL_BUFFER_SIZE+PASSWORD_BUFFER_SIZE+TIME_BUFFER_SIZE+32
#define LOG_LINE_BUFFER_SIZE TIME_BUFFER_SIZE+LINE_BUFFER_SIZE+32
#define EXCLUDE_STRING_BUFFER_SIZE 2048

#define MyWriteLog(flag, ...) { const wchar_t *tmpLogStrArray[] = { ##__VA_ARGS__ }; WriteLog(flag, tmpLogStrArray, sizeof(tmpLogStrArray) / sizeof(wchar_t *));}
#define MyLog(...) MyWriteLog(FALSE, ##__VA_ARGS__)
#define MyDebug(...) MyWriteLog(TRUE, ##__VA_ARGS__)
#define MyPreLog(...) MyLog(L"<", logPrefix, L"> ", ##__VA_ARGS__)
#define MyPreDebug(...) MyDebug(L"<", logPrefix, L"> ", ##__VA_ARGS__)

BOOLEAN ENABLE_Debug = TRUE;
BOOLEAN ENABLE_Log = TRUE;

BOOLEAN ENABLE_CheckPass4Type = TRUE;
BOOLEAN ENABLE_CheckPass3DupChr = TRUE;
BOOLEAN ENABLE_CheckPassSubStr = TRUE;
BOOLEAN ENABLE_CheckPassSubStrExt = TRUE;

#define MyCheckIniKey(section, key, defaultValue) { ENABLE_ ## key = (GetPrivateProfileInt(L#section, L#key, defaultValue, INI_PATH) == INI_TURE); MyPreDebug(L#key, ENABLE_ ## key ? L" is enable" : L" is disable"); }
#define MyCheck(fun, ...) ((!(ENABLE_##fun)) || ##fun(##__VA_ARGS__))

void WriteLog(BOOL DebugFlag, const wchar_t* szString[], int count)
{
	FILE* pFile = NULL;

	if (!ENABLE_Log)
	{
		return;
	}

	if ((!ENABLE_Debug) && DebugFlag)
	{
		return;
	}

	try
	{
		srand((unsigned)timeGetTime());

		struct tm timeinfo;
		__time64_t rawtime;

		// Get time as 64-bit integer.
		_time64(&rawtime);
		// Convert to local time.
		_localtime64_s(&timeinfo, &rawtime);

		wchar_t timeStr[TIME_BUFFER_SIZE] = L"";
		wcsftime(timeStr, TIME_BUFFER_SIZE, L"%c", &timeinfo);
		wchar_t lineStr[LOG_LINE_BUFFER_SIZE] = L"";
		swprintf_s(lineStr, LOG_LINE_BUFFER_SIZE, L"%ls ", timeStr);

		for (int i = 0; i<4000; i++) {
			fopen_s(&pFile, LOG_PATH, "a");
			if (pFile)
			{
				break;
			}
			Sleep(rand() % 5);
		}
		if (pFile)
		{
			fwprintf(pFile, L"%ls", lineStr);

			if (DebugFlag)
			{
				fwprintf(pFile, L"[DEBUG] ");
			}

			for (int i = 0; i < count; i++, szString++)
			{
				fwprintf(pFile, L"%ls", *szString);
			}

			fwprintf(pFile, L"\n");
		}
	}
	catch (...)
	{
	}

	_fcloseall();
}

bool CheckPass4Type(const wchar_t* passStr, const wchar_t* logPrefix)
{
	bool res = false;

	wstring target(passStr);
	wsmatch wideMatch;
	wregex wrx1(L".*[0-9].*");
	wregex wrx2(L".*[a-z].*");
	wregex wrx3(L".*[A-Z].*");
	wregex wrx4(L".*[^0-9a-zA-Z].*");

	if ((regex_match(target.cbegin(), target.cend(), wideMatch, wrx1)) &&
		(regex_match(target.cbegin(), target.cend(), wideMatch, wrx2)) &&
		(regex_match(target.cbegin(), target.cend(), wideMatch, wrx3)) &&
		(regex_match(target.cbegin(), target.cend(), wideMatch, wrx4))
		)
	{
		res = true;
	}
	else
	{
		MyPreLog(L"CheckPass4Type::Failed");
	}

	return res;
}

bool CheckPass3DupChr(const wchar_t* passStr, const wchar_t* logPrefix)
{
	bool res = false;

	wchar_t *passStrLower;
	_wcslwr_s(passStrLower = _wcsdup(passStr), wcslen(passStr) + 1);

	wstring target(passStrLower);
	wsmatch wideMatch;
	wregex wrx(LR"(.*([0-9a-zA-Z])\1\1.*)");

	if (!regex_match(target.cbegin(), target.cend(), wideMatch, wrx))
	{
		res = true;
	}
	else
	{
		MyPreLog(L"CheckPass3DupChr::Failed");
	}

	free(passStrLower);

	return res;
}

bool CheckPassSubStr(const wchar_t* passStr, const wchar_t* logPrefix)
{
	const wchar_t checkList[][PASSWORD_BUFFER_SIZE] = {
		L"one", L"two", L"three", L"four", L"five", L"six", L"seven", L"eight", L"nine", L"ten",
		L"january", L"february", L"march", L"april", L"may", L"june", L"july", L"august", L"september", L"october", L"november", L"december",
		L"jan", L"feb", L"mar", L"apr", L"may", L"jun", L"jul", L"aug", L"sep", L"oct", L"nov", L"dec",
		L"012", L"123", L"234", L"345", L"456", L"567", L"678", L"789", L"890",
		L"abc", L"bcd", L"cde", L"def", L"efg", L"fgh", L"ghi", L"hij", L"ijk", L"jkl",
		L"klm", L"lmn", L"mno", L"nop", L"opq", L"pqr", L"qrs", L"rst", L"stu", L"tuv",
		L"uvw", L"vwx", L"wxy", L"xyz",
	};
	bool res = false;
	bool flag = false;
	int len = sizeof(checkList) / sizeof(checkList[0]);
	const wchar_t *pwc = NULL;

	wchar_t *passStrLower;
	_wcslwr_s(passStrLower = _wcsdup(passStr), wcslen(passStr) + 1);

	for (int i = 0; i < len; i++)
	{
		pwc = wcsstr(passStrLower, checkList[i]);
		if (pwc != NULL)
		{
			MyPreLog(L"CheckPassSubStr::Fail::", checkList[i]);
			flag = true;
			break;
		}
	}
	free(passStrLower);

	if (!flag)
	{
		res = true;
	}
	return res;
}

bool CheckPassSubStrExt(const wchar_t* passStr, const wchar_t* excludeString, const wchar_t* logPrefix)
{
	bool res = false;
	bool flag = false;
	const wchar_t *pwc = NULL;

	wchar_t newExtString[EXCLUDE_STRING_BUFFER_SIZE] = L"";
	memset(newExtString, 0, EXCLUDE_STRING_BUFFER_SIZE*(sizeof(wchar_t)));
	wcsncpy_s(newExtString, excludeString, EXCLUDE_STRING_BUFFER_SIZE);

	const wchar_t *sep = L", \t";
	wchar_t *pcheck;
	wchar_t *next_token = NULL;
	pcheck = wcstok_s(newExtString, sep, &next_token);
	int i = 0;
	while (pcheck){
		i += 1;
		MyPreDebug(pcheck);

		pwc = wcsstr(passStr, pcheck);
		if (pwc != NULL)
		{
			MyPreLog(L"CheckPassSubStrExt::Fail::", pcheck);
			flag = true;
			break;
		}

		pcheck = wcstok_s(NULL, sep, &next_token);
	}
	if (i == 0)
	{
		MyPreDebug(L"Dict Empty! Please check value of PasswordRule::ExcludeString.");
	}

	if (!flag)
	{
		res = true;
	}
	return res;
}

bool CheckPass(const wchar_t* userStr, const wchar_t* passStr)
{
	bool res;
	const wchar_t* logPrefix = userStr;

	MyCheckIniKey(Common, Debug, 0);
	MyCheckIniKey(Common, Log, 1);
	MyCheckIniKey(PasswordRule, CheckPass4Type, 1);
	MyCheckIniKey(PasswordRule, CheckPass3DupChr, 1);
	MyCheckIniKey(PasswordRule, CheckPassSubStr, 1);
	MyCheckIniKey(PasswordRule, CheckPassSubStrExt, 1);

	wchar_t excludeString[EXCLUDE_STRING_BUFFER_SIZE] = L"";
	memset(excludeString, 0, EXCLUDE_STRING_BUFFER_SIZE*(sizeof(wchar_t)));

	int ret;
	ret = GetPrivateProfileString(L"PasswordRule", L"ExcludeString", L"", excludeString,
		(sizeof(excludeString) / sizeof(wchar_t)), INI_PATH);

	MyPreDebug(L"ExcludeString: ", excludeString);

	res = MyCheck(CheckPass4Type, passStr, userStr) \
		&& MyCheck(CheckPass3DupChr, passStr, userStr) \
		&& MyCheck(CheckPassSubStr, passStr, userStr) \
		&& MyCheck(CheckPassSubStrExt, passStr, excludeString, userStr);

	return res;
}

void GetStrFromPUNI(PUNICODE_STRING UserName, wchar_t strBuff[], int buffSize)
{
	int i;
	memset(strBuff, 0, buffSize*(sizeof(wchar_t)));
	for (i = 0; i < UserName->Length / sizeof(wchar_t); i++)
	{
		strBuff[i] = UserName->Buffer[i];
	}
	strBuff[++i] = 0;
}

BOOL
NTAPI
InitializeChangeNotify(
void
)
/*++

Routine Description:

This (optional) routine is called when the password change package
is loaded.

Arguments:

Return Value:

TRUE if initialization succeeded.

FALSE if initialization failed. This DLL will be unloaded by the
system.

--*/
{
	//
	// initialize any critical sections associated with password change
	// events, etc.
	//
	MyLog(L"InitializeChangeNotify");
	return TRUE;
}


NTSTATUS
NTAPI
PasswordChangeNotify(
PUNICODE_STRING UserName,
ULONG RelativeId,
PUNICODE_STRING Password
)
/*++

Routine Description:

This (optional) routine is notified of a password change.

Arguments:

UserName - Name of user whose password changed

RelativeId - RID of the user whose password changed

NewPassword - Cleartext new password for the user

Return Value:

STATUS_SUCCESS only - errors from packages are ignored.

--*/
{
	wchar_t userStr[USER_BUFFER_SIZE] = L"";
	wchar_t* logPrefix = userStr;
	GetStrFromPUNI(UserName, userStr, USER_BUFFER_SIZE);

	MyPreLog(L"PasswordChangeNotify");
	return STATUS_SUCCESS;
}

BOOL
NTAPI
PasswordFilter(
PUNICODE_STRING UserName,
PUNICODE_STRING FullName,
PUNICODE_STRING Password,
BOOL SetOperation
)
/*++

Routine Description:

This (optional) routine is notified of a password change.

Arguments:

UserName - Name of user whose password changed

FullName - Full name of the user whose password changed

NewPassword - Cleartext new password for the user

SetOperation - TRUE if the password was SET rather than CHANGED

Return Value:

TRUE if the specified Password is suitable (complex, long, etc).
The system will continue to evaluate the password update request
through any other installed password change packages.

FALSE if the specified Password is unsuitable. The password change
on the specified account will fail.

--*/
{
	BOOL bComplex = FALSE; // assume the password in not complex enough
	wchar_t lineStr[LINE_BUFFER_SIZE] = L"";

	wchar_t userStr[USER_BUFFER_SIZE] = L"";
	wchar_t* logPrefix = userStr;
	GetStrFromPUNI(UserName, userStr, USER_BUFFER_SIZE);

	MyPreDebug(L"PasswordFilter::Begin");
	try
	{
		if (Password->MaximumLength >= PASSWORD_BUFFER_SIZE)
		{
			MyPreLog(L"PasswordFilter::End::Password->MaximumLength >= PASSWORD_BUFFER_SIZE");
			return FALSE;
		}

		wchar_t passStr[PASSWORD_BUFFER_SIZE] = L"";
		GetStrFromPUNI(Password, passStr, PASSWORD_BUFFER_SIZE);
		//WriteLogLineTime(passStr);

		bComplex = CheckPass(userStr, passStr);
	}
	catch (...)
	{
	}

	MyPreDebug(L"PasswordFilter::End");
	return bComplex;
}



