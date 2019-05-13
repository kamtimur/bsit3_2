#include <cstdio>
#include <comutil.h>
#include <string>
#include <string>
#include "winbase.h"
#include <mstask.h>
#include <msterr.h>
#include <taskschd.h>
#include <comutil.h>
#include <fstream>
#include <streambuf>

#pragma comment(lib, "comsuppw.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")

const int UNLEN = 255;
int nTasks = 0;

void CreateTask(ITaskService* pService);
void DeleteTask(ITaskService* pService);
HRESULT CreateSecurityTask(IEventTrigger *pEventTrigger);
HRESULT CreatePingTask(IEventTrigger *pEventTrigger);
void GetTasks(ITaskService *pService);
void GetRunningTasks(ITaskService *pService);
void GetTasksInFolder(PWCHAR path, ITaskService *pService);
void PrintState(int taskState);



void CreateTask(ITaskService* pService)
{
	WCHAR taskName[64];
	printf("Enter task name: ");
	scanf("%S", taskName);
	ITaskFolder* pFolder = NULL;
	HRESULT hr = pService->GetFolder(_bstr_t(L"\\"), &pFolder);
	if (FAILED(hr))
	{
		printf("Cannot get root folder pointer: %x\n\n", hr);
		return;
	}
	//  If the same task exists, remove it.
	pFolder->DeleteTask(_bstr_t(taskName), 0);
	//  Create the task definition object to create the task.
	ITaskDefinition* pTask = NULL;
	hr = pService->NewTask(0, &pTask);
	if (FAILED(hr))
	{
		printf("Failed to CoCreate an instance of the TaskService class: %x\n\n", hr);
		pFolder->Release();
		return;
	}
	//  Get the registration info for setting the identification.
	IRegistrationInfo* pRegInfo = NULL;
	hr = pTask->get_RegistrationInfo(&pRegInfo);
	if (FAILED(hr))
	{
		printf("Cannot get identification pointer: %x\n\n", hr);
		pFolder->Release();
		pTask->Release();
		return;
	}
	WCHAR username[UNLEN + 1];
	DWORD username_len = UNLEN + 1;
	if (GetUserName(username, &username_len) == FALSE)
		wcscpy(username, L"Default");
	hr = pRegInfo->put_Author(_bstr_t(username));
	pRegInfo->Release();
	if (FAILED(hr))
	{
		printf("Cannot put identification info: %x\n\n", hr);
		pFolder->Release();
		pTask->Release();
		return;
	}
	//  Create the settings for the task
	ITaskSettings *pSettings = NULL;
	hr = pTask->get_Settings(&pSettings);
	if (FAILED(hr))
	{
		printf("Cannot get settings pointer: %x\n\n", hr);
		pFolder->Release();
		pTask->Release();
		return;
	}
	//  Set setting values for the task.  
	hr = pSettings->put_StartWhenAvailable(VARIANT_TRUE);
	pSettings->Release();
	if (FAILED(hr))
	{
		printf("Cannot put setting info: %x\n\n", hr);
		pFolder->Release();
		pTask->Release();
		return;
	}
	//  Get the trigger collection to insert the event trigger.
	ITriggerCollection *pTriggerCollection = NULL;
	hr = pTask->get_Triggers(&pTriggerCollection);
	if (FAILED(hr))
	{
		printf("Cannot get trigger collection: %x\n\n", hr);
		pFolder->Release();
		pTask->Release();
		return;
	}
	//  Create the event trigger for the task.
	ITrigger *pTrigger = NULL;
	hr = pTriggerCollection->Create(TASK_TRIGGER_EVENT, &pTrigger);
	pTriggerCollection->Release();
	if (FAILED(hr))
	{
		printf("Cannot create the trigger: %x\n\n", hr);
		pFolder->Release();
		pTask->Release();
		return;
	}
	IEventTrigger *pEventTrigger = NULL;
	hr = pTrigger->QueryInterface(IID_IEventTrigger, (void**)&pEventTrigger);
	pTrigger->Release();
	if (FAILED(hr))
	{
		printf("QueryInterface call on IEventTrigger failed: %x\n\n", hr);
		pFolder->Release();
		pTask->Release();
		return;
	}
	hr = pEventTrigger->put_Id(_bstr_t(L"Trigger"));
	if (FAILED(hr))
		printf("Cannot put the trigger ID: %x\n\n", hr);
	int type;
	printf("\
1 - security changes task\n\
2 - ping block task\n\
Task type: ");
	scanf("%d", &type);
	switch (type)
	{
	case 1: hr = CreateSecurityTask(pEventTrigger); break;
	case 2: hr = CreatePingTask(pEventTrigger); break;
	default: pEventTrigger->Release(); pFolder->Release(); pTask->Release(); return;
	}
	pEventTrigger->Release();
	if (FAILED(hr))
	{
		pFolder->Release();
		pTask->Release();
		return;
	}
	IActionCollection *pActionCollection = NULL;
	hr = pTask->get_Actions(&pActionCollection);
	if (FAILED(hr))
	{
		printf("Cannot get action collection pointer: %x\n\n", hr);
		pFolder->Release();
		pTask->Release();
		return;
	}

	// Create the action, specifying that it is an executable action.
	IAction *pAction = NULL;
	hr = pActionCollection->Create(TASK_ACTION_EXEC, &pAction);
	pActionCollection->Release();
	if (FAILED(hr))
	{
		printf("Cannot create the action: %x\n\n", hr);
		pFolder->Release();
		pTask->Release();
		return;
	}
	IExecAction *pExecAction = NULL;
	hr = pAction->QueryInterface(IID_IExecAction, (void**)&pExecAction);
	pAction->Release();
	if (FAILED(hr))
	{
		printf("QueryInterface call failed for IExecAction: %x\n\n", hr);
		pFolder->Release();
		pTask->Release();
		return;
	}
	switch (type)
	{
	case 1:
		hr = pExecAction->put_Path(_bstr_t(L"powershell"));
		hr = pExecAction->put_Arguments(_bstr_t(L"-WindowStyle hidden -Command \"&\
			{[System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms');\
			[System.Windows.Forms.MessageBox]::Show('Security changed!', 'Security change task')}\""));
		break;
	case 2:
		hr = pExecAction->put_Path(_bstr_t(L"powershell"));
		hr = pExecAction->put_Arguments(_bstr_t(L"-WindowStyle hidden -Command \"&\
			{[System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms');\
			[System.Windows.Forms.MessageBox]::Show('ping rejected!', 'ping rejected')}\""));
		break;
	}
	pExecAction->Release();
	if (FAILED(hr))
	{
		printf("\nCannot put the executable path: %x", hr);
		pFolder->Release();
		pTask->Release();
		return;
	}
	ITaskSettings *settings = NULL;
	hr = pTask->get_Settings(&settings);
	if (FAILED(hr))
	{
		printf("Cannot get settings: %x\n\n", hr);
		pFolder->Release();
		pTask->Release();
		return;
	}

	hr = settings->put_StopIfGoingOnBatteries(FALSE);
	if (FAILED(hr))
	{
		printf("Cannot set setting StopIfGoingOnBatteries: %x\n\n", hr);
		pFolder->Release();
		pTask->Release();
		return;
	}
	hr = settings->put_DisallowStartIfOnBatteries(FALSE);
	if (FAILED(hr))
	{
		printf("Cannot set setting DisallowStartIfOnBatteries: %x\n\n", hr);
		pFolder->Release();
		pTask->Release();
		return;
	}
	//  Save the task in the root folder.
	IRegisteredTask *pRegisteredTask = NULL;
	VARIANT varPassword;
	varPassword.vt = VT_EMPTY;
	hr = pFolder->RegisterTaskDefinition(_bstr_t(taskName), pTask, TASK_CREATE_OR_UPDATE,
		_variant_t(), _variant_t(), TASK_LOGON_INTERACTIVE_TOKEN, _variant_t(L""), &pRegisteredTask);
	if (FAILED(hr))
	{
		printf("Error saving the Task : %x\n\n", hr);
		pFolder->Release();
		pTask->Release();
		return;
	}
	printf("Task successfully registered\n\n");
	pFolder->Release();
	pTask->Release();
	pRegisteredTask->Release();
}
void DeleteTask(ITaskService* pService)
{
	WCHAR taskName[64];
	printf("Enter task name: ");
	scanf("%S", taskName);
	ITaskFolder* pFolder = NULL;
	HRESULT hr = pService->GetFolder(_bstr_t(L"\\"), &pFolder);
	if (FAILED(hr))
	{
		printf("Cannot get root folder pointer: %x\n\n", hr);
		return;
	}
	pFolder->DeleteTask(_bstr_t(taskName), 0);
	if (FAILED(hr))
	{
		printf("Task cannot be deleted: %x\n\n", hr);
		return;
	}
	printf("Task successfully deleted\n\n");
	return;
}
HRESULT CreateSecurityTask(IEventTrigger *pEventTrigger)
{
	HRESULT hr = pEventTrigger->put_Subscription(_bstr_t("<QueryList>\
<Query Id = \"0\" Path = \"Microsoft-Windows-Windows Firewall With Advanced Security/Firewall\">\
	<Select Path = \"Microsoft-Windows-Windows Firewall With Advanced Security/Firewall\">\
	*[System[(EventID = 2002 or EventID = 2003 or EventID = 2004 or EventID = 2005 or EventID = 2006 or EventID = 2010)]]\
	</Select></Query>\
<Query Id = \"1\" Path = \"Microsoft-Windows-Windows Defender/Operational\">\
	<Select Path = \"Microsoft-Windows-Windows Defender/Operational\">\
	*[System[(EventID = 5000 or EventID = 5001 or EventID = 5004 or EventID = 5007 or EventID = 5009 or EventID = 5010 or EventID = 5011 or EventID = 5012)]]</Select>\
	</Query>\
</QueryList>"));
	if (FAILED(hr))
		printf("Cannot put subscribition: %x\n\n", hr);
	return hr;
}
HRESULT CreatePingTask(IEventTrigger *pEventTrigger)
{
	HRESULT hr = pEventTrigger->put_Subscription(_bstr_t(
		"<QueryList>\
		<Query Id = \"0\" Path = \"Security\">\
		<Select Path = \"Security\">\
		*[System[(EventID = 5152)]] and\
		*[EventData[Data[@Name='SourceAddress'] = '192.168.0.103']]\
		</Select>\
		</Query>\
		</QueryList>\
	"));
	if (FAILED(hr))
	{
		printf("Cannot put subscribition: %x\n\n", hr);
		return hr;
	}
	return hr;
}
void GetTasks(ITaskService *pService)
{
	nTasks = 0;
	GetRunningTasks(pService);

	WCHAR path[256] = L"\\";
	GetTasksInFolder(path, pService);
}
void GetRunningTasks(ITaskService *pService)
{
	IRunningTaskCollection* pRunningTasks = NULL;
	HRESULT hr = pService->GetRunningTasks(TASK_ENUM_HIDDEN, &pRunningTasks);
	if (FAILED(hr))
		return;
	LONG numTasks = 0;
	hr = pRunningTasks->get_Count(&numTasks);
	if (numTasks == 0)
	{
		pRunningTasks->Release();
		return;
	}
	TASK_STATE taskState;
	for (LONG i = 0; i < numTasks; i++)
	{
		IRunningTask* pRunningTask = NULL;
		hr = pRunningTasks->get_Item(_variant_t(i + 1), &pRunningTask);
		if (SUCCEEDED(hr))
		{
			BSTR taskName = NULL;
			hr = pRunningTask->get_Name(&taskName);
			if (SUCCEEDED(hr))
			{
				printf("%d\n", ++nTasks);
				printf("Name: %S\n", taskName);
				SysFreeString(taskName);
				hr = pRunningTask->get_State(&taskState);
				if (SUCCEEDED(hr))
					PrintState(taskState);
			}
			pRunningTask->Release();
		}
	}
	pRunningTasks->Release();
}
void GetTasksInFolder(PWCHAR path, ITaskService *pService)
{
	ITaskFolder *pFolder = NULL;
	HRESULT hr = pService->GetFolder(_bstr_t(path), &pFolder);
	if (FAILED(hr))
		return;
	IRegisteredTaskCollection* pTaskCollection = NULL;
	hr = pFolder->GetTasks(NULL, &pTaskCollection);
	if (FAILED(hr))
		return;
	LONG numTasks = 0;
	hr = pTaskCollection->get_Count(&numTasks);
	TASK_STATE taskState;
	for (LONG i = 0; i < numTasks; i++)
	{
		IRegisteredTask* pRegisteredTask = NULL;
		hr = pTaskCollection->get_Item(_variant_t(i + 1), &pRegisteredTask);
		if (SUCCEEDED(hr))
		{
			BSTR taskName = NULL;
			hr = pRegisteredTask->get_Name(&taskName);
			if (SUCCEEDED(hr))
			{
				printf("%d\n", ++nTasks);
				printf("Name: %S\n", taskName);
				SysFreeString(taskName);
				hr = pRegisteredTask->get_State(&taskState);
				if (SUCCEEDED(hr))
					PrintState(taskState);
			}
			pRegisteredTask->Release();
		}
	}
	pTaskCollection->Release();
	ITaskFolderCollection *pSubFolders = NULL;
	hr = pFolder->GetFolders(0, &pSubFolders);
	if (FAILED(hr))
		return;
	LONG numSubFolders;
	hr = pSubFolders->get_Count(&numSubFolders);
	if (FAILED(hr))
		return;
	for (LONG i = 0; i < numSubFolders; i++)
	{
		ITaskFolder* pSubFolder;
		pSubFolders->get_Item(_variant_t(i + 1), &pSubFolder);
		if (SUCCEEDED(hr))
		{
			WCHAR name[256];
			BSTR bstrName = _bstr_t(name);
			hr = pSubFolder->get_Name(&bstrName);
			if (SUCCEEDED(hr))
			{
				WCHAR newPath[256];
				wcscpy(newPath, path);
				if (wcscmp(path, L"\\") != 0)
					wcscat(newPath, L"\\");
				wcscat(newPath, bstrName);
				GetTasksInFolder(newPath, pService);
			}
			pSubFolder->Release();
		}
	}
	pFolder->Release();
}
void PrintState(int taskState)
{
	{
		printf("State: ");
		switch (taskState)
		{
		case 1: printf("disabled\n\n"); break;
		case 2: printf("queued\n\n"); break;
		case 3: printf("ready\n\n"); break;
		case 4: printf("running\n\n"); break;
		default: printf("%d\n\n", taskState); break;
		}
	}
}


int main()
{
	//  ------------------------------------------------------
	//  Initialize COM.
	HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if (FAILED(hr))
	{
		printf("\nCoInitializeEx failed: %x", hr);
		return 1;
	}

	//  ------------------------------------------------------
	//  Create an instance of the Task Service. 
	ITaskService *pService = NULL;
	hr = CoCreateInstance(CLSID_TaskScheduler,
		NULL,
		CLSCTX_INPROC_SERVER,
		IID_ITaskService,
		(void**)&pService);
	if (FAILED(hr))
	{
		printf("Failed to create an instance of ITaskService: %x", hr);
		CoUninitialize();
		return 1;
	}

	//  Connect to the task service.
	hr = pService->Connect(_variant_t(), _variant_t(),
		_variant_t(), _variant_t());
	if (FAILED(hr))
	{
		printf("ITaskService::Connect failed: %x", hr);
		pService->Release();
		CoUninitialize();
		return 1;
	}
	
	CreateTask(pService);
	//GetRunningTasks(pService);
	//GetTasks(pService);
	DeleteTask(pService);
	//GetTasks(pService);
	return 0;
}