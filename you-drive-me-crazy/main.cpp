#include "hook.h"
#include <ntddk.h>
extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING reg_path)
{
	DbgPrint("Driver Entry$$$$$$");
	UNREFERENCED_PARAMETER(driver_object);
	UNREFERENCED_PARAMETER(reg_path);

 if (!mchook::call_kernel_function(&mchook::hook_handler)) {
        DbgPrint("[-] Failed to install hook\n");
        return STATUS_UNSUCCESSFUL;
    }
	//mchook::call_kernel_function(&mchook::hook_handler);
    DbgPrint("[+] Hook installed successfully\n");
    return STATUS_SUCCESS;
}