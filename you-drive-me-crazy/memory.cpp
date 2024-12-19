#include "memory.h"



PVOID get_system_module_base(const char* module_name)
{
	ULONG bytes = 0;
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, NULL, bytes, &bytes);

	if (!bytes)
		return NULL;

	PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, 0x77656564);


	status = ZwQuerySystemInformation(SystemModuleInformation, modules, bytes, &bytes);

	if (!NT_SUCCESS(status))
		return NULL;

	PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;

	PVOID module_base = 0, module_size = 0;

	for (ULONG i = 0; i < modules->NumberOfModules; i++)
	{
		if (strcmp((char*)module[i].FullPathName, module_name) == 0)
		{
			module_base = module[i].ImageBase;
			module_size = (PVOID)module[i].ImageSize;
			break;
		}
	}

	if (modules)
		ExFreePoolWithTag(modules, NULL);

	if (module_base <= NULL)
		return NULL;
	
	return module_base;
}

//PVOID get_system_module_export(const char* module_name, LPCSTR routine_name)
//{
//	PVOID lpModule = get_system_module_base(module_name);
//
//	if (!lpModule)
//		return NULL;
//
//	return RtlFindExportedRoutineByName(lpModule, routine_name);
//}

PVOID get_system_routine_address(PCWSTR routine_name)
{
	UNICODE_STRING name;
	RtlInitUnicodeString(&name, routine_name);
	return MmGetSystemRoutineAddress(&name);
}

PVOID get_system_module_export(LPCWSTR module_name, LPCSTR routine_name)
{
	DbgPrint("get_system_module_export: Entered function.\n");

	// Get the address of PsLoadedModuleList
	PLIST_ENTRY module_list = reinterpret_cast<PLIST_ENTRY>(get_system_routine_address(L"PsLoadedModuleList"));
	if (!module_list)
	{
		DbgPrint("Error: Failed to retrieve PsLoadedModuleList.\n");
		return NULL;
	}

	DbgPrint("PsLoadedModuleList retrieved: 0x%p\n", module_list);
	DbgPrint("Looking for module: %S\n", module_name);

	// Iterate through the loaded modules
	for (PLIST_ENTRY link = module_list; link != module_list->Blink; link = link->Flink)
	{
		// Get the LDR_DATA_TABLE_ENTRY
		LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(link, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);
		//DbgPrint("Inspecting module entry at address: 0x%p\n", entry);

		UNICODE_STRING name;
		RtlInitUnicodeString(&name, module_name);

		// Compare the module name with the one we are looking for
		if (RtlEqualUnicodeString(&entry->BaseDllName, &name, TRUE))
		{
			DbgPrint("Module found: %wZ\n", &entry->BaseDllName);

			// Check if the DllBase is valid
			if (entry->DllBase)
			{
				DbgPrint("DllBase address: 0x%p\n", entry->DllBase);

				// Look for the routine in the module's export table
				PVOID routine = RtlFindExportedRoutineByName(entry->DllBase, routine_name);
				if (routine)
				{
					DbgPrint("Routine %s found at address: 0x%p\n", routine_name, routine);
					return routine;
				}
				else
				{
					DbgPrint("Error: Routine %s not found in module %wZ.\n", routine_name, &entry->BaseDllName);
					return NULL;
				}
			}
			else
			{
				DbgPrint("Error: DllBase is NULL for module %wZ.\n", &entry->BaseDllName);
				return NULL;
			}
		}
		else
		{
			continue;
			//DbgPrint("Module %wZ does not match %S.\n", &entry->BaseDllName, module_name);
		}
	}

	DbgPrint("Error: Module %S not found in PsLoadedModuleList.\n", module_name);
	return NULL;
}


bool write_memory(void* address, void* buffer, size_t size)
{
	if (!RtlCopyMemory(address, buffer, size))
	{
		return false;
	}

	else
	{
		return true;
	}
}

bool write_to_read_only_memory(void* address, void* buffer, size_t size)
{
	DbgPrint("in write to read only");
	PMDL Mdl = IoAllocateMdl(address, size, FALSE, FALSE, NULL);

	if (!Mdl){
		DbgPrint("No Mdl");
		return false;
	}
	MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess);
	PVOID Mapping = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
	if (!Mapping) {
		DbgPrint("No mapping");
		return false;
	}
	MmProtectMdlSystemAddress(Mdl, PAGE_READWRITE);

	write_memory(Mapping, buffer, size);

	MmUnmapLockedPages(Mapping, Mdl);
	MmUnlockPages(Mdl);
	IoFreeMdl(Mdl);

	return true;
}

ULONG64 get_module_base_x64(PEPROCESS proc, UNICODE_STRING module_name)
{
	DbgPrint("In get module base");
	PPEB pPeb = PsGetProcessPeb(proc);

	if (!pPeb)
	{
		return NULL;
	}
	
	KAPC_STATE state;

	KeStackAttachProcess(proc, &state);

	PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)pPeb->Ldr;

	if (!pLdr)
	{
		KeUnstackDetachProcess(&state);
		return NULL;
	}

	for (PLIST_ENTRY list = (PLIST_ENTRY)pLdr->ModuleListInitOrder.Flink; list != &pLdr->ModuleListLoadOrder; list = (PLIST_ENTRY)list->Flink)
	{
		PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);

		if (RtlCompareUnicodeString(&pEntry->BaseDllName, &module_name, TRUE) == NULL)
		{
			ULONG64 baseAddr = (ULONG64)pEntry->DllBase;
			KeUnstackDetachProcess(&state);
			return baseAddr;
		}
	}

	KeUnstackDetachProcess(&state);
	return NULL;
}

bool read_kernel_memory(HANDLE pid, uintptr_t address, void* buffer, SIZE_T size)
{
	DbgPrint("In read kernel memory");
	if (!address || !buffer || !size)
		return false;

	SIZE_T bytes = 0;
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS process;
	PsLookupProcessByProcessId((HANDLE)pid, &process);

	status = MmCopyVirtualMemory(process, (void*)address, (PEPROCESS)PsGetCurrentProcess(), (void*)buffer, size, KernelMode, &bytes);

	if (!NT_SUCCESS(status))
	{
		return false;
	}
	else
	{
		return true;
	}
}

bool write_kernel_memory(HANDLE pid, uintptr_t address, void* buffer, SIZE_T size)
{
	DbgPrint("In write kernel memory");
	if (!address || !buffer || !size)
	{
		return false;
	}

	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS process;
	PsLookupProcessByProcessId((HANDLE)pid, &process);

	KAPC_STATE state;
	KeStackAttachProcess((PEPROCESS)process, &state);

	MEMORY_BASIC_INFORMATION info;

	status = ZwQueryVirtualMemory(ZwCurrentProcess(), (PVOID)address, MemoryBasicInformation, &info, sizeof(info), NULL);
	if (!NT_SUCCESS(status))
	{
		KeUnstackDetachProcess(&state);
		return false;
	}

	if (((uintptr_t)info.BaseAddress + info.RegionSize) < (address + size))
	{
		KeUnstackDetachProcess(&state);
		return false;
	}

	if (!(info.State & MEM_COMMIT) || (info.Protect & (PAGE_GUARD | PAGE_NOACCESS)))
	{
		KeUnstackDetachProcess(&state);
		return false;
	}

	if ((info.Protect & PAGE_EXECUTE_READWRITE) || (info.Protect & PAGE_EXECUTE_WRITECOPY) || (info.Protect & PAGE_READWRITE) || (info.Protect & PAGE_WRITECOPY))
	{
		RtlCopyMemory((void*)address, buffer, size);
	}
	KeUnstackDetachProcess(&state);
	return true;
}