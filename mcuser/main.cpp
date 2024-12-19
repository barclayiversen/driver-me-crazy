#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <memory>
#include <string_view>
#include <cstdint>
#include <vector>

typedef struct _NULL_MEMORY
{
	void* buffer_address;
	UINT_PTR address;
	ULONGLONG size;
	ULONG pid;
	BOOLEAN write;
	BOOLEAN read;
	BOOLEAN req_base;
	BOOLEAN draw_box;
	int r, g, b, x, y, w, h, t;
	void* output;
	const char* module_name;
	ULONG64 base_address;
}NULL_MEMORY;

uintptr_t base_address = 0;
std::uint32_t process_id = 0;

template<typename ... Arg>
	uint64_t call_hook(const Arg ... args)
	{
		printf("call_hook####\n");
		//void* hooked_function = GetProcAddress(LoadLibraryA("win32k.dll"), "NtSetCompositionSurfaceStatistics");
		void* hooked_function = GetProcAddress(LoadLibraryA("win32u.dll"), "NtDxgkGetTrackedWorkloadStatistics"); //  function must match line 19 in hook.cpp
	
		if (!hooked_function) {
			printf("[-] Unable to resolve NtDxgkGetTrackedWorkloadStatistics!\n");
			return -1;
		}
		printf("Calling NtDxgkGetTrackedWorkloadStatistics...\n");
		auto func = static_cast<uint64_t(_stdcall*)(Arg...)>(hooked_function);
		printf("Result: 0x%llx\n", func);
		if (!func) {
			printf("no func!");
			return -1;
		}
		printf("Success");
		return func(args ...);
	}

struct HandleDisposer
{
	using pointer = HANDLE;
	void operator()(HANDLE handle) const
	{
		if (handle != NULL || handle != INVALID_HANDLE_VALUE)
		{
			CloseHandle(handle);
		}
	}
};

using unique_handle = std::unique_ptr<HANDLE, HandleDisposer>;

static std::uint32_t get_process_id(std::string_view process_name)
{
	printf("[+] get_process_id is called\n");
	
	PROCESSENTRY32 processentry;
	const unique_handle snapshot_handle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL));

	if (snapshot_handle.get() == INVALID_HANDLE_VALUE)
		return NULL;

	processentry.dwSize = sizeof(MODULEENTRY32);

	while (Process32Next(snapshot_handle.get(), &processentry) == TRUE)
	{
		if (process_name.compare(processentry.szExeFile) == NULL)
		{
			printf("[+] we returned a matching process ID\n");

			return processentry.th32ProcessID;
		}
	}
	printf("[-] returning NULL from get_process_id\n");

	return NULL;
}

static ULONG64 get_module_base_address(const char* module_name)
{
	printf("[+] get_module_base_address is called\n");

	NULL_MEMORY instructions = { 0 };
	instructions.pid = process_id;
	instructions.req_base = TRUE;
	instructions.read = FALSE;
	instructions.write = FALSE;
	instructions.draw_box = FALSE;
	instructions.module_name = module_name;
	call_hook(&instructions);
	printf("[+] below call_hook");
	ULONG64 base = NULL;
	base = instructions.base_address;
	return base;
};

template<class T>
T Read(UINT_PTR read_address)
{
	T response{};
	NULL_MEMORY instructions;
	instructions.pid = process_id;
	instructions.size = sizeof(T);
	instructions.address = read_address;
	instructions.read = TRUE;
	instructions.write = FALSE;
	instructions.draw_box = FALSE;
	instructions.req_base = FALSE;
	instructions.output = &response;
	call_hook(&instructions);
	return response;
}

bool write_memory(UINT_PTR write_address, UINT_PTR source_address, SIZE_T write_size)
{
	printf("In write memory");
	NULL_MEMORY instructions;
	instructions.address = write_address;
	instructions.pid = process_id;
	instructions.write = TRUE;
	instructions.read = FALSE;
	instructions.draw_box = FALSE;
	instructions.buffer_address = (void*)source_address;
	instructions.size = write_size;

	call_hook(&instructions);

	return true;
}

bool draw_box(int x, int y, int w, int h, int t, int r, int g, int b)
{
	printf("draw box function\n");
	NULL_MEMORY instructions;
	instructions.write = FALSE;
	instructions.read = FALSE;
	instructions.req_base = FALSE;
	instructions.draw_box = TRUE;

	instructions.x = x;
	instructions.y = y;
	instructions.w = w;
	instructions.h = h;
	instructions.t = t;

	instructions.r = r;
	instructions.g = g;
	instructions.b = b;


	call_hook(&instructions);

	return true;
}

template<typename S>
bool write(UINT_PTR write_address, const S& value)
{
	return write_memory(write_address, (UINT_PTR)&value, sizeof(S));
}

int main()
{
	/*printf("hello world\n");
	process_id = get_process_id("cs2.exe");
	printf("getting base address\n");
	base_address = get_module_base_address("cs2.EXE");
	printf("aafter bASE ADDRESS");

	if (!base_address)
	{
		printf("FUCK!");

	}
	else
	{
		printf("Sweet");
	}

	Sleep(5000);
	return NULL;*/

	while (true)
	{
		draw_box(50, 50, 50, 50, 2, 255, 0, 0);
		Sleep(100); // 100 ms delay
	}
}