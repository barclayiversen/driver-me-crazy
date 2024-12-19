#include "hook.h"
#include <wingdi.h>

GdiSelectBrush_t GdiSelectBrush = NULL;
PatBlt_t NtGdiPatBlt = NULL;
NtUserGetDC_t NtUserGetDC = NULL;
NtGdiCreateSolidBrush_t NtGdiCreateSolidBrush = NULL;
ReleaseDC_t NtUserReleaseDC = NULL;
DeleteObjectApp_t NtGdiDeleteObjectApp = NULL;

void verify_hook(PVOID* function) {
    BYTE buffer[16];
    RtlCopyMemory(buffer, function, sizeof(buffer));
    DbgPrint("Hook memory: ");
    for (int i = 0; i < sizeof(buffer); i++) {
        DbgPrint("0x%02X ", buffer[i]);
    }
    DbgPrint("\n");
}


bool mchook::call_kernel_function(void* kernel_function_address)
{
    DbgPrint("[-] enter call kernel function\n");
    DbgPrint("[-] kernel_function_address: 0x%p\n", kernel_function_address);

    if (!kernel_function_address) {
        DbgPrint("[-] Invalid kernel function address\n");
        return false;

    }
    //NtQueryCompositionSurfaceStatistics
    DbgPrint("[-] enter call kernel function 2\n");

    PVOID* function = reinterpret_cast<PVOID*>(get_system_module_export(L"dxgkrnl.sys", "NtDxgkGetTrackedWorkloadStatistics"));
    if (!function) {
        DbgPrint("[-] Failed to find NtDxgkGetTrackedWorkloadStatistics\n");
        return false;
    }

    BYTE orig[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

    BYTE shell_code[] = { 0x48, 0xB8 }; // mov rax, xxx
    //BYTE shell_code[] = { 0xCC }; // Trigger a breakpoint

    BYTE shell_code_end[] = { 0xFF, 0xE0 }; //jmp rax
    DbgPrint("[-] enter call kernel function 3\n");

    RtlSecureZeroMemory(&orig, sizeof(orig));
    memcpy((PVOID)((ULONG_PTR)orig), &shell_code, sizeof(shell_code));
    uintptr_t hook_address = reinterpret_cast<uintptr_t>(kernel_function_address);
    memcpy((PVOID)((ULONG_PTR)orig + sizeof(shell_code)), &hook_address, sizeof(void*));
    memcpy((PVOID)((ULONG_PTR)orig + sizeof(shell_code) + sizeof(void*)), &shell_code_end, sizeof(shell_code_end));

    
    if (!write_to_read_only_memory(function, orig, sizeof(orig))) {
        DbgPrint("[-] Failed to write shell code to read-only memory\n");
        return false;
    }

    verify_hook(function);



    DbgPrint("[+] Hook installed at address: 0x%p\n", function);

    GdiSelectBrush = (GdiSelectBrush_t)get_system_module_export(L"win32kfull.sys", "NtGdiSelectBrush");
    NtGdiCreateSolidBrush = (NtGdiCreateSolidBrush_t)get_system_module_export(L"win32kfull.sys", "NtGdiCreateSolidBrush");
    NtGdiPatBlt = (PatBlt_t)get_system_module_export(L"win32kfull.sys", "NtGdiPatBlt");
    NtUserGetDC = (NtUserGetDC_t)get_system_module_export(L"win32kbase.sys", "NtUserGetDC");
    NtUserReleaseDC = (ReleaseDC_t)get_system_module_export(L"win32kbase.sys", "NtUserReleaseDC");
    NtGdiDeleteObjectApp = (DeleteObjectApp_t)get_system_module_export(L"win32kbase.sys", "NtGdiDeleteObjectApp");

    DbgPrint("succesfully called kernel function");
    return true;
}



NTSTATUS mchook::hook_handler(PVOID called_param)
{
    DbgPrint("hook_handler: Entry\n");
    if (!called_param) {
        DbgPrint("[-] called_param is NULL\n");
        return STATUS_UNSUCCESSFUL;
    }

    NULL_MEMORY* instructions = (NULL_MEMORY*)called_param;
    DbgPrint("hook_handler: req_base=%d, write=%d, read=%d, draw_box=%d\n",
        instructions->req_base, instructions->write, instructions->read, instructions->draw_box);

    if (instructions->req_base == TRUE)
    {
        ANSI_STRING AS;
        UNICODE_STRING ModuleName;

        RtlInitAnsiString(&AS, instructions->module_name);
        RtlAnsiStringToUnicodeString(&ModuleName, &AS, TRUE);

        PEPROCESS process;
        PsLookupProcessByProcessId((HANDLE)instructions->pid, &process);
        ULONG64 base_address64 = NULL;
        base_address64 = get_module_base_x64(process, ModuleName);
        instructions->base_address = base_address64;
        RtlFreeUnicodeString(&ModuleName);

    }

    else if (instructions->write != FALSE)
    {
        if (instructions->address < 0X7FFFFFFFFFFF && instructions->address > 0)
        {
            PVOID kernelBuff = ExAllocatePool(NonPagedPool, instructions->size);

            if (!kernelBuff)
            {
                return STATUS_UNSUCCESSFUL;
            }

            if (!memcpy(kernelBuff, instructions->buffer_address, instructions->size))
            {
                return STATUS_UNSUCCESSFUL;
            }

            PEPROCESS process;
            PsLookupProcessByProcessId((HANDLE)instructions->pid, &process);
            write_kernel_memory((HANDLE)instructions->pid, instructions->address, kernelBuff, instructions->size);
            ExFreePool(kernelBuff);
        }
    }

    else if (instructions->read == TRUE)
    {
        if (instructions->address < 0X7FFFFFFFFFFF && instructions->address > 0)
        {
            read_kernel_memory((HANDLE)instructions->pid, instructions->address, instructions->output, instructions->size);
        }
    }

    else if (instructions->draw_box == TRUE)
    {
        DbgPrint("draw_box: Drawing box initiated\n");

      
        __try {
            ProbeForRead(instructions, sizeof(NULL_MEMORY), __alignof(NULL_MEMORY));
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrint("Error: Invalid instructions pointer\n");
            return STATUS_UNSUCCESSFUL;
        }
        


        HDC hdc = NtUserGetDC(NULL);
        if (!hdc) {
            DbgPrint("draw_box: NtUserGetDC failed\n");
            return STATUS_UNSUCCESSFUL;
        }
        DbgPrint("draw_box: HDC retrieved: 0x%p\n", hdc);

        HBRUSH brush = NtGdiCreateSolidBrush(RGB(instructions->r, instructions->g, instructions->b), NULL);
        if (!brush) {
            DbgPrint("draw_box: NtGdiCreateSolidBrush failed\n");
            NtUserReleaseDC(hdc);
            return STATUS_UNSUCCESSFUL;
        }
        DbgPrint("draw_box: Brush created: 0x%p\n", brush);

        RECT rect = { instructions->x, instructions->y, instructions->x + instructions->w, instructions->y + instructions->h };
        FrameRect(hdc, &rect, brush, instructions->t);

        NtUserReleaseDC(hdc);
        NtGdiDeleteObjectApp(brush);

        DbgPrint("draw_box: Drawing box completed\n");
    }


    return STATUS_SUCCESS;
}

INT mchook::FrameRect(HDC hDc, CONST RECT* lprc, HBRUSH hbr, int thickness) 
{

    HBRUSH oldbrush;
    RECT r = *lprc;
    DbgPrint("in FrameRect.\n");

    if (!(oldbrush = GdiSelectBrush(hDc, hbr))) return 0;

    NtGdiPatBlt(hDc, r.left, r.top, thickness, r.bottom - r.top, PATCOPY);
    NtGdiPatBlt(hDc, r.right - thickness, r.top, thickness, r.bottom - r.top, PATCOPY);
    NtGdiPatBlt(hDc, r.left, r.top, r.right - r.left, thickness, PATCOPY);
    NtGdiPatBlt(hDc, r.left, r.bottom - thickness, r.right - r.left, thickness, PATCOPY);

    GdiSelectBrush(hDc, oldbrush);
    return TRUE;
}