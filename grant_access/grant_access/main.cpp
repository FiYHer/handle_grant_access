#include "main.h"

UNICODE_STRING g_device_name = RTL_CONSTANT_STRING(L"\\Device\\handle_access");
UNICODE_STRING g_symbolic_link = RTL_CONSTANT_STRING(L"\\DosDevices\\handle_access");
PDEVICE_OBJECT g_device_object = 0;

// Win10 1909的回调参数就四个,其它版本的不确定,
unsigned char handle_callback(
	PHANDLE_TABLE HandleTable,
	PHANDLE_TABLE_ENTRY HandleTableEntry,
	HANDLE Handle,
	PVOID EnumParameter)
{
#define ExpIsValidObjectEntry(Entry) ( (Entry) && (Entry->LowValue != 0) && (Entry->HighValue != -2) )

	unsigned char result = 0;
	if (MmIsAddressValid(EnumParameter))
	{
		phandle_information info = (phandle_information)EnumParameter;
		if (info->handle == (unsigned long long)Handle
			&& MmIsAddressValid(HandleTableEntry)
			&& ExpIsValidObjectEntry(HandleTableEntry)
			&& HandleTableEntry->GrantedAccessBits != info->access)
		{
			DbgPrintEx(0, 0, "[%s] process %ld handle 0x%llx access 0x%lx -> 0x%lx \n",
				__FUNCTION__, info->process_id, info->handle, HandleTableEntry->GrantedAccessBits, info->access);

			HandleTableEntry->GrantedAccessBits = info->access;
			result = 1;
		}
	}

	if (HandleTableEntry) _InterlockedExchangeAdd8((char*)&HandleTableEntry->VolatileLowValue, 1);
	if (HandleTable && HandleTable->HandleContentionEvent) ExfUnblockPushLock(&HandleTable->HandleContentionEvent, NULL);

	return result;
}

void handle_grant_access(handle_information info)
{
	PEPROCESS process{ 0 };
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)info.process_id, &process);
	if (NT_SUCCESS(status))
	{
		// Win10 1909的句柄表偏移为0x418,如果换了系统请修改,不然一个大蓝屏马上出现你眼前
		PHANDLE_TABLE table_ptr = *(PHANDLE_TABLE*)((PUCHAR)process + 0x418);
		if (MmIsAddressValid(table_ptr)) ExEnumHandleTable(table_ptr, &handle_callback, &info, NULL);

		ObDereferenceObject(process);
	}
	else DbgPrintEx(0, 0, "[%s] PsLookupProcessByProcessId error\n", __FUNCTION__);
}

NTSTATUS defalut_irp(PDEVICE_OBJECT device, PIRP irp)
{
	UNREFERENCED_PARAMETER(device);

	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS communication_irp(PDEVICE_OBJECT device, PIRP irp)
{
	UNREFERENCED_PARAMETER(device);

	PIO_STACK_LOCATION io = IoGetCurrentIrpStackLocation(irp);
	ULONG control = io->Parameters.DeviceIoControl.IoControlCode;
	phandle_information info = (phandle_information)irp->AssociatedIrp.SystemBuffer;

	if (control == UPDATE_ACCESS && info) handle_grant_access(*info);

	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS create_device(PDRIVER_OBJECT driver)
{
	NTSTATUS status = IoCreateDevice(driver, 0, &g_device_name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &g_device_object);
	if (!NT_SUCCESS(status)) return status;

	status = IoCreateSymbolicLink(&g_symbolic_link, &g_device_name);
	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(g_device_object);
		return status;
	}

	g_device_object->Flags |= DO_DIRECT_IO;
	g_device_object->Flags &= ~DO_DEVICE_INITIALIZING;

	for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) driver->MajorFunction[i] = defalut_irp;
	driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = communication_irp;

	return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT)
{
	if (g_device_object != nullptr)
	{
		IoDeleteSymbolicLink(&g_symbolic_link);
		IoDeleteDevice(g_device_object);
	}
}

EXTERN_C
NTSTATUS
DriverEntry(
	PDRIVER_OBJECT driver,
	PUNICODE_STRING)
{
	driver->DriverUnload = DriverUnload;
	return create_device(driver);
}