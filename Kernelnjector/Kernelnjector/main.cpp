#include <main.h>


PDEVICE_OBJECT DeviceObject;
UNICODE_STRING deviceName, symLinkName;
EX_RUNDOWN_REF PendingOperations;

void DriverUnload(
	_In_ PDRIVER_OBJECT DriverObject
)
{

	ExWaitForRundownProtectionRelease(&PendingOperations);
	IoDeleteDevice(DriverObject->DeviceObject);
	IoDeleteSymbolicLink(&symLinkName);
	DbgPrint("[*] injector unloaded\n");
}


EXTERN_C NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING ssdl;
	ExInitializeRundownProtection(&PendingOperations);

	RtlInitUnicodeString(&deviceName, L"\\Device\\kinjector");
	RtlInitUnicodeString(&symLinkName, L"\\??\\kinjector");

	RtlInitUnicodeString(&ssdl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
	status = IoCreateDeviceSecure(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &ssdl, NULL, &DeviceObject);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[*] Failed to create device  (status = %lx)\n", status);
		return status;
	}

	status = IoCreateSymbolicLink(&symLinkName, &deviceName);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[*] Failed to create symlink  (status = %lx)\n", status);
		return status;
	}

	DriverObject->DriverUnload = DriverUnload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateCloseDispatch;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoctlHandler;


	DbgPrint("[*] injector loading!\n");



	return status;

}