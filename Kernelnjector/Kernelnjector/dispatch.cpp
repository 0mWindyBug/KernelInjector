#include <main.h>

NTSTATUS CreateCloseDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
NTSTATUS IoctlHandler(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	NTSTATUS status;
	PIO_STACK_LOCATION irpStack;
	irpStack = IoGetCurrentIrpStackLocation(Irp);

	if (irpStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_DLL_INJECT)
	{
		if (!irpStack->Parameters.DeviceIoControl.InputBufferLength > 0) {
			status = STATUS_INVALID_PARAMETER;
			Irp->IoStatus.Status = status;
			Irp->IoStatus.Information = 0;
			IoCompleteRequest(Irp, IO_NO_INCREMENT);
			return status;
		}
		PINJECTION_INFO InjectionInfo = (PINJECTION_INFO)Irp->AssociatedIrp.SystemBuffer;
		DbgPrint("[*] received request to inject DLL to pid %d \n",InjectionInfo->TargetPid);
		Inject(InjectionInfo);
		status = STATUS_SUCCESS;
		Irp->IoStatus.Status = status;
		Irp->IoStatus.Information = 0;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return status;

	}
	else
	{
		status = STATUS_INVALID_DEVICE_REQUEST;
		Irp->IoStatus.Status = status;
		Irp->IoStatus.Information = 0;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return status;
	}


}