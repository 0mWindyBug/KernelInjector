#include <main.h>


ProcAttach::ProcAttach(ULONG pid)
{
	m_pid = pid;
	m_process = nullptr;
	m_pkapc_state = nullptr;
	PEPROCESS Process;
	NTSTATUS status = PsLookupProcessByProcessId(UlongToHandle(m_pid), &Process);
	if (!NT_SUCCESS(status))
	{
		m_attached = false; 
		return;
	}

	m_pkapc_state = new(NonPagedPool, TAG)KAPC_STATE;
	if (!m_pkapc_state)
	{
		m_attached = false;
		return;
	}
	
	
	KeStackAttachProcess(Process, m_pkapc_state);
	m_attached = true;
	return ;
}


ProcAttach::~ProcAttach()
{
	if (m_process)
		ObDereferenceObject(m_process);
	if (m_pkapc_state)
	{
		KeUnstackDetachProcess(m_pkapc_state);
		delete m_pkapc_state;
	}
}

bool ProcAttach::IsAttached()
{
	return m_attached;
}