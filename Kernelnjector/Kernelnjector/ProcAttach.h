#pragma once
#include <main.h>



class ProcAttach
{
private:
	PKAPC_STATE m_pkapc_state;
	ULONG   m_pid;
	PEPROCESS m_process;
	bool m_attached;
public:
	ProcAttach(ULONG pid);
	~ProcAttach();
	bool IsAttached();


};