#pragma once

class CThreadEnumerator
{
	public:
		CThreadEnumerator(DWORD dwProcessId);
		~CThreadEnumerator();

		SYSTEM_PROCESS_INFORMATION * GetProcInfo();
		SYSTEM_THREAD_INFORMATION  * GetThreadList(SYSTEM_PROCESS_INFORMATION * procInfo);
		DWORD				    	 GetThreadCount(SYSTEM_PROCESS_INFORMATION * procInfo);

		SYSTEM_THREAD_INFORMATION  * FindThread(SYSTEM_PROCESS_INFORMATION * procInfo, DWORD dwThreadId);

	protected:
		BYTE * InitializeQuery();

	private:
		DWORD  m_dwProcessId;
		BYTE * m_Cap;
};

