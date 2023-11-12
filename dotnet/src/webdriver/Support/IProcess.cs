using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

using HANDLE = System.IntPtr;
using DWORD = System.UInt32;
using WORD = System.UInt16;
using LPBYTE = System.IntPtr;

namespace OpenQA.Selenium.Support.UI
{
    /// <summary>
    /// A Interface of Operating System Process
    /// </summary>
    public interface IProcess : IDisposable
    {
        /// <summary>
        /// Process Start Information
        /// </summary>
        ProcessStartInfo StartInfo { get; }

        /// <summary>
        /// Process Id
        /// </summary>
        int Id { get; }

        /// <summary>
        /// Is Process Exited?
        /// </summary>
        bool HasExited { get; }
        /// <summary>
        /// Process Exit Code
        /// </summary>
        int ExitCode { get; }

        /// <summary>
        /// Process Standard Input
        /// </summary>
        StreamWriter StandardInput { get; }
        /// <summary>
        /// Process Standard Output
        /// </summary>
        StreamReader StandardOutput { get; }
        /// <summary>
        /// Process Standard Error
        /// </summary>
        StreamReader StandardError { get; }

        /// <summary>
        /// Process Start
        /// </summary>
        /// <returns></returns>
        bool Start();
        /// <summary>
        /// Process Kill
        /// </summary>
        void Kill();
        /// <summary>
        /// Wait for Process Exit
        /// </summary>
        /// <param name="timeoutMilliseconds">Timeout</param>
        void WaitForExit(int timeoutMilliseconds);
    }

    internal class ManagedProcess : IProcess
    {
        private Process process;

        public ProcessStartInfo StartInfo => process.StartInfo;

        public int Id => process.Id;
        public bool HasExited => process.HasExited;
        public int ExitCode => process.ExitCode;

        public StreamWriter StandardInput => process.StandardInput;
        public StreamReader StandardOutput => process.StandardOutput;
        public StreamReader StandardError => process.StandardError;

        public ManagedProcess(ProcessStartInfo startInfo)
        {
            process = new Process();
            process.StartInfo = startInfo;
        }

        ~ManagedProcess()
        {
            Dispose(false);
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            process.Dispose();
            process = null;
        }

        public bool Start() => process.Start();
        public void Kill() => process.Kill();

        public void WaitForExit(int timeoutMilliseconds) => process.WaitForExit(timeoutMilliseconds);
    }

    internal class Win32Process : IProcess
    {
        private IntPtr processHandle;
        private IntPtr threadHandle;

        private readonly ProcessStartInfo startInfo;
        private StreamWriter standardInput;
        private StreamReader standardOutput;
        private StreamReader standardError;

        public ProcessStartInfo StartInfo => startInfo;

        public int Id => (int)GetProcessId(processHandle);

        public bool HasExited
        {
            get
            {
                if (!GetExitCodeProcess(processHandle, out var exitCode))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                return exitCode != StillAlive;
            }
        }

        public int ExitCode
        {
            get
            {
                if (!GetExitCodeProcess(processHandle, out var exitCode))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                if (exitCode != StillAlive)
                    throw new InvalidOperationException();
                return (int)exitCode;
            }
        }

        public StreamWriter StandardInput => standardInput ?? throw new InvalidOperationException();
        public StreamReader StandardOutput => standardOutput ?? throw new InvalidOperationException();
        public StreamReader StandardError => standardError ?? throw new InvalidOperationException();

        public Win32Process(ProcessStartInfo startInfo)
        {
            this.startInfo = startInfo;
            if (startInfo.UseShellExecute)
                throw new ArgumentException("UseShellExecute not support.");
        }

        ~Win32Process()
        {
            Dispose(false);
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (processHandle == IntPtr.Zero)
                throw new ObjectDisposedException(GetType().Name);

            CloseHandle(threadHandle);
            CloseHandle(processHandle);

            if (disposing)
            {
                processHandle = IntPtr.Zero;
                threadHandle = IntPtr.Zero;
            }
        }

        public unsafe bool Start()
        {
            if (processHandle != IntPtr.Zero)
                return false;

            var startupInfo = new StartupInfo();
            startupInfo.cb = (DWORD)Marshal.SizeOf<StartupInfo>();

            var createProcessFlags = (CreateProcessFlags)0;
            if (startInfo.CreateNoWindow)
                createProcessFlags |= CreateProcessFlags.CreateNoWindow;

            var commandLineStr = $"{startInfo.FileName} {startInfo.Arguments}";
            char* commandLine = stackalloc char[32768];
            for (var i = 0; i < commandLineStr.Length; ++i)
            {
                commandLine[i] = commandLineStr[i];
            }
            commandLine[commandLineStr.Length] = '\0';

            if (!CreateProcess(null, commandLine, IntPtr.Zero, IntPtr.Zero, false, createProcessFlags, IntPtr.Zero,
                    startInfo.WorkingDirectory, in startupInfo, out var processInfo))
                throw new Win32Exception(Marshal.GetLastWin32Error());

            processHandle = processInfo.hProcess;
            threadHandle = processInfo.hThread;

            return true;
        }

        public void Kill()
        {
            if (HasExited)
                throw new InvalidOperationException();
            TerminateProcess(processHandle, 0xffffffff);
        }

        public void WaitForExit(int timeoutMilliseconds)
        {
            if (HasExited)
                return;
            WaitForSingleObject(processHandle, (uint)timeoutMilliseconds);
        }

        #region P/Invoke

        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern unsafe bool CreateProcess(
            string applicationName,
            char* commandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool inheritHandles,
            CreateProcessFlags creationFlags,
            IntPtr environment,
            string currentDirectory,
            in StartupInfo startupInfo,
            out ProcessInformation processInformation);

        [DllImport("kernel32", SetLastError = true)]
        private static extern DWORD GetProcessId(HANDLE process);

        [DllImport("kernel32", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetExitCodeProcess(HANDLE process, out DWORD exitCode);

        [DllImport("kernel32", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool TerminateProcess(HANDLE process, uint exitCode);

        [DllImport("kernel32", SetLastError = true)]
        private static extern DWORD WaitForSingleObject(HANDLE handle, DWORD milliseconds);

        [DllImport("kernel32", SetLastError = true)]
        private static extern bool CloseHandle(HANDLE handle);

        [StructLayout(LayoutKind.Sequential)]
        private struct StartupInfo
        {
            public DWORD cb;
            public string Reserved;
            public string Desktop;
            public string Title;
            public DWORD X;
            public DWORD Y;
            public DWORD XSize;
            public DWORD YSize;
            public DWORD XCountChars;
            public DWORD YCountChars;
            public DWORD FillAttribute;
            public StartupInfoFlags Flags;
            public WORD ShowWindow;
            public WORD Reserved2;
            public LPBYTE Reserved2Ptr;
            public HANDLE StdInput;
            public HANDLE StdOutput;
            public HANDLE StdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ProcessInformation
        {
            public HANDLE hProcess;
            public HANDLE hThread;
            public DWORD dwProcessId;
            public DWORD dwThreadId;
        }

        [Flags]
        private enum CreateProcessFlags : DWORD
        {
            DebugProcess = 0x00000001,
            DebugOnlyThisProcess = 0x00000002,
            CreateSuspended = 0x00000004,
            DetachedProcess = 0x00000008,
            CreateNewConsole = 0x00000010,
            CreateNewProcessGroup = 0x00000200,
            CreateUnicodeEnvironment = 0x00000400,
            CreateSeparateWindowsOnWindowsVirtualDiskOperatingSystemMachine = 0x00000800,
            CreateSharedWindowsOnWindowsVirtualDiskOperatingSystemMachine = 0x00001000,
            CreateProtectedProcess = 0x00040000,
            ExtendedStartupInfoPresent = 0x00080000,
            InheritParentAffinity = 0x00010000,
            CreateSecureProcess = 0x00400000,
            CreateBreakAwayFromJob = 0x01000000,
            CreatePreserveCodeAuthZLevel = 0x02000000,
            CreateDefaultErrorMode = 0x04000000,
            CreateNoWindow = 0x08000000,
        }

        [Flags]
        private enum StartupInfoFlags : DWORD
        {
            UseShowWindow = 0x00000001,
            UseSize = 0x00000002,
            UsePosition = 0x00000004,
            UseCountChars = 0x00000008,
            UseFillAttribute = 0x00000010,
            RunFullScreen = 0x00000020,
            ForceOnFeedBack = 0x00000040,
            ForceOffFeedBack = 0x00000080,
            UseStandardHandles = 0x00000100,
            UseHotKey = 0x00000200,
            TitleIsLinkName = 0x00000800,
            TitleIsAppId = 0x00001000,
            PreventPinning = 0x00002000,
            UntrustedSource = 0x00008000,
        }

        private const int StillAlive = 259;

        #endregion
    }
}
