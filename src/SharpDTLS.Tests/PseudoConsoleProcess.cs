using Microsoft.Win32.SafeHandles;
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace SharpDTLS.Tests
{
    /// <summary>
    /// Runs a Windows console program whose stdin is a pseudo console (ConPTY) while stdout and stderr go to a pipe.
    /// OpenSSL's s_server and s_client poll a console for keystrokes, but treat a redirected stdin as always readable
    /// and block reading it, so they would stop servicing their socket until the next line arrives.
    /// </summary>
    internal sealed class PseudoConsoleProcess : IDisposable
    {
        private readonly IntPtr _pseudoConsole;
        private readonly SafeFileHandle _process;
        private readonly FileStream _input;
        private readonly Thread _outputReader;
        private readonly Thread _consoleDrain;

        public PseudoConsoleProcess(string fileName, string arguments, string workingDirectory, Action<string> onOutputLine)
        {
            // Console input: we write keystrokes to inputWrite. Console rendering (the echo): drained and dropped.
            CreatePipeOrThrow(out var inputRead, out var inputWrite);
            CreatePipeOrThrow(out var consoleRead, out var consoleWrite);
            // stdout and stderr: the child writes outputWrite, which it must inherit.
            CreatePipeOrThrow(out var outputRead, out var outputWrite);
            SetHandleInformation(outputWrite, HandleFlagInherit, HandleFlagInherit);

            int hr = CreatePseudoConsole(new Coord { X = 1000, Y = 50 }, inputRead, consoleWrite, 0, out _pseudoConsole);
            inputRead.Dispose();
            consoleWrite.Dispose();
            if (hr != 0)
                throw new Win32Exception(hr, "CreatePseudoConsole failed");

            IntPtr attributes = IntPtr.Zero;
            IntPtr handleList = Marshal.AllocHGlobal(IntPtr.Size);
            try
            {
                IntPtr size = IntPtr.Zero;
                InitializeProcThreadAttributeList(IntPtr.Zero, 2, 0, ref size);
                attributes = Marshal.AllocHGlobal(size);
                if (!InitializeProcThreadAttributeList(attributes, 2, 0, ref size))
                    throw new Win32Exception();
                if (!UpdateProcThreadAttribute(attributes, 0, ProcThreadAttributePseudoConsole, _pseudoConsole, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero))
                    throw new Win32Exception();
                // Inherit only the output pipe, not handles other tests are passing to their processes right now.
                Marshal.WriteIntPtr(handleList, outputWrite.DangerousGetHandle());
                if (!UpdateProcThreadAttribute(attributes, 0, ProcThreadAttributeHandleList, handleList, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero))
                    throw new Win32Exception();

                var startup = new StartupInfoEx
                {
                    StartupInfo = new StartupInfo
                    {
                        cb = Marshal.SizeOf<StartupInfoEx>(),
                        dwFlags = StartfUseStdHandles,
                        hStdInput = IntPtr.Zero, // the pseudo console
                        hStdOutput = outputWrite.DangerousGetHandle(),
                        hStdError = outputWrite.DangerousGetHandle(),
                    },
                    lpAttributeList = attributes,
                };
                var commandLine = new StringBuilder($"\"{fileName}\" {arguments}");
                if (!CreateProcess(null, commandLine, IntPtr.Zero, IntPtr.Zero, true, ExtendedStartupInfoPresent,
                    IntPtr.Zero, workingDirectory, ref startup, out var info))
                    throw new Win32Exception();
                CloseHandle(info.hThread);
                _process = new SafeFileHandle(info.hProcess, ownsHandle: true);
            }
            finally
            {
                if (attributes != IntPtr.Zero)
                {
                    DeleteProcThreadAttributeList(attributes);
                    Marshal.FreeHGlobal(attributes);
                }
                Marshal.FreeHGlobal(handleList);
                outputWrite.Dispose(); // the child holds its copy; reading ends when it exits
            }

            _input = new FileStream(inputWrite, FileAccess.Write);
            _outputReader = new Thread(() =>
            {
                using var reader = new StreamReader(new FileStream(outputRead, FileAccess.Read), Encoding.UTF8);
                string line;
                while ((line = reader.ReadLine()) != null)
                    onOutputLine(line);
            }) { IsBackground = true };
            _consoleDrain = new Thread(() =>
            {
                using var console = new FileStream(consoleRead, FileAccess.Read);
                byte[] buffer = new byte[4096];
                try { while (console.Read(buffer, 0, buffer.Length) > 0) { } } catch (IOException) { }
            }) { IsBackground = true };
            _outputReader.Start();
            _consoleDrain.Start();
        }

        public bool HasExited => WaitForSingleObject(_process, 0) == 0;

        /// <summary>Waits for the process to exit and for its output to be read.</summary>
        public void WaitForExit()
        {
            WaitForSingleObject(_process, Infinite);
            _outputReader.Join();
        }

        /// <summary>Types <paramref name="line"/> followed by Enter.</summary>
        public void WriteLine(string line)
        {
            byte[] keys = Encoding.UTF8.GetBytes(line + "\r");
            _input.Write(keys, 0, keys.Length);
            _input.Flush();
        }

        public void Dispose()
        {
            if (!HasExited)
                TerminateProcess(_process, 1);
            _input.Dispose();
            ClosePseudoConsole(_pseudoConsole);
            _process.Dispose();
        }

        private static void CreatePipeOrThrow(out SafeFileHandle read, out SafeFileHandle write)
        {
            if (!CreatePipe(out read, out write, IntPtr.Zero, 0))
                throw new Win32Exception();
        }

        private const int StartfUseStdHandles = 0x00000100;
        private const int ExtendedStartupInfoPresent = 0x00080000;
        private const int HandleFlagInherit = 0x00000001;
        private const uint Infinite = 0xFFFFFFFF;
        private static readonly IntPtr ProcThreadAttributePseudoConsole = (IntPtr)0x00020016;
        private static readonly IntPtr ProcThreadAttributeHandleList = (IntPtr)0x00020002;

        [StructLayout(LayoutKind.Sequential)]
        private struct Coord
        {
            public short X;
            public short Y;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct StartupInfo
        {
            public int cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
            public short wShowWindow, cbReserved2;
            public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct StartupInfoEx
        {
            public StartupInfo StartupInfo;
            public IntPtr lpAttributeList;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ProcessInformation
        {
            public IntPtr hProcess, hThread;
            public int dwProcessId, dwThreadId;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CreatePipe(out SafeFileHandle hReadPipe, out SafeFileHandle hWritePipe, IntPtr lpPipeAttributes, int nSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetHandleInformation(SafeFileHandle hObject, int dwMask, int dwFlags);

        [DllImport("kernel32.dll")]
        private static extern int CreatePseudoConsole(Coord size, SafeFileHandle hInput, SafeFileHandle hOutput, int dwFlags, out IntPtr phPC);

        [DllImport("kernel32.dll")]
        private static extern void ClosePseudoConsole(IntPtr hPC);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool UpdateProcThreadAttribute(IntPtr lpAttributeList, int dwFlags, IntPtr attribute, IntPtr lpValue, IntPtr cbSize,
            IntPtr lpPreviousValue, IntPtr lpReturnSize);

        [DllImport("kernel32.dll")]
        private static extern void DeleteProcThreadAttributeList(IntPtr lpAttributeList);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "CreateProcessW")]
        private static extern bool CreateProcess(string lpApplicationName, StringBuilder lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes,
            bool bInheritHandles, int dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref StartupInfoEx lpStartupInfo,
            out ProcessInformation lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(SafeFileHandle hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateProcess(SafeFileHandle hProcess, int uExitCode);
    }
}
