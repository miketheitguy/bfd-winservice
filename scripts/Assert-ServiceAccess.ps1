#Requires -Version 5.1
# Native access checks use only temporary token handles; no service is changed.
if (-not ('BfdServiceAccess' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

public static class BfdServiceAccess
{
    [StructLayout(LayoutKind.Sequential)]
    struct SidAndAttributes { public IntPtr Sid; public uint Attributes; }
    [StructLayout(LayoutKind.Sequential)]
    struct GenericMapping { public uint Read, Write, Execute, All; }

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool CreateRestrictedToken(IntPtr token, uint flags, uint disableCount,
        IntPtr disableSids, uint privilegeCount, IntPtr privileges, uint restrictCount,
        SidAndAttributes[] restrictSids, out IntPtr restricted);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool DuplicateToken(IntPtr token, int level, out IntPtr duplicate);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool AccessCheck(byte[] descriptor, IntPtr token, uint access,
        ref GenericMapping mapping, byte[] privileges, ref uint privilegeLength,
        out uint granted, out bool allowed);
    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr handle);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr OpenSCManager(string machine, string database, uint access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr OpenService(IntPtr manager, string name, uint access);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool QueryServiceObjectSecurity(IntPtr service, uint information,
        byte[] descriptor, uint length, out uint needed);
    [DllImport("advapi32.dll")]
    static extern bool CloseServiceHandle(IntPtr handle);

    public static byte[] ReadDescriptor(string name)
    {
        IntPtr manager = OpenSCManager(null, null, 1); // SC_MANAGER_CONNECT.
        if (manager == IntPtr.Zero) throw new Win32Exception();
        try {
            IntPtr service = OpenService(manager, name, 0x20000); // READ_CONTROL.
            if (service == IntPtr.Zero) throw new Win32Exception();
            try {
                uint needed;
                QueryServiceObjectSecurity(service, 7, null, 0, out needed);
                if (Marshal.GetLastWin32Error() != 122 || needed == 0)
                    throw new Win32Exception();
                byte[] descriptor = new byte[needed];
                if (!QueryServiceObjectSecurity(service, 7, descriptor, needed, out needed))
                    throw new Win32Exception();
                return descriptor;
            } finally { CloseServiceHandle(service); }
        } finally { CloseServiceHandle(manager); }
    }

    public static bool AuthenticatedReaderAllowed(byte[] descriptor, uint access)
    {
        byte[] sid = new byte[new SecurityIdentifier("S-1-5-11").BinaryLength];
        new SecurityIdentifier("S-1-5-11").GetBinaryForm(sid, 0);
        IntPtr sidPointer = Marshal.AllocHGlobal(sid.Length);
        IntPtr restricted = IntPtr.Zero, impersonation = IntPtr.Zero;
        try {
            Marshal.Copy(sid, 0, sidPointer, sid.Length);
            var restrictions = new[] { new SidAndAttributes { Sid = sidPointer } };
            using (var identity = WindowsIdentity.GetCurrent()) {
                // DISABLE_MAX_PRIVILEGE and an Authenticated Users restricting SID
                // make this work even when the test runner is an administrator.
                if (!CreateRestrictedToken(identity.Token, 1, 0, IntPtr.Zero,
                    0, IntPtr.Zero, 1, restrictions, out restricted))
                    throw new Win32Exception();
            }
            if (!DuplicateToken(restricted, 2, out impersonation))
                throw new Win32Exception();
            var mapping = new GenericMapping {
                Read = 0x2008d, Write = 0x20002, Execute = 0x20170, All = 0xf01ff
            };
            byte[] privileges = new byte[1024];
            uint length = (uint)privileges.Length, granted;
            bool allowed;
            if (!AccessCheck(descriptor, impersonation, access, ref mapping,
                privileges, ref length, out granted, out allowed))
                throw new Win32Exception();
            return allowed;
        } finally {
            if (impersonation != IntPtr.Zero) CloseHandle(impersonation);
            if (restricted != IntPtr.Zero) CloseHandle(restricted);
            Marshal.FreeHGlobal(sidPointer);
        }
    }
}
'@
}

function Assert-ServiceReaderAccess {
    param([Parameter(Mandatory)][Security.AccessControl.RawSecurityDescriptor]$Descriptor)
    $bytes = [byte[]]::new($Descriptor.BinaryLength)
    $Descriptor.GetBinaryForm($bytes, 0)
    foreach ($right in @(0x1, 0x4, 0x8, 0x80, 0x20000, 0x2008d)) {
        if (-not [BfdServiceAccess]::AuthenticatedReaderAllowed($bytes, $right)) {
            throw "Authenticated readers cannot query the service (access mask $right)."
        }
    }
    foreach ($right in @(0x2, 0x10, 0x20, 0x40, 0x100, 0x10000, 0x40000, 0x80000)) {
        if ([BfdServiceAccess]::AuthenticatedReaderAllowed($bytes, $right)) {
            throw "Authenticated readers can control the service (access mask $right)."
        }
    }
}
