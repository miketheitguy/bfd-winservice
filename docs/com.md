# Query the current BFD state through COM

Monitoring clients can query the installed service through a read-only Component
Object Model (COM) Automation interface. The interface reads the live engine's
local state without locking the packet loop. PowerShell and C# clients can use
late binding; C++ and Rust clients can use the standard `IDispatch` interface.

## Before you begin

Install the x64 MSI and [configure the service](setup.md#2-configure-the-session).
Use a 64-bit client on the same machine. The foreground `--console` mode does
not host the COM server.

Authenticated local users can activate and query the running server, subject to
the machine's COM security policy. Only SYSTEM and administrators can launch the
service through COM: their activation starts a stopped `BfdWinService`, so finish
configuration first. A standard user's activation of a stopped service fails with
`E_ACCESSDENIED` (`0x80070005`) instead of undoing an administrator's Stop, which
would resume BGP control. Remote and anonymous calls are denied. The MSI
does not add a COM network firewall rule. File-copy installations do not register
the Automation class; use the MSI for this interface.

## Query from PowerShell

In 64-bit Windows PowerShell or PowerShell 7, run:

```powershell
$session = New-Object -ComObject BfdWinService.SessionState
try {
    $session.GetState()
    $session.StateName
} finally {
    [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($session)
}
```

An established classical BFD or S-BFD initiator session returns `3` and `Up`.
A session waiting for a peer returns `1` and `Down`. The properties reflect the
state at each individual call; two calls can observe different states.

## Query from C#

Use late binding through .NET COM reflection in a Windows application. Mark the calling thread with
`[MTAThread]` or `[STAThread]` and release the COM object when finished:

```csharp
using System;
using System.Reflection;
using System.Runtime.InteropServices;

class Program
{
    [MTAThread]
    static void Main()
    {
        Type type = Type.GetTypeFromProgID("BfdWinService.SessionState", true);
        object session = Activator.CreateInstance(type);
        try
        {
            int state = (int)session.GetType().InvokeMember(
                "GetState", BindingFlags.InvokeMethod, null, session,
                new object[0]);
            Console.WriteLine(state);
        }
        finally
        {
            Marshal.FinalReleaseComObject(session);
        }
    }
}
```

## Automation contract

The class uses ProgID `BfdWinService.SessionState` and CLSID
`{4B19A10F-8CD1-46F1-A1EA-6C68ECBA7657}`. Its AppID is
`{EBF04871-D193-4CDF-ABBC-DCD7D220224B}`. Request the standard `IDispatch` IID
`{00020400-0000-0000-C000-000000000046}` with `CLSCTX_LOCAL_SERVER` after
initializing COM on the client thread.

The following members accept no arguments:

| Member | DISPID | Invocation | Return type |
| --- | --- | --- | --- |
| `State` | 1 | `DISPATCH_PROPERTYGET` | `VT_I4` (32-bit signed integer) |
| `StateName` | 2 | `DISPATCH_PROPERTYGET` | `VT_BSTR` (string) |
| `GetState()` | 3 | `DISPATCH_METHOD` | `VT_I4` (32-bit signed integer) |

`GetIDsOfNames` resolves names without regard to ASCII case. `Invoke` requires
`IID_NULL`, an empty `DISPPARAMS`, and the matching invocation flags. Property
writes, arguments, and unknown members return standard Automation errors.
`GetTypeInfoCount` returns `1`; `GetTypeInfo(0)` supplies member metadata created
in memory. Clients need no separately installed type library or custom proxy.

State values follow [RFC 5880](https://www.rfc-editor.org/rfc/rfc5880#section-4.1):

| Value | Name | Meaning |
| --- | --- | --- |
| 0 | `AdminDown` | Administrative shutdown or S-BFD reflector maintenance |
| 1 | `Down` | Session has not established or detection has expired |
| 2 | `Init` | Classical BFD handshake is in progress |
| 3 | `Up` | Session is established, or an S-BFD reflector is available |

A reflector is stateless: `Up` reports reflector availability, not an established
session with a particular initiator. The interface reports local state only.

During service shutdown, queries can briefly return `AdminDown`. After the engine
finishes, retained objects return `CO_E_OBJNOTCONNECTED` (`0x800401FD`) instead of
a stale state. Once the service process exits, COM can also return a disconnected
RPC error. Release the old object and activate a new one to query a restarted
service; references do not keep the service running after an SCM Stop request.

## Caller privileges and resource access

The installed BFD service runs as `LocalService`. At startup it permanently removes
every process privilege except `SeChangeNotifyPrivilege` and
`SeCreateGlobalPrivilege`, including `SeImpersonatePrivilege`, before accepting
network traffic or COM calls. An authenticated COM caller can be a standard user;
authentication does not establish administrator privileges.
The factory and dispatch objects own only a read-only state observer. State
queries read this shared atomic value, accept no arguments, and reject property
writes. They have no engine, logging, file, registry, or BGP management handles.
Automation metadata is built in memory and is never saved to disk. Each
`GetTypeInfo` request builds it again; the process builds at most 64 per second
and otherwise returns `RPC_E_SERVERCALL_RETRYLATER` (`0x8001010A`), so a caller
looping on metadata requests cannot consume the packet engine's processor time.

The current methods perform no file or registry access on a caller's behalf.
If you add such a method, apply these requirements:

1. Validate and authorize the requested operation before acquiring resources.
2. Call [`CoImpersonateClient`](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-coimpersonateclient)
   on the RPC thread handling the call. Check the result and reject the operation
   if impersonation fails. Never continue using the service's own token.
3. Keep caller-directed resource access synchronous on that same thread. An
   impersonation token does not follow a command sent to the engine or a worker.
   Resource operations require an impersonation-capable client proxy; ordinary
   state queries continue to support `IDENTIFY` clients.
4. Call [`CoRevertToSelf`](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-coreverttoself)
   immediately after resource access. Use a thread-bound scoped guard for cleanup
   on all return paths and check the reversion result before further work.

Service startup reads administrator-controlled configuration and the engine
performs configured monitoring using its LocalService identity. BGP management
runs in the separate LocalSystem [BGP broker](bgp.md#service-identities-and-authorization).
The COM query interface provides no commands to alter those settings or invoke
management operations.

## Implementation and validation

The server uses Microsoft's official
[`windows` crate](https://github.com/microsoft/windows-rs), including generated
`IClassFactory` and `IDispatch` implementations. A dedicated `bfd-com` thread
hosts a multithreaded COM apartment; the packet worker publishes an atomic state
value. COM initialization, class registration, revocation, and uninitialization
stay on that dedicated thread. The service supervisor waits for initialization
before constructing the engine or starting management providers. It waits for
class registration before reporting Running, then joins the COM thread after the
BFD worker and provider cleanup finish. Startup errors also stop and join the
COM thread. No COM interface pointers cross the lifecycle command channel.

COM dispatches incoming MTA calls using its RPC threads; the dedicated thread
does not need a window-message pump. See
[Microsoft's multithreaded apartment documentation](https://learn.microsoft.com/en-us/windows/win32/com/multithreaded-apartments).

The MSI maps the AppID to the service using
[`LocalService`](https://learn.microsoft.com/en-us/windows/win32/com/localservice)
and adds the `RpcSs` service dependency. It writes these `REG_SZ` values under
64-bit `HKLM\SOFTWARE\Classes`:

| Key | Value name | Value |
| --- | --- | --- |
| `AppID\{EBF04871-D193-4CDF-ABBC-DCD7D220224B}` | `LocalService` | `BfdWinService` |
| `CLSID\{4B19A10F-8CD1-46F1-A1EA-6C68ECBA7657}` | `AppID` | `{EBF04871-D193-4CDF-ABBC-DCD7D220224B}` |
| `AppID\bfd-winservice.exe` | `AppID` | `{EBF04871-D193-4CDF-ABBC-DCD7D220224B}` |

`LocalService` matches the SCM service name, so COM activation uses the installed
service. The release installation test checks the registry view, value types,
and mappings after both installation and repair.

The launch ACL grants local launch and activation to SYSTEM and administrators,
and local activation only to authenticated users. The server's
[`CoInitializeSecurity`](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-coinitializesecurity)
access ACL grants local call rights to SYSTEM, administrators, and authenticated
users. Standard machine-wide restrictions still apply.
The dedicated thread calls `CoInitializeSecurity` immediately after `CoInitializeEx`,
before starting management workers or registering its class factory. Startup
fails if process security has already been initialized. A process-wide guard
allows only one security-initialization attempt, including after a failed startup
or after the COM thread exits. The explicit
`RPC_C_AUTHN_LEVEL_PKT_INTEGRITY` setting requires packet integrity rather than
relying on the machine's default authentication setting. The service also sets
`EOAC_DISABLE_AAA` and `EOAC_NO_CUSTOM_MARSHAL`.

The outgoing COM impersonation default is `RPC_C_IMP_LEVEL_IDENTIFY`. The broker
initializes security on its own dedicated COM thread before starting MI; it does
not register the Automation factory. Its access ACL admits only SYSTEM,
administrators, and service accounts (`SU`), so interactive standard users have
no COM access to the LocalSystem broker process. Its local MI destination explicitly requests
[`MI_DestinationOptions_ImpersonationType_Impersonate`](https://learn.microsoft.com/en-us/windows/win32/api/mi/ne-mi-mi_destinationoptions_impersonationtype).
This follows
[Microsoft's WMI guidance](https://learn.microsoft.com/en-us/windows/win32/wmisdk/setting-the-default-process-security-level-using-c-)
so local management providers can access the service's identity without raising
the process-wide default. The state server does not impersonate monitoring
clients. `CoInitializeSecurity`'s `dwImpLevel`
controls outgoing proxies; it does not cap incoming clients' impersonation levels.
Monitoring clients can limit their own proxy to `RPC_C_IMP_LEVEL_IDENTIFY` with
[`CoSetProxyBlanket`](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cosetproxyblanket).

All CLSID, AppID, and ProgID entries are registered in the 64-bit
`HKLM\SOFTWARE\Classes` hive. The MSI installs the executable under
`Program Files\BfdWinService` and applies protected ACLs to the folder, each
installed file, and every COM registration key. SYSTEM owns these objects;
SYSTEM and administrators have full control. The Users group has read/execute
access to the files and folder, and read access to the registry keys. Existing
permissive ACLs and inherited grants are replaced during installation.

The enabled `NT SERVICE\BfdWinService` SID receives read/execute access to those
files and read access to COM registration. The Parameters key permits reads only
by SYSTEM, administrators, and that service SID. The ProgramData log folder grants
Modify to that SID, with no write grant to unrelated LocalService processes.

Release and AddressSanitizer tests cover rejection of caller-supplied file/registry
paths and both property-write forms, Automation errors, all state values,
live transitions, engine shutdown, and cross-process PowerShell/C# queries.
The client tests use an `IDENTIFY` proxy and check that a second security
initialization fails rather than accepting existing process defaults. A separate
process test rejects security initialized first by another library. The tests also
check that the caller can still initialize an STA, registration errors leave the
host usable, and the class is revoked after explicit shutdown or Drop cleanup.
The cross-process test uses a temporary COM class registration with a random
CLSID and does not install the service. The release workflow additionally checks
installed ProgID activation, protected file/registry ACLs after installation and
repair, and registration removal on its disposable Windows runner.
It also reads native MI provider metadata under the COM security defaults,
without changing BGP or network adapter settings.
