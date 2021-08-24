function Get-InjectedThread
{
    <# __CyberCX__
    
    .SYNOPSIS 
    
    Looks for threads that were created as a result of code injection.
    
    .DESCRIPTION
    
    Memory resident malware (fileless malware) often uses a form of memory injection to get code execution. Get-InjectedThread looks at each running thread to determine if it is the result of memory injection.
    
    Common memory injection techniques that *can* be caught using this method include:
    - Classic Injection (OpenProcess, VirtualAllocEx, WriteProcessMemory, CreateRemoteThread)
    - Reflective DLL Injection
    - Memory Module

    NOTE: Nothing in security is a silver bullet. An attacker could modify their tactics to avoid detection using this methodology.
    
    .NOTES

    Author - Jared Atkinson (@jaredcatkinson)
    
    #>

    [CmdletBinding()]
    param
    (

    )

    foreach($proc in (Get-Process))
    {
        if($proc.Id -ne 0 -and $proc.Id -ne 4)
        {
            Write-Verbose -Message "Checking $($proc.Name) [$($proc.Id)] for injection"
            foreach($thread in $proc.Threads)
            {
                Write-Verbose -Message "Thread Id: [$($thread.Id)]"
               
                $hThread = OpenThread -ThreadId $thread.Id -DesiredAccess THREAD_ALL_ACCESS
                if($hThread -ne 0)
                {
                    $BaseAddress = NtQueryInformationThread -ThreadHandle $hThread
                    $hProcess = OpenProcess -ProcessId $proc.Id -DesiredAccess PROCESS_ALL_ACCESS -InheritHandle $false

                    if($hProcess -ne 0)
                    {
                        $memory_basic_info = VirtualQueryEx -ProcessHandle $hProcess -BaseAddress $BaseAddress
                        $AllocatedMemoryProtection = $memory_basic_info.AllocationProtect -as $MemProtection
                        $MemoryProtection = $memory_basic_info.Protect -as $MemProtection
                        $MemoryState = $memory_basic_info.State -as $MemState
                        $MemoryType = $memory_basic_info.Type -as $MemType
                    
                        if($MemoryState -eq $MemState::MEM_COMMIT -and $MemoryType -ne $MemType::MEM_IMAGE)
                        {   
                            if($memory_basic_info.RegionSize.ToUInt64() -ge 0x400)
                            {
                                $buf = ReadProcessMemory -ProcessHandle $hProcess -BaseAddress $BaseAddress -Size 0x400
                            }
                            else
                            {
                                $buf = ReadProcessMemory -ProcessHandle $hProcess -BaseAddress $BaseAddress -Size $memory_basic_info.RegionSize
                            }
                            $proc = Get-WmiObject Win32_Process -Filter "ProcessId = '$($proc.Id)'"
                            $KernelPath = QueryFullProcessImageName -ProcessHandle $hProcess
                            $PathMismatch = $proc.Path.ToLower() -ne $KernelPath.ToLower()

                            # check if thread has unique token
                            try
                            {
                                $hThreadToken = OpenThreadToken -ThreadHandle $hThread -DesiredAccess TOKEN_QUERY
                                
                                if($hThreadToken -ne 0)
                                {
                                    $SID = GetTokenInformation -TokenHandle $hThreadToken -TokenInformationClass 1
                                    $Privs = GetTokenInformation -TokenHandle $hThreadToken -TokenInformationClass 3 
                                    $LogonSession = GetTokenInformation -TokenHandle $hThreadToken -TokenInformationClass 17 
                                    $Integrity = GetTokenInformation -TokenHandle $hThreadToken -TokenInformationClass 25 
                                    $IsUniqueThreadToken = $true
                                }
                            }
                            catch
                            {
                                $hProcessToken = OpenProcessToken -ProcessHandle $hProcess -DesiredAccess TOKEN_QUERY
                                
                                if($hProcessToken -ne 0)
                                {
                                    $SID = GetTokenInformation -TokenHandle $hProcessToken -TokenInformationClass 1
                                    $Privs = GetTokenInformation -TokenHandle $hProcessToken -TokenInformationClass 3 
                                    $LogonSession = GetTokenInformation -TokenHandle $hProcessToken -TokenInformationClass 17 
                                    $Integrity = GetTokenInformation -TokenHandle $hProcessToken -TokenInformationClass 25
                                    $IsUniqueThreadToken = $false
                                }
                            }
                        
                            $ThreadDetail = New-Object PSObject
                            $ThreadDetail | Add-Member -MemberType Noteproperty -Name ProcessName -Value $proc.Name
                            $ThreadDetail | Add-Member -MemberType Noteproperty -Name ProcessId -Value $proc.ProcessId
                            $ThreadDetail | Add-Member -MemberType Noteproperty -Name Path -Value $proc.Path
                            $ThreadDetail | Add-Member -MemberType Noteproperty -Name KernelPath -Value $KernelPath
                            $ThreadDetail | Add-Member -MemberType Noteproperty -Name CommandLine -Value $proc.CommandLine
                            $ThreadDetail | Add-Member -MemberType Noteproperty -Name PathMismatch -Value $PathMismatch
                            $ThreadDetail | Add-Member -MemberType Noteproperty -Name ThreadId -Value $thread.Id
                            $ThreadDetail | Add-Member -MemberType NoteProperty -Name ThreadStartTime -Value $thread.StartTime
                            $ThreadDetail | Add-Member -MemberType Noteproperty -Name AllocatedMemoryProtection -Value $AllocatedMemoryProtection
                            $ThreadDetail | Add-Member -MemberType Noteproperty -Name MemoryProtection -Value $MemoryProtection
                            $ThreadDetail | Add-Member -MemberType Noteproperty -Name MemoryState -Value $MemoryState
                            $ThreadDetail | Add-Member -MemberType Noteproperty -Name MemoryType -Value $MemoryType
                            $ThreadDetail | Add-Member -MemberType Noteproperty -Name BasePriority -Value $thread.BasePriority
                            $ThreadDetail | Add-Member -MemberType Noteproperty -Name IsUniqueThreadToken -Value $IsUniqueThreadToken
                            $ThreadDetail | Add-Member -MemberType Noteproperty -Name Integrity -Value $Integrity
                            $ThreadDetail | Add-Member -MemberType Noteproperty -Name Privilege -Value $Privs
                            $ThreadDetail | Add-Member -MemberType Noteproperty -Name LogonId -Value $LogonSession.LogonId
                            $ThreadDetail | Add-Member -MemberType Noteproperty -Name SecurityIdentifier -Value $SID
                            $ThreadDetail | Add-Member -MemberType Noteproperty -Name UserName -Value "$($LogonSession.Domain)\$($LogonSession.UserName)"
                            $ThreadDetail | Add-Member -MemberType Noteproperty -Name LogonSessionStartTime -Value $LogonSession.StartTime
                            $ThreadDetail | Add-Member -MemberType Noteproperty -Name LogonType -Value $LogonSession.LogonType
                            $ThreadDetail | Add-Member -MemberType Noteproperty -Name AuthenticationPackage -Value $LogonSession.AuthenticationPackage
                            $ThreadDetail | Add-Member -MemberType Noteproperty -Name BaseAddress -Value $BaseAddress
                            $ThreadDetail | Add-Member -MemberType Noteproperty -Name Size -Value $memory_basic_info.RegionSize
                            $ThreadDetail | Add-Member -MemberType Noteproperty -Name Bytes -Value $buf
                            Write-Output $ThreadDetail
                        }
                        CloseHandle($hProcess)
                    }
                }
                CloseHandle($hThread)
            }
        }
    }
}

function Get-LogonSession
{
    <# __CyberCX__
    .NOTES

    Author: Lee Christensen (@tifkin_)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
    #>
    param
    (
        [Parameter(Mandatory = $true)]
        [UInt32]
        $LogonId
    )
    
    $LogonMap = @{}
    Get-WmiObject Win32_LoggedOnUser  | %{
    
        $Identity = $_.Antecedent | Select-String 'Domain="(.*)",Name="(.*)"'
        $LogonSession = $_.Dependent | Select-String 'LogonId="(\d+)"'

        $LogonMap[$LogonSession.Matches[0].Groups[1].Value] = New-Object PSObject -Property @{
            Domain = $Identity.Matches[0].Groups[1].Value
            UserName = $Identity.Matches[0].Groups[2].Value
        }
    }

    Get-WmiObject Win32_LogonSession -Filter "LogonId = `"$($LogonId)`"" | %{
        $LogonType = $Null
        switch($_.LogonType) {
            $null {$LogonType = 'None'}
            0 { $LogonType = 'System' }
            2 { $LogonType = 'Interactive' }
            3 { $LogonType = 'Network' }
            4 { $LogonType = 'Batch' }
            5 { $LogonType = 'Service' }
            6 { $LogonType = 'Proxy' }
            7 { $LogonType = 'Unlock' }
            8 { $LogonType = 'NetworkCleartext' }
            9 { $LogonType = 'NewCredentials' }
            10 { $LogonType = 'RemoteInteractive' }
            11 { $LogonType = 'CachedInteractive' }
            12 { $LogonType = 'CachedRemoteInteractive' }
            13 { $LogonType = 'CachedUnlock' }
            default { $LogonType = $_.LogonType}
        }

        New-Object PSObject -Property @{
            UserName = $LogonMap[$_.LogonId].UserName
            Domain = $LogonMap[$_.LogonId].Domain
            LogonId = $_.LogonId
            LogonType = $LogonType
            AuthenticationPackage = $_.AuthenticationPackage
            Caption = $_.Caption
            Description = $_.Description
            InstallDate = $_.InstallDate
            Name = $_.Name
            StartTime = $_.ConvertToDateTime($_.StartTime)
        }
    }
}

#region PSReflect

function New-InMemoryModule
{
<# __CyberCX__
.SYNOPSIS

Creates an in-memory assembly and module

Author: Matthew Graeber (@_matti_f_e_station)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

#>

    Param
    (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )

    $AppDomain = [Reflection.Assembly].Assembly.GetType('System.AppDomain').GetProperty('CurrentDomain').GetValue($null, @())
    $LoadedAssemblies = $AppDomain.GetAssemblies()

    foreach ($Assembly in $LoadedAssemblies) {
        if ($Assembly.FullName -and ($Assembly.FullName.Split(',')[0] -eq $ModuleName)) {
            return $Assembly
        }
    }

    $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
    $Domain = $AppDomain
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, 'Run')
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)

    return $ModuleBuilder
}

# A helper function used to reduce typing while defining function
# prototypes for Add-Win32Type.
function func
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $DllName,

        [Parameter(Position = 1, Mandatory = $True)]
        [string]
        $FunctionName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $ReturnType,

        [Parameter(Position = 3)]
        [Type[]]
        $ParameterTypes,

        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention,

        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        $Charset,

        [String]
        $EntryPoint,

        [Switch]
        $SetLastError
    )

    $Properties = @{
        DllName = $DllName
        FunctionName = $FunctionName
        ReturnType = $ReturnType
    }

    if ($ParameterTypes) { $Properties['ParameterTypes'] = $ParameterTypes }
    if ($NativeCallingConvention) { $Properties['NativeCallingConvention'] = $NativeCallingConvention }
    if ($Charset) { $Properties['Charset'] = $Charset }
    if ($SetLastError) { $Properties['SetLastError'] = $SetLastError }
    if ($EntryPoint) { $Properties['EntryPoint'] = $EntryPoint }

    New-Object PSObject -Property $Properties
}

function Add-Win32Type
{
<# __CyberCX__
.SYNOPSIS

Creates a .NET type for an unmanaged Win32 function.

Author: Matthew Graeber (@___mattif___estation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: func
 
#>

    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $DllName,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $FunctionName,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [String]
        $EntryPoint,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Type]
        $ReturnType,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Type[]]
        $ParameterTypes,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CharSet]
        $Charset = [Runtime.InteropServices.CharSet]::Auto,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Switch]
        $SetLastError,

        [Parameter(Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [ValidateNotNull()]
        [String]
        $Namespace = ''
    )

    BEGIN
    {
        $TypeHash = @{}
    }

    PROCESS
    {
        if ($Module -is [Reflection.Assembly])
        {
            if ($Namespace)
            {
                $TypeHash[$DllName] = $Module.GetType("$Namespace.$DllName")
            }
            else
            {
                $TypeHash[$DllName] = $Module.GetType($DllName)
            }
        }
        else
        {
            # Define one type for each DLL
            if (!$TypeHash.ContainsKey($DllName))
            {
                if ($Namespace)
                {
                    $TypeHash[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
                }
                else
                {
                    $TypeHash[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
                }
            }

            $Method = $TypeHash[$DllName].DefineMethod(
                $FunctionName,
                'Public,Static,PinvokeImpl',
                $ReturnType,
                $ParameterTypes)

            # Make each ByRef parameter an Out parameter
            $i = 1
            foreach($Parameter in $ParameterTypes)
            {
                if ($Parameter.IsByRef)
                {
                    [void] $Method.DefineParameter($i, 'Out', $null)
                }

                $i++
            }

            $DllImport = [Runtime.InteropServices.DllImportAttribute]
            $SetLastErrorField = $DllImport.GetField('SetLastError')
            $CallingConventionField = $DllImport.GetField('CallingConvention')
            $CharsetField = $DllImport.GetField('CharSet')
            $EntryPointField = $DllImport.GetField('EntryPoint')
            if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }

            if ($PSBoundParameters['EntryPoint']) { $ExportedFuncName = $EntryPoint } else { $ExportedFuncName = $FunctionName }

            # Equivalent to C# version of [DllImport(DllName)]
            $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
                $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                [Reflection.FieldInfo[]] @($SetLastErrorField,
                                           $CallingConventionField,
                                           $CharsetField,
                                           $EntryPointField),
                [Object[]] @($SLEValue,
                             ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention),
                             ([Runtime.InteropServices.CharSet] $Charset),
                             $ExportedFuncName))

            $Method.SetCustomAttribute($DllImportAttribute)
        }
    }

    END
    {
        if ($Module -is [Reflection.Assembly])
        {
            return $TypeHash
        }

        $ReturnTypes = @{}

        foreach ($Key in $TypeHash.Keys)
        {
            $Type = $TypeHash[$Key].CreateType()
            
            $ReturnTypes[$Key] = $Type
        }

        return $ReturnTypes
    }
}

function psenum
{
<# __CyberCX__
.SYNOPSIS

Creates an in-memory enumeration for use in your PowerShell session.

Author: Matthew Graeber (@__mattif__estation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
#>

    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $Type,

        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $EnumElements,

        [Switch]
        $Bitfield
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    $EnumType = $Type -as [Type]

    $EnumBuilder = $Module.DefineEnum($FullName, 'Public', $EnumType)

    if ($Bitfield)
    {
        $FlagsConstructor = [FlagsAttribute].GetConstructor(@())
        $FlagsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($FlagsConstructor, @())
        $EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
    }

    foreach ($Key in $EnumElements.Keys)
    {
        # Apply the specified enum type to each element
        $null = $EnumBuilder.DefineLiteral($Key, $EnumElements[$Key] -as $EnumType)
    }

    $EnumBuilder.CreateType()
}

# A helper function used to reduce typing while defining struct
# fields.
function field
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [UInt16]
        $Position,
        
        [Parameter(Position = 1, Mandatory = $True)]
        [Type]
        $Type,
        
        [Parameter(Position = 2)]
        [UInt16]
        $Offset,
        
        [Object[]]
        $MarshalAs
    )

    @{
        Position = $Position
        Type = $Type -as [Type]
        Offset = $Offset
        MarshalAs = $MarshalAs
    }
}

function struct
{
<# __CyberCX__
.SYNOPSIS

Creates an in-memory struct for use in your PowerShell session.

Author: Matthew Graeber (@__matti__festation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: field
#>

    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 2, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $StructFields,

        [Reflection.Emit.PackingSize]
        $PackingSize = [Reflection.Emit.PackingSize]::Unspecified,

        [Switch]
        $ExplicitLayout
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    [Reflection.TypeAttributes] $StructAttributes = 'AnsiClass,
        Class,
        Public,
        Sealed,
        BeforeFieldInit'

    if ($ExplicitLayout)
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
    }

    $StructBuilder = $Module.DefineType($FullName, $StructAttributes, [ValueType], $PackingSize)
    $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))

    $Fields = New-Object Hashtable[]($StructFields.Count)

    # Sort each field according to the orders specified
    # Unfortunately, PSv2 doesn't have the luxury of the
    # hashtable [Ordered] accelerator.
    foreach ($Field in $StructFields.Keys)
    {
        $Index = $StructFields[$Field]['Position']
        $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field]}
    }

    foreach ($Field in $Fields)
    {
        $FieldName = $Field['FieldName']
        $FieldProp = $Field['Properties']

        $Offset = $FieldProp['Offset']
        $Type = $FieldProp['Type']
        $MarshalAs = $FieldProp['MarshalAs']

        $NewField = $StructBuilder.DefineField($FieldName, $Type, 'Public')

        if ($MarshalAs)
        {
            $UnmanagedType = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
            if ($MarshalAs[1])
            {
                $Size = $MarshalAs[1]
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo,
                    $UnmanagedType, $SizeConst, @($Size))
            }
            else
            {
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, [Object[]] @($UnmanagedType))
            }
            
            $NewField.SetCustomAttribute($AttribBuilder)
        }

        if ($ExplicitLayout) { $NewField.SetOffset($Offset) }
    }

    # Make the struct aware of its own size.
    # No more having to call [Runtime.InteropServices.Marshal]::SizeOf!
    $SizeMethod = $StructBuilder.DefineMethod('GetSize',
        'Public, Static',
        [Int],
        [Type[]] @())
    $ILGenerator = $SizeMethod.GetILGenerator()
    # Thanks for the help, Jason Shirk!
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)

    # Allow for explicit casting from an IntPtr
    # No more having to call [Runtime.InteropServices.Marshal]::PtrToStructure!
    $ImplicitConverter = $StructBuilder.DefineMethod('op_Implicit',
        'PrivateScope, Public, Static, HideBySig, SpecialName',
        $StructBuilder,
        [Type[]] @([IntPtr]))
    $ILGenerator2 = $ImplicitConverter.GetILGenerator()
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)

    $StructBuilder.CreateType()
}

#endregion PSReflect

#region PSReflect Definitions (Thread)

$Module = New-InMemoryModule -ModuleName GetInjectedThread

#region Constants
$UNTRUSTED_MANDATORY_LEVEL = "S-1-16-0"
$LOW_MANDATORY_LEVEL = "S-1-16-4096"
$MEDIUM_MANDATORY_LEVEL = "S-1-16-8192"
$MEDIUM_PLUS_MANDATORY_LEVEL = "S-1-16-8448"
$HIGH_MANDATORY_LEVEL = "S-1-16-12288"
$SYSTEM_MANDATORY_LEVEL = "S-1-16-16384"
$PROTECTED_PROCESS_MANDATORY_LEVEL = "S-1-16-20480"
$SECURE_PROCESS_MANDATORY_LEVEL = "S-1-16-28672"
#endregion Constants

#region Enums
$LuidAttributes = psenum $Module LuidAttributes UInt32 @{
    DISABLED                            =   '0x00000000'
    SE_PRIVILEGE_ENABLED_BY_DEFAULT     =   '0x00000001'
    SE_PRIVILEGE_ENABLED                =   '0x00000002'
    SE_PRIVILEGE_REMOVED                =   '0x00000004'
    SE_PRIVILEGE_USED_FOR_ACCESS        =   '0x80000000'
} -Bitfield

$MemProtection = psenum $Module MemProtection UInt32 @{
    PAGE_EXECUTE = 0x10
    PAGE_EXECUTE_READ = 0x20
    PAGE_EXECUTE_READWRITE = 0x40
    PAGE_EXECUTE_WRITECOPY = 0x80
    PAGE_NOACCESS = 0x01
    PAGE_READONLY = 0x02
    PAGE_READWRITE = 0x04
    PAGE_WRITECOPY = 0x08
    PAGE_TARGETS_INVALID = 0x40000000
    PAGE_TARGETS_NO_UPDATE = 0x40000000
    PAGE_GUARD = 0x100
    PAGE_NOCACHE = 0x200
    PAGE_WRITECOMBINE = 0x400
} -Bitfield

$MemState = psenum $Module MemState UInt32 @{
    MEM_COMMIT = 0x1000
    MEM_RESERVE = 0x2000
    MEM_FREE = 0x10000
}

$MemType = psenum $Module MemType UInt32 @{
    MEM_PRIVATE = 0x20000
    MEM_MAPPED = 0x40000
    MEM_IMAGE = 0x1000000
}

$PROCESS_ACCESS = psenum $Module PROCESS_ACCESS UInt32 @{
    PROCESS_TERMINATE                 = 0x00000001
    PROCESS_CREATE_THREAD             = 0x00000002
    PROCESS_VM_OPERATION              = 0x00000008
    PROCESS_VM_READ                   = 0x00000010
    PROCESS_VM_WRITE                  = 0x00000020
    PROCESS_DUP_HANDLE                = 0x00000040
    PROCESS_CREATE_PROCESS            = 0x00000080
    PROCESS_SET_QUOTA                 = 0x00000100
    PROCESS_SET_INFORMATION           = 0x00000200
    PROCESS_QUERY_INFORMATION         = 0x00000400
    PROCESS_SUSPEND_RESUME            = 0x00000800
    PROCESS_QUERY_LIMITED_INFORMATION = 0x00001000
    DELETE                            = 0x00010000
    READ_CONTROL                      = 0x00020000
    WRITE_DAC                         = 0x00040000
    WRITE_OWNER                       = 0x00080000
    SYNCHRONIZE                       = 0x00100000
    PROCESS_ALL_ACCESS                = 0x001f1ffb
} -Bitfield

$SecurityEntity = psenum $Module SecurityEntity UInt32 @{
    SeCreateTokenPrivilege              =   1
    SeAssignPrimaryTokenPrivilege       =   2
    SeLockMemoryPrivilege               =   3
    SeIncreaseQuotaPrivilege            =   4
    SeUnsolicitedInputPrivilege         =   5
    SeMachineAccountPrivilege           =   6
    SeTcbPrivilege                      =   7
    SeSecurityPrivilege                 =   8
    SeTakeOwnershipPrivilege            =   9
    SeLoadDriverPrivilege               =   10
    SeSystemProfilePrivilege            =   11
    SeSystemtimePrivilege               =   12
    SeProfileSingleProcessPrivilege     =   13
    SeIncreaseBasePriorityPrivilege     =   14
    SeCreatePagefilePrivilege           =   15
    SeCreatePermanentPrivilege          =   16
    SeBackupPrivilege                   =   17
    SeRestorePrivilege                  =   18
    SeShutdownPrivilege                 =   19
    SeDebugPrivilege                    =   20
    SeAuditPrivilege                    =   21
    SeSystemEnvironmentPrivilege        =   22
    SeChangeNotifyPrivilege             =   23
    SeRemoteShutdownPrivilege           =   24
    SeUndockPrivilege                   =   25
    SeSyncAgentPrivilege                =   26
    SeEnableDelegationPrivilege         =   27
    SeManageVolumePrivilege             =   28
    SeImpersonatePrivilege              =   29
    SeCreateGlobalPrivilege             =   30
    SeTrustedCredManAccessPrivilege     =   31
    SeRelabelPrivilege                  =   32
    SeIncreaseWorkingSetPrivilege       =   33
    SeTimeZonePrivilege                 =   34
    SeCreateSymbolicLinkPrivilege       =   35
}

$SidNameUser = psenum $Module SID_NAME_USE UInt32 @{
  SidTypeUser                            = 1
  SidTypeGroup                           = 2
  SidTypeDomain                          = 3
  SidTypeAlias                           = 4
  SidTypeWellKnownGroup                  = 5
  SidTypeDeletedAccount                  = 6
  SidTypeInvalid                         = 7
  SidTypeUnknown                         = 8
  SidTypeComputer                        = 9
}

$THREAD_ACCESS = psenum $Module THREAD_ACCESS UInt32 @{
    THREAD_TERMINATE                 = 0x00000001
    THREAD_SUSPEND_RESUME            = 0x00000002
    THREAD_GET_CONTEXT               = 0x00000008
    THREAD_SET_CONTEXT               = 0x00000010
    THREAD_SET_INFORMATION           = 0x00000020
    THREAD_QUERY_INFORMATION         = 0x00000040
    THREAD_SET_THREAD_TOKEN          = 0x00000080
    THREAD_IMPERSONATE               = 0x00000100
    THREAD_DIRECT_IMPERSONATION      = 0x00000200
    THREAD_SET_LIMITED_INFORMATION   = 0x00000400
    THREAD_QUERY_LIMITED_INFORMATION = 0x00000800
    DELETE                           = 0x00010000
    READ_CONTROL                     = 0x00020000
    WRITE_DAC                        = 0x00040000
    WRITE_OWNER                      = 0x00080000
    SYNCHRONIZE                      = 0x00100000
    THREAD_ALL_ACCESS                = 0x001f0ffb
} -Bitfield

$TOKEN_ACCESS = psenum $Module TOKEN_ACCESS UInt32 @{
    TOKEN_DUPLICATE          = 0x00000002
    TOKEN_IMPERSONATE        = 0x00000004
    TOKEN_QUERY              = 0x00000008
    TOKEN_QUERY_SOURCE       = 0x00000010
    TOKEN_ADJUST_PRIVILEGES  = 0x00000020
    TOKEN_ADJUST_GROUPS      = 0x00000040
    TOKEN_ADJUST_DEFAULT     = 0x00000080
    TOKEN_ADJUST_SESSIONID   = 0x00000100
    DELETE                   = 0x00010000
    READ_CONTROL             = 0x00020000
    WRITE_DAC                = 0x00040000
    WRITE_OWNER              = 0x00080000
    SYNCHRONIZE              = 0x00100000
    STANDARD_RIGHTS_REQUIRED = 0x000F0000
    TOKEN_ALL_ACCESS         = 0x001f01ff
} -Bitfield

$TokenInformationClass = psenum $Module TOKEN_INFORMATION_CLASS UInt16 @{ 
  TokenUser                             = 1
  TokenGroups                           = 2
  TokenPrivileges                       = 3
  TokenOwner                            = 4
  TokenPrimaryGroup                     = 5
  TokenDefaultDacl                      = 6
  TokenSource                           = 7
  TokenType                             = 8
  TokenImpersonationLevel               = 9
  TokenStatistics                       = 10
  TokenRestrictedSids                   = 11
  TokenSessionId                        = 12
  TokenGroupsAndPrivileges              = 13
  TokenSessionReference                 = 14
  TokenSandBoxInert                     = 15
  TokenAuditPolicy                      = 16
  TokenOrigin                           = 17
  TokenElevationType                    = 18
  TokenLinkedToken                      = 19
  TokenElevation                        = 20
  TokenHasRestrictions                  = 21
  TokenAccessInformation                = 22
  TokenVirtualizationAllowed            = 23
  TokenVirtualizationEnabled            = 24
  TokenIntegrityLevel                   = 25
  TokenUIAccess                         = 26
  TokenMandatoryPolicy                  = 27
  TokenLogonSid                         = 28
  TokenIsAppContainer                   = 29
  TokenCapabilities                     = 30
  TokenAppContainerSid                  = 31
  TokenAppContainerNumber               = 32
  TokenUserClaimAttributes              = 33
  TokenDeviceClaimAttributes            = 34
  TokenRestrictedUserClaimAttributes    = 35
  TokenRestrictedDeviceClaimAttributes  = 36
  TokenDeviceGroups                     = 37
  TokenRestrictedDeviceGroups           = 38
  TokenSecurityAttributes               = 39
  TokenIsRestricted                     = 40
  MaxTokenInfoClass                     = 41
}
#endregion Enums

#region Structs
$LUID = struct $Module Luid @{
    LowPart         =   field 0 $SecurityEntity
    HighPart        =   field 1 Int32
}

$LUID_AND_ATTRIBUTES = struct $Module LuidAndAttributes @{
    Luid            =   field 0 $LUID
    Attributes      =   field 1 UInt32
}

$MEMORYBASICINFORMATION = struct $Module MEMORY_BASIC_INFORMATION @{
  BaseAddress       = field 0 UIntPtr
  AllocationBase    = field 1 UIntPtr
  AllocationProtect = field 2 UInt32
  RegionSize        = field 3 UIntPtr
  State             = field 4 UInt32
  Protect           = field 5 UInt32
  Type              = field 6 UInt32
}

$SID_AND_ATTRIBUTES = struct $Module SidAndAttributes @{
    Sid             =   field 0 IntPtr
    Attributes      =   field 1 UInt32
}

$TOKEN_MANDATORY_LABEL = struct $Module TokenMandatoryLabel @{
    Label           = field 0 $SID_AND_ATTRIBUTES;
}

$TOKEN_ORIGIN = struct $Module TokenOrigin @{
  OriginatingLogonSession = field 0 UInt64
}

$TOKEN_PRIVILEGES = struct $Module TokenPrivileges @{
    PrivilegeCount  = field 0 UInt32
    Privileges      = field 1 $LUID_AND_ATTRIBUTES.MakeArrayType() -MarshalAs @('ByValArray', 50)
}

$TOKEN_USER = struct $Module TOKEN_USER @{
    User            = field 0 $SID_AND_ATTRIBUTES
}
#endregion Structs

#region Function Definitions
$FunctionDefinitions = @(
    (func kernel32 CloseHandle ([bool]) @(
        [IntPtr]                                  #_In_ HANDLE hObject
    ) -SetLastError),
    
    (func advapi32 ConvertSidToStringSid ([bool]) @(
        [IntPtr]                                  #_In_  PSID   Sid,
        [IntPtr].MakeByRefType()                  #_Out_ LPTSTR *StringSid
    ) -SetLastError),
    
    (func advapi32 GetTokenInformation ([bool]) @(
      [IntPtr],                                   #_In_      HANDLE                  TokenHandle
      [Int32],                                    #_In_      TOKEN_INFORMATION_CLASS TokenInformationClass
      [IntPtr],                                   #_Out_opt_ LPVOID                  TokenInformation
      [UInt32],                                   #_In_      DWORD                   TokenInformationLength
      [UInt32].MakeByRefType()                    #_Out_     PDWORD                  ReturnLength
    ) -SetLastError),

    (func ntdll NtQueryInformationThread ([UInt32]) @(
        [IntPtr],                                 #_In_      HANDLE          ThreadHandle,
        [Int32],                                  #_In_      THREADINFOCLASS ThreadInformationClass,
        [IntPtr],                                 #_Inout_   PVOID           ThreadInformation,
        [Int32],                                  #_In_      ULONG           ThreadInformationLength,
        [IntPtr]                                  #_Out_opt_ PULONG          ReturnLength
    )),

    (func kernel32 OpenProcess ([IntPtr]) @(
        [UInt32],                                 #_In_ DWORD dwDesiredAccess,
        [bool],                                   #_In_ BOOL  bInheritHandle,
        [UInt32]                                  #_In_ DWORD dwProcessId
    ) -SetLastError),
    
    (func advapi32 OpenProcessToken ([bool]) @(
      [IntPtr],                                   #_In_  HANDLE  ProcessHandle
      [UInt32],                                   #_In_  DWORD   DesiredAccess
      [IntPtr].MakeByRefType()                    #_Out_ PHANDLE TokenHandle
    ) -SetLastError),

    (func kernel32 OpenThread ([IntPtr]) @(
        [UInt32],                                  #_In_ DWORD dwDesiredAccess,
        [bool],                                    #_In_ BOOL  bInheritHandle,
        [UInt32]                                   #_In_ DWORD dwThreadId
    ) -SetLastError),
    
    (func advapi32 OpenThreadToken ([bool]) @(
      [IntPtr],                                    #_In_  HANDLE  ThreadHandle
      [UInt32],                                    #_In_  DWORD   DesiredAccess
      [bool],                                      #_In_  BOOL    OpenAsSelf
      [IntPtr].MakeByRefType()                     #_Out_ PHANDLE TokenHandle
    ) -SetLastError),
    
    (func kernel32 QueryFullProcessImageName ([bool]) @(
      [IntPtr]                                     #_In_    HANDLE hProcess
      [UInt32]                                     #_In_    DWORD  dwFlags,
      [System.Text.StringBuilder]                  #_Out_   LPTSTR lpExeName,
      [UInt32].MakeByRefType()                     #_Inout_ PDWORD lpdwSize
    ) -SetLastError),
    
    (func kernel32 ReadProcessMemory ([Bool]) @(
        [IntPtr],                                  # _In_ HANDLE hProcess
        [IntPtr],                                  # _In_ LPCVOID lpBaseAddress
        [Byte[]],                                  # _Out_ LPVOID  lpBuffer
        [Int],                                     # _In_ SIZE_T nSize
        [Int].MakeByRefType()                      # _Out_ SIZE_T *lpNumberOfBytesRead
    ) -SetLastError),
    
    (func kernel32 VirtualQueryEx ([Int32]) @(
        [IntPtr],                                  #_In_     HANDLE                    hProcess,
        [IntPtr],                                  #_In_opt_ LPCVOID                   lpAddress,
        $MEMORYBASICINFORMATION.MakeByRefType(),   #_Out_    PMEMORY_BASIC_INFORMATION lpBuffer,
        [UInt32]                                   #_In_     SIZE_T                    dwLength
    ) -SetLastError)
)

$Types = $FunctionDefinitions | Add-Win32Type -Module $Module -Namespace 'Win32SysInfo'
$Kernel32 = $Types['kernel32']
$Ntdll = $Types['ntdll']
$Advapi32 = $Types['advapi32']
#endregion Function Definitions

#endregion PSReflect Definitions (Thread)

#region Win32 API Abstractions

function CloseHandle
{
    <# __CyberCX__
    .SYNOPSIS

    Closes an open object handle.
    Author - Jared Atkinson (@__jared__catkinson)
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $Handle    
    )
    
    <#
    (func kernel32 CloseHandle ([bool]) @(
        [IntPtr]                                  #_In_ HANDLE hObject
    ) -SetLastError)
    #>
    
    $Success = $Kernel32::CloseHandle($Handle); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if(-not $Success) 
    {
        Write-Debug "Close Handle Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
}

function ConvertSidToStringSid
{
    <# __CyberCX__
    .SYNOPSIS

    The ConvertSidToStringSid function converts a security identifier (SID) to a string format suitable for display, storage, or transmission.
    Author - Jared Atkinson (@__jaredc__atkinson)

    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $SidPointer    
    )
    
    <#
    (func advapi32 ConvertSidToStringSid ([bool]) @(
        [IntPtr]                                  #_In_  PSID   Sid,
        [IntPtr].MakeByRefType()                  #_Out_ LPTSTR *StringSid
    ) -SetLastError)
    #>
    
    $StringPtr = [IntPtr]::Zero
    $Success = $Advapi32::ConvertSidToStringSid($SidPointer, [ref]$StringPtr); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if(-not $Success) 
    {
        Write-Debug "ConvertSidToStringSid Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    
    Write-Output ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto($StringPtr))
}

function GetTokenInformation
{
    <# __CyberCX__
    Author - Jared Atkinson (@__jaredc__atkinson)
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $TokenHandle,
        
        [Parameter(Mandatory = $true)]
        $TokenInformationClass 
    )
    
    <# 
    (func advapi32 GetTokenInformation ([bool]) @(
      [IntPtr],                                   #_In_      HANDLE                  TokenHandle
      [Int32],                                    #_In_      TOKEN_INFORMATION_CLASS TokenInformationClass
      [IntPtr],                                   #_Out_opt_ LPVOID                  TokenInformation
      [UInt32],                                   #_In_      DWORD                   TokenInformationLength
      [UInt32].MakeByRefType()                    #_Out_     PDWORD                  ReturnLength
    ) -SetLastError)
    #>
    
    # initial query to determine the necessary buffer size
    $TokenPtrSize = 0
    $Success = $Advapi32::GetTokenInformation($TokenHandle, $TokenInformationClass, 0, $TokenPtrSize, [ref]$TokenPtrSize)
    [IntPtr]$TokenPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPtrSize)
    
    # retrieve the proper buffer value
    $Success = $Advapi32::GetTokenInformation($TokenHandle, $TokenInformationClass, $TokenPtr, $TokenPtrSize, [ref]$TokenPtrSize); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    
    if($Success)
    {
        switch($TokenInformationClass)
        {
            1 # TokenUser
            {    
                $TokenUser = $TokenPtr -as $TOKEN_USER
                ConvertSidToStringSid -SidPointer $TokenUser.User.Sid
            }
            3 # TokenPrivilege
            {
                # query the process token with the TOKEN_INFORMATION_CLASS = 3 enum to retrieve a TOKEN_PRIVILEGES structure
                $TokenPrivileges = $TokenPtr -as $TOKEN_PRIVILEGES
                
                $sb = New-Object System.Text.StringBuilder
                
                for($i=0; $i -lt $TokenPrivileges.PrivilegeCount; $i++) 
                {
                    if((($TokenPrivileges.Privileges[$i].Attributes -as $LuidAttributes) -band $LuidAttributes::SE_PRIVILEGE_ENABLED) -eq $LuidAttributes::SE_PRIVILEGE_ENABLED)
                    {
                       $sb.Append(", $($TokenPrivileges.Privileges[$i].Luid.LowPart.ToString())") | Out-Null  
                    }
                }
                Write-Output $sb.ToString().TrimStart(', ')
            }
            17 # TokenOrigin
            {
                $TokenOrigin = $TokenPtr -as $LUID
                Write-Output (Get-LogonSession -LogonId $TokenOrigin.LowPart)
            }
            22 # TokenAccessInformation
            {
            
            }
            25 # TokenIntegrityLevel
            {
                $TokenIntegrity = $TokenPtr -as $TOKEN_MANDATORY_LABEL
                switch(ConvertSidToStringSid -SidPointer $TokenIntegrity.Label.Sid)
                {
                    $UNTRUSTED_MANDATORY_LEVEL
                    {
                        Write-Output "UNTRUSTED_MANDATORY_LEVEL"
                    }
                    $LOW_MANDATORY_LEVEL
                    {
                        Write-Output "LOW_MANDATORY_LEVEL"
                    }
                    $MEDIUM_MANDATORY_LEVEL
                    {
                        Write-Output "MEDIUM_MANDATORY_LEVEL"
                    }
                    $MEDIUM_PLUS_MANDATORY_LEVEL
                    {
                        Write-Output "MEDIUM_PLUS_MANDATORY_LEVEL"
                    }
                    $HIGH_MANDATORY_LEVEL
                    {
                        Write-Output "HIGH_MANDATORY_LEVEL"
                    }
                    $SYSTEM_MANDATORY_LEVEL
                    {
                        Write-Output "SYSTEM_MANDATORY_LEVEL"
                    }
                    $PROTECTED_PROCESS_MANDATORY_LEVEL
                    {
                        Write-Output "PROTECTED_PROCESS_MANDATORY_LEVEL"
                    }
                    $SECURE_PROCESS_MANDATORY_LEVEL
                    {
                        Write-Output "SECURE_PROCESS_MANDATORY_LEVEL"
                    }
                }
            }
        }
    }
    else
    {
        Write-Debug "GetTokenInformation Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }        
    try
    {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPtr)
    }
    catch
    {
    
    }
}

function NtQueryInformationThread
{
    <# __CyberCX__
    .SYNOPSIS

    Retrieves information about the specified thread.
    Author - Jared Atkinson (@jaredcatkinson)
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $ThreadHandle  
    )
    
    <#
    (func ntdll NtQueryInformationThread ([Int32]) @(
        [IntPtr],                                 #_In_      HANDLE          ThreadHandle,
        [Int32],                                  #_In_      THREADINFOCLASS ThreadInformationClass,
        [IntPtr],                                 #_Inout_   PVOID           ThreadInformation,
        [Int32],                                  #_In_      ULONG           ThreadInformationLength,
        [IntPtr]                                  #_Out_opt_ PULONG          ReturnLength
    ))
    #>
    
    $buf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([IntPtr]::Size)

    $Success = $Ntdll::NtQueryInformationThread($ThreadHandle, 9, $buf, [IntPtr]::Size, [IntPtr]::Zero); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if(-not $Success) 
    {
        Write-Debug "NtQueryInformationThread Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    
    Write-Output ([System.Runtime.InteropServices.Marshal]::ReadIntPtr($buf))
}

function OpenProcess
{
    <# __CyberCX__
    .SYNOPSIS

    Opens an existing local process object.    
    Author: Jared Atkinson (@__jaredc__atkinson)
    License: BSD 3-Clause
    Required Dependencies: PSReflect
    Optional Dependencies: PROCESS_ACCESS
    #>

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [UInt32]
        $ProcessId,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('PROCESS_TERMINATE','PROCESS_CREATE_THREAD','PROCESS_VM_OPERATION','PROCESS_VM_READ','PROCESS_VM_WRITE','PROCESS_DUP_HANDLE','PROCESS_CREATE_PROCESS','PROCESS_SET_QUOTA','PROCESS_SET_INFORMATION','PROCESS_QUERY_INFORMATION','PROCESS_SUSPEND_RESUME','PROCESS_QUERY_LIMITED_INFORMATION','DELETE','READ_CONTROL','WRITE_DAC','WRITE_OWNER','SYNCHRONIZE','PROCESS_ALL_ACCESS')]
        [string[]]
        $DesiredAccess,
        
        [Parameter()]
        [bool]
        $InheritHandle = $false
    )

    # Calculate Desired Access Value
    $dwDesiredAccess = 0

    foreach($val in $DesiredAccess)
    {
        $dwDesiredAccess = $dwDesiredAccess -bor $PROCESS_ACCESS::$val
    }

    $hProcess = $Kernel32::OpenProcess($dwDesiredAccess, $InheritHandle, $ProcessId); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if($hProcess -eq 0) 
    {
        #throw "OpenProcess Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    
    Write-Output $hProcess
}

function OpenProcessToken
{ 
    <# __CyberCX__
    .SYNOPSIS

    The OpenProcessToken function opens the access token associated with a process.
    Author: Jared Atkinson (@jaredc__atkinson)
    License: BSD 3-Clause
    Required Dependencies: PSReflect
    Optional Dependencies: TOKEN_ACCESS (Enumeration)
    #>

    [OutputType([IntPtr])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $ProcessHandle,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('TOKEN_ASSIGN_PRIMARY','TOKEN_DUPLICATE','TOKEN_IMPERSONATE','TOKEN_QUERY','TOKEN_QUERY_SOURCE','TOKEN_ADJUST_PRIVILEGES','TOKEN_ADJUST_GROUPS','TOKEN_ADJUST_DEFAULT','TOKEN_ADJUST_SESSIONID','DELETE','READ_CONTROL','WRITE_DAC','WRITE_OWNER','SYNCHRONIZE','STANDARD_RIGHTS_REQUIRED','TOKEN_ALL_ACCESS')]
        [string[]]
        $DesiredAccess  
    )
    
    # Calculate Desired Access Value
    $dwDesiredAccess = 0

    foreach($val in $DesiredAccess)
    {
        $dwDesiredAccess = $dwDesiredAccess -bor $TOKEN_ACCESS::$val
    }

    $hToken = [IntPtr]::Zero
    $Success = $Advapi32::OpenProcessToken($ProcessHandle, $dwDesiredAccess, [ref]$hToken); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if(-not $Success) 
    {
        throw "OpenProcessToken Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    
    Write-Output $hToken
}

function OpenThread
{
    <# __CyberCX__
    .SYNOPSIS

    Opens an existing thread object.
    Author: Jared Atkinson (@__jaredc__atkinson)
    License: BSD 3-Clause
    Required Dependencies: PSReflect
    Optional Dependencies: THREAD_ACCESS (Enumeration)
    #>

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [UInt32]
        $ThreadId,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('THREAD_TERMINATE','THREAD_SUSPEND_RESUME','THREAD_GET_CONTEXT','THREAD_SET_CONTEXT','THREAD_SET_INFORMATION','THREAD_QUERY_INFORMATION','THREAD_SET_THREAD_TOKEN','THREAD_IMPERSONATE','THREAD_DIRECT_IMPERSONATION','THREAD_SET_LIMITED_INFORMATION','THREAD_QUERY_LIMITED_INFORMATION','DELETE','READ_CONTROL','WRITE_DAC','WRITE_OWNER','SYNCHRONIZE','THREAD_ALL_ACCESS')]
        [string[]]
        $DesiredAccess,
        
        [Parameter()]
        [bool]
        $InheritHandle = $false
    )
    
    # Calculate Desired Access Value
    $dwDesiredAccess = 0
    
    foreach($val in $DesiredAccess)
    {
        $dwDesiredAccess = $dwDesiredAccess -bor $THREAD_ACCESS::$val
    }

    $hThread = $Kernel32::OpenThread($dwDesiredAccess, $InheritHandle, $ThreadId); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if($hThread -eq 0) 
    {
        #throw "OpenThread Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    
    Write-Output $hThread
}

function OpenThreadToken
{
    <# __CyberCX__
    .SYNOPSIS

    The OpenThreadToken function opens the access token associated with a thread
    Author: Jared Atkinson (@__jaredc__atkinson)
    License: BSD 3-Clause
    Required Dependencies: PSReflect
    Optional Dependencies: $TOKEN_ACCESS (Enumeration)
    #>

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $ThreadHandle,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('TOKEN_ASSIGN_PRIMARY','TOKEN_DUPLICATE','TOKEN_IMPERSONATE','TOKEN_QUERY','TOKEN_QUERY_SOURCE','TOKEN_ADJUST_PRIVILEGES','TOKEN_ADJUST_GROUPS','TOKEN_ADJUST_DEFAULT','TOKEN_ADJUST_SESSIONID','DELETE','READ_CONTROL','WRITE_DAC','WRITE_OWNER','SYNCHRONIZE','STANDARD_RIGHTS_REQUIRED','TOKEN_ALL_ACCESS')]
        [string[]]
        $DesiredAccess,
        
        [Parameter()]
        [bool]
        $OpenAsSelf = $false   
    )
    
    # Calculate Desired Access Value
    $dwDesiredAccess = 0

    foreach($val in $DesiredAccess)
    {
        $dwDesiredAccess = $dwDesiredAccess -bor $TOKEN_ACCESS::$val
    }

    $hToken = [IntPtr]::Zero
    $Success = $Advapi32::OpenThreadToken($ThreadHandle, $dwDesiredAccess, $OpenAsSelf, [ref]$hToken); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if(-not $Success) 
    {
        throw "OpenThreadToken Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    
    Write-Output $hToken
}

function QueryFullProcessImageName
{
    <# __CyberCX__
    .SYNOPSIS

    Retrieves the full name of the executable image for the specified process.
    Author - Jared Atkinson (@__jaredc__atkinson)
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $ProcessHandle,
        
        [Parameter()]
        [UInt32]
        $Flags = 0
    )
    
    $capacity = 2048
    $sb = New-Object -TypeName System.Text.StringBuilder($capacity)

    $Success = $Kernel32::QueryFullProcessImageName($ProcessHandle, $Flags, $sb, [ref]$capacity); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if(-not $Success) 
    {
        Write-Debug "QueryFullProcessImageName Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    
    Write-Output $sb.ToString()
}

function ReadProcessMemory
{
    <# __CyberCX__
    .SYNOPSIS

    Reads data from an area of memory in a specified process. The entire area to be read must be accessible or the operation fails.
    Author - Jared Atkinson (@__jaredc__atkinson)
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $ProcessHandle,
        
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $BaseAddress,
        
        [Parameter(Mandatory = $true)]
        [Int]
        $Size    
    )
    
    <#
    (func kernel32 ReadProcessMemory ([Bool]) @(
        [IntPtr],                                  # _In_ HANDLE hProcess
        [IntPtr],                                  # _In_ LPCVOID lpBaseAddress
        [Byte[]],                                  # _Out_ LPVOID  lpBuffer
        [Int],                                     # _In_ SIZE_T nSize
        [Int].MakeByRefType()                      # _Out_ SIZE_T *lpNumberOfBytesRead
    ) -SetLastError) # MSDN states to call GetLastError if the return value is false. 
    #>
    
    $buf = New-Object byte[]($Size)
    [Int32]$NumberOfBytesRead = 0
    
    $Success = $Kernel32::ReadProcessMemory($ProcessHandle, $BaseAddress, $buf, $buf.Length, [ref]$NumberOfBytesRead); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if(-not $Success) 
    {
        Write-Debug "ReadProcessMemory Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    
    Write-Output $buf
}

function VirtualQueryEx
{
    <# __CyberCX__
    .SYNOPSIS
    Retrieves information about a range of pages within the virtual address space of a specified process.
    Author - Jared Atkinson (@__jaredc__atkinson)
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $ProcessHandle,
        
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $BaseAddress
    )
    
    <#  
    (func kernel32 VirtualQueryEx ([Int32]) @(
        [IntPtr],                                  #_In_     HANDLE                    hProcess,
        [IntPtr],                                  #_In_opt_ LPCVOID                   lpAddress,
        $MEMORYBASICINFORMATION.MakeByRefType(),   #_Out_    PMEMORY_BASIC_INFORMATION lpBuffer,
        [UInt32]                                   #_In_     SIZE_T                    dwLength
    ) -SetLastError)
    #>
    
    $memory_basic_info = [Activator]::CreateInstance($MEMORYBASICINFORMATION)
    $Success = $Kernel32::VirtualQueryEx($ProcessHandle, $BaseAddress, [Ref]$memory_basic_info, $MEMORYBASICINFORMATION::GetSize()); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if(-not $Success) 
    {
        Write-Debug "VirtualQueryEx Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    
    Write-Output $memory_basic_info
}

#endregion Win32 API Abstractions

$CyberCX = $true
$hash = @{}
$results = Get-InjectedThread

# Clean up data for our presentation - /r/n and Time to ISO format
$Results.ProcessName = ($Results.ProcessName| Out-String).trim()
$Results.ProcessId = ($Results.ProcessId | Out-String).trim()
$Results.Path = $($Results.Path | Out-String).trim()
$Results.KernelPath = $($Results.KernelPath | Out-String).trim()
$Results.CommandLine = $($Results.CommandLine | Out-String).trim()
$Results.PathMismatch = $($Results.PathMismatch | Out-String).trim()
$Results.ThreadId = $($Results.ThreadId | Out-String).trim()
$Results.ThreadStartTime = Get-date $($Results.ThreadStartTime | Out-String).trim() -UFormat '+%Y-%m-%dT%H:%M:%SZ'
$Results.AllocatedMemoryProtection = $($Results.AllocatedMemoryProtection | Out-String).trim()
$Results.MemoryProtection = $($Results.MemoryProtection | Out-String).trim()
$Results.MemoryState = $($Results.MemoryState | Out-String).trim()
$Results.MemoryType = $($Results.MemoryType | Out-String).trim()
$Results.BasePriority = $($Results.BasePriority | Out-String).trim()
$Results.IsUniqueThreadToken = $($Results.IsUniqueThreadToken | Out-String).trim()
$Results.Integrity = $($Results.Integrity | Out-String).trim()
$Results.Privilege = $($Results.Privilege | Out-String).trim()
$Results.LogonId = $($Results.LogonId | Out-String).trim()
$Results.SecurityIdentifier = $($Results.SecurityIdentifier | Out-String).trim()
$Results.UserName = $($Results.UserName | Out-String).trim()
$Results.LogonSessionStartTime = Get-date $($Results.LogonSessionStartTime | Out-String).trim() -UFormat '+%Y-%m-%dT%H:%M:%SZ'
$Results.LogonType = $($Results.LogonType | Out-String).trim()
$Results.AuthenticationPackage = $($Results.AuthenticationPackage | Out-String).trim()
$Results.BaseAddress = $($Results.BaseAddress | Out-String).trim()
$Results.Size = $($Results.Size | Out-String).trim()
$Results | Add-Member -MemberType Noteproperty -Name FirstBytes -Value ($($Results.Bytes[0..4] -join ',') + ' ...')
$Results.Bytes = $($Results.Bytes -join ',')

$results
