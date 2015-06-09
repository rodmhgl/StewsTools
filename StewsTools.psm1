# Begin Service-Related Functions
function Restart-STService {
<#
.Synopsis
   Restart a specified service on the specified machine
.DESCRIPTION
   Restarts a specified service on the specified machine, defaults to localhost
.EXAMPLE
   Restart-STService -ComputerName "SERVER01" -ServiceName BITS
    Would restart the BITS service on SERVER01
.EXAMPLE
   Restart-STService -ServiceName BITS
    Would restart the BITS service on the localhost
#>
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  ConfirmImpact='High'
    )]
    [OutputType([String])]
    Param(
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0,
                   ParameterSetName='Default'
                   )]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [Alias('server')] 
        [string[]]$ComputerName='localhost',

        [Parameter(Mandatory=$true,
                   Position=1,
                   ParameterSetName='Default'
        )]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [String[]]$ServiceName
    )

    Begin {
        $VerbosePreference = 'Continue'    
        Write-Verbose -Message "Restarting $ServiceName on $ComputerName"
    }
    
    Process {
        foreach ($computer in $computerName) { 
            foreach ($service in $ServiceName) {
                if ($pscmdlet.ShouldProcess("Restarted $service on $computer", "Restart $service on '$computer'?", 'Restarting Service')) {
                    Try { $service = Get-Service -ComputerName $computer -Name $service -ErrorAction Stop }
                    Catch { 
                            $ErrorMessage = $_.Exception.Message
                            Write-Error -Message "Unable to locate $service on $computer - $($_.Exception.Message)" 
                    }
                    If ($service) { 
                        Try { 
                            Write-Verbose -Message "$($service.name) - $($service.Status)"
                            Restart-Service -InputObject $service -Verbose -ErrorAction Stop
                            $service.Refresh()
                            Write-Verbose -Message "$($service.name) - $($service.Status)"
                        }
                        Catch {
                                $ErrorMessage = $_.Exception.Message
                                Write-Error -Message "Unable to restart $service on $computer - $ErrorMessage" 
                        } 
                    }
                }
            } # End foreach ($service in $ServiceName)
        } # End Foreach ($computer in $computerName)
    }

    End {}
} 

# Begin Active Directory User Related Functions
function Get-STUserLastLogonInfo {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true, 
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [string[]]$UserName
    )
    Begin {}
    Process {
        foreach ($User in $UserName) {
            get-aduser -Properties LastLogonDate, Description, SamAccountName -Identity $User |
            select SamAccountName, LastLogonDate, Description
        }
    }
    End {}
} 

function Get-STIsUserDisabled {
<#
.Synopsis
   Checks to see if a user is disabled
.DESCRIPTION
   Checks to see if a user is disabled. Requires the ActiveDirectory module
.EXAMPLE
   Get-IsUserDisasabled -SAMAccountName "User01"
    Will return True or False based on the enabled / disabled state of User01
#>
    [CmdletBinding(DefaultParameterSetName='Default', 
                  ConfirmImpact='Low')]
    [OutputType([String])]
    Param
    (
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0,
                   ParameterSetName='Default')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [Alias('UserName')] 
        [string[]]$SAMAccountName
    )

    Begin { }
    Process
    {
        foreach ($user in $SAMAccountName) {
            Write-Debug -Message $user 

            $UserInfo = try { (Get-ADUser -Identity $user -ErrorAction Stop) }
            catch { throw $_ }
            
            If ($UserInfo.enabled -eq 'True') { 
                $Enabled = $true
            } elseif ($UserInfo.enabled -eq 'False') {
                $Enabled = $false 
            }

            $Props = @{
                'SAMAccountName' = $UserInfo.SAMAccountName
                'Enabled' = $Enabled 
            }

            $UserStatus = New-Object -TypeName PSObject -Property $Props

            Write-Output -inputobject $UserStatus
        }
    }
    End {}
} 

function Get-STRealName {
<#
.Synopsis
   Retrieves the SAMAccountName, DisplayName, Office, and TelephoneNumber of the specified user
.DESCRIPTION
   Retrieves the SAMAccountName, DisplayName, Office, and TelephoneNumber of the specified user
.EXAMPLE
   Get-Realname User01
    Would return the SAMAccountName, DisplayName, Office, and TelephoneNumber of the specified user
#>
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$false, 
                  PositionalBinding=$false,
                  ConfirmImpact='Low')]
    [OutputType([String])]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0,
                   ParameterSetName='Default')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [Alias('UserName')] 
        [string[]]$SAMAccountName
    )
    Begin { Write-Verbose -Message "Searching for $SAMAccountName" }
    Process {
        foreach ($user in $SAMAccountName) { 
            # samaccountname, displayname, office, telephonenumber
            $UserInfo = Get-ADUser -Identity $user -Properties SAMAccountName, DisplayName, Office, TelephoneNumber | 
            Select-Object -Property  SAMAccountName, DisplayName, Office, TelephoneNumber
            Write-Output -InputObject $UserInfo 
        }
    }
    End {}
} 

function Get-STSamAccountName {
<#
.Synopsis
   Retrieves the SAMAccountName, DisplayName, Office, and TelephoneNumber of users matching the specified DisplayName
.DESCRIPTION
   Retrieves the SAMAccountName, DisplayName, Office, and TelephoneNumber of users matching the specified DisplayName
.EXAMPLE
   Get-Realname 'Doe, John'
    Would return the SAMAccountName, DisplayName, Office, and TelephoneNumber of users matching the specified DisplayName
#>
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$false, 
                  PositionalBinding=$false,
                  ConfirmImpact='Low')]
    [OutputType([String])]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0,
                   ParameterSetName='Default')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [String[]]$DisplayName
    )
    Begin { Write-Verbose -Message "Searching for $DisplayName" }
    Process {
        foreach ($name in $DisplayName) {
            # samaccountname, displayname, office, telephonenumber
            $UserInfo = try { 
                Get-ADUser -Filter "DisplayName -like '*$name*'"-Properties SAMAccountName, DisplayName, Office, TelephoneNumber | 
                Select-Object -Property  SAMAccountName, DisplayName, Office, TelephoneNumber 
            }
            
            catch { Throw $_ }
            
            If ( $UserInfo -eq $null ) { Throw "Unable to locate matching user for $name" }
            
            Write-Output -InputObject $UserInfo 
        }
    }
    End {}
} 

function Get-STEmailAddress {
<#
.Synopsis
   Retrieves the email address of the specified user
.DESCRIPTION
   Retrieves the email address of the specified user
.EXAMPLE
    Get-STEmailAddress User01
#>
    [CmdletBinding()]
    [OutputType([int])]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [String[]]$SAMAccountName
    )

    Begin
    {
    }
    Process
    {
        foreach ($name in $SAMAccountName) {
            $User = Get-ADUser -Identity $name -Properties emailaddress | Select-Object -Property  samaccountname, emailaddress
            Write-Output -InputObject $User 
        }
    }
    End
    {
    }
} 

# Begin Active Directory Computer Related Functions
function Get-STComputerLastLogonInfo {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true, 
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [string[]]$ComputerName
    )
    Begin {}
    Process {
        foreach ($computer in $ComputerName) {
            get-adcomputer -Properties LastLogonDate, Description, SamAccountName -Identity $computer |
            select SamAccountName, LastLogonDate, Description
        }
    }
    End {}
} 

function Get-STComputerByUser {
<#
.Synopsis
   Finds computers with a description field matching a user's DisplayName
.DESCRIPTION
   Finds computers with a description field matching a user's DisplayName
.EXAMPLE
    Get-STComputerByUser -DisplayName Stewart
.EXAMPLE
   Get-STComputerByUser Stewart
#>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [String[]]$DisplayName
    )

    Begin {}
    Process {
        foreach ($name in $DisplayName) {
            $result = Get-ADComputer -Filter "Description -like '*$name*'" -Properties Description | Select-Object -Property  name, Description
            write-output -InputObject $result
        }
    }
    End {}
} 

Function Get-STIPInfo {
    [cmdletbinding()]
    param(
        [Parameter(
            Mandatory=$true, 
            ValueFromPipeline=$true,
            ParameterSetName='NoCredential',
            Position=0
        )]
        [Parameter(
            Mandatory=$true, 
            ValueFromPipeline=$true,
            ParameterSetName='Credential',
            Position=0
        )]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string[]]$computername,
        
        [Parameter(
            Mandatory=$true, 
            ValueFromPipeline=$true,
            ParameterSetName='Credential'
        )]
        [System.Management.Automation.PSCredential]$Credential
    )

    Begin {
        $Activity = 'Getting IP Information'
        $Class = 'Win32_NetworkAdapterConfiguration'
        $Error = 'Unable to Get IP Information'
    }

    Process {
        foreach ($computer in $computername) { 
            Write-Progress -Activity $Activity -CurrentOperation $computer
            try {
                if ($PSCmdlet.ParameterSetName -eq 'Credential') {
                    $parms = @{ 
                        'computername'=$computername;
                        'Credential'=$Credential; 
                        'Class'=$Class
                        'ErrorAction' = 'Stop'
                    }
                }  else {
                    $parms = @{ 
                        'computername'=$computername;
                        'Class'=$Class
                        'ErrorAction' = 'Stop'
                        }
                } # If / Else
                $IP = Get-WmiObject @parms
                $IP = $IP.IPAddress | Where-Object {$_ -match '10.*'}
            } # Try
            catch {
                Write-Error "$Error : $_"
                #$props = @{
                #    'PSComputerName' = $computer
                #    'IPAddress' = "$_"
                #}
            $IP = $_
            } # Catch 
            return $IP
        } # For-Each
    } # Process 
}  

Function Get-STOperatingSystemInfo {
    [cmdletbinding()]
    param(
        [Parameter(
            Mandatory=$true, 
            ValueFromPipeline=$true,
            ParameterSetName='NoCredential',
            Position=0
        )]
        [Parameter(
            Mandatory=$true, 
            ValueFromPipeline=$true,
            ParameterSetName='Credential',
            Position=0
        )]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string[]]$computername,
        
        [Parameter(
            Mandatory=$true, 
            ValueFromPipeline=$true,
            ParameterSetName='Credential'
        )]
        [System.Management.Automation.PSCredential]$Credential
    )

    Begin {
        $Activity = 'Getting OS Information'
        $Class = 'Win32_OperatingSystem'
        $Error = 'Unable to Get OS Information'
    }

    Process {
        foreach ($computer in $computername) { 
            Write-Progress -Activity $Activity -CurrentOperation $computer
            try {
                if ($PSCmdlet.ParameterSetName -eq 'Credential') {
                    $parms = @{ 
                        'computername'=$computername;
                        'Credential'=$Credential; 
                        'Class'=$Class
                        'ErrorAction' = 'Stop'
                    }
                }  else {
                    $parms = @{ 
                        'computername'=$computername;
                        'Class'=$Class
                        'ErrorAction' = 'Stop'
                        }
                } # If / Else
                $OS = Get-WmiObject @parms
            } # Try
            catch {
                Write-Error "$Error : $_"
                $props = @{
                    'PSComputerName' = $computer
                    'OSDescription' = "$_"
                    'Organization' = "$_"
                    'OSVersion' = "$_"
                    'OSCaption' = "$_"
                }
            $OS = New-Object -TypeName PSObject -Property $props   
            } # Catch 
            return $OS
        } # For-Each
    } # Process 
} 

Function Get-STComputerInfo {
    [cmdletbinding()]
    param(
        [Parameter(
            Mandatory=$true, 
            ValueFromPipeline=$true,
            ParameterSetName='NoCredential',
            Position=0
        )]
        [Parameter(
            Mandatory=$true, 
            ValueFromPipeline=$true,
            ParameterSetName='Credential',
            Position=0
        )]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string[]]$computername,
        
        [Parameter(
            Mandatory=$true, 
            ValueFromPipeline=$true,
            ParameterSetName='Credential'
        )]
        [System.Management.Automation.PSCredential]$Credential
    )

    Begin {
        $Activity = 'Getting Computer Information'
        $Class = 'Win32_ComputerSystem'
        $Error = 'Unable to Get Computer Information'
    }

    Process {
        foreach ($computer in $computername) { 
            Write-Progress -Activity $Activity -CurrentOperation $computer
            try {
                if ($PSCmdlet.ParameterSetName -eq 'Credential') {
                    $parms = @{ 
                        'computername'=$computername;
                        'Credential'=$Credential; 
                        'Class'=$Class
                        'ErrorAction' = 'Stop'
                    }
                }  else {
                    $parms = @{ 
                        'computername'=$computername;
                        'Class'=$Class
                        'ErrorAction' = 'Stop'
                        }
                } # If / Else
                $CI = Get-WmiObject @parms
            } # Try
            catch {
                Write-Error "$Error : $_"
                $props = @{
                    'Domain' = "$_"
                    'Manufacturer' = "$_"
                    'Model' = "$_"
                    'UserName' = $null
                    'SystemType' = "$_"
                    'PrimaryOwnerName' = "$_"
                    'TotalPhysicalMemory' = '0'
                }
            $CI = New-Object -TypeName PSObject -Property $props   
            } # Catch 
            return $CI
        } # For-Each
    } # Process 
} 

Function Get-STBIOSInfo {
    [cmdletbinding()]
    param(
        [Parameter(
            Mandatory=$true, 
            ValueFromPipeline=$true,
            ParameterSetName='NoCredential',
            Position=0
        )]
        [Parameter(
            Mandatory=$true, 
            ValueFromPipeline=$true,
            ParameterSetName='Credential',
            Position=0
        )]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string[]]$computername,
        
        [Parameter(
            Mandatory=$true, 
            ValueFromPipeline=$true,
            ParameterSetName='Credential'
        )]
        [System.Management.Automation.PSCredential]$Credential
    )

    Begin {
        $Activity = 'Getting BIOS Information'
        $Class = 'Win32_BIOS'
        $Error = 'Unable to Get BIOS Information'
    }

    Process {
        foreach ($computer in $computername) { 
            Write-Progress -Activity $Activity -CurrentOperation $computer
            try {
                if ($PSCmdlet.ParameterSetName -eq 'Credential') {
                    $parms = @{ 
                        'computername'=$computername;
                        'Credential'=$Credential; 
                        'Class'=$Class
                        'ErrorAction' = 'Stop'
                    }
                }  else {
                    $parms = @{ 
                        'computername'=$computername;
                        'Class'=$Class
                        'ErrorAction' = 'Stop'
                        }
                } # If / Else
                $BIOS = Get-WmiObject @parms
            } # Try
            catch {
                Write-Error "$Error : $_"
                $props = @{
                    'PSComputerName' = $computer
                    'Serial' = "$_"
                }
            $BIOS = New-Object -TypeName PSObject -Property $props   
            } # Catch 
            return $BIOS
        } # For-Each
    } # Process 
} 

function Get-STServerInfo {
<#
.Synopsis
   Retrieves the Serial Number, Product Number, and Model of the specified server.
.DESCRIPTION
   Retrieves the Serial Number, Product Number, and Model of the specified server. Useful for warranty checks.
.EXAMPLE
   Get-STServerInfo SERVER01
    Would return the Serial Number, Product Number, and Model of SERVER01
#>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [string[]]$ComputerName
    )
    Begin { }
    Process
    {
        If (Test-Connection $ComputerName[0] -Count 1 -Quiet) { 
            $CS = Get-WmiObject -class win32_computersystem -ComputerName $ComputerName[0]
            $BIOS = Get-WmiObject -class win32_bios -ComputerName $ComputerName[0]
        
            if ($cs.model -ne 'Virtual Machine') {
                $productnumber = $($cs | Select-Object -ExpandProperty oemstringarray)
                $productnumber = $productnumber[-1].replace('Product ID: ','')
            } else {
                $productnumber = 'Virtual Machine'
            }
            $props = @{
                'ComputerName'=$ComputerName[0]
                'SerialNumber'=$BIOS.serialnumber
                'Model'=$cs.model
                'ProductNumber'=$productnumber
            }
            $Server = New-Object -TypeName PSObject -Property $props
            write-output -InputObject $Server
        } else { 
            Write-Warning "Unable to contact $($ComputerName[0])"
        }
    }
    End { }
} 

# Begin Active Directory Group Related Functions
Function New-STGroup {
<#
.Synopsis
   Creates a new group. Group will be placed in "Domain.com/Users". Designed foruse with Import-CSV
.DESCRIPTION
   Creates a new group. Group will be placed in "Domain.com/Users". Scope defaults to DomainLocal.
   CSV file should contain at a minimum two fields - Name and Description.
   Additionally, a Scope field may be present.
.Parameter Scope
    Group Scope, valid values are Global, DomainLocal, and Universal
.Parameter Name
    The group name, this will be used for both the Name and SAMAccountName fields
.Parameter Description
    The group's description field
.EXAMPLE
    CSV:
        name,description
        Test-Group-One,Owner:Bob
        Test-Group-Two,Owner:Bill

    Import-CSV .\Groups.txt | New-STGroup

    DistinguishedName : CN=Test-Group-One,CN=Users,DC=Targa,DC=com
    GroupCategory     : Security
    GroupScope        : DomainLocal
    Name              : Test-Group-One
    ObjectClass       : group
    ObjectGUID        : ec669308-e675-48ad-a455-bf2ca25e9dc7
    SamAccountName    : Test-Group-One
    SID               : S-1-5-21-725773287-1225889490-525293817-56574

    DistinguishedName : CN=Test-Group-Two,CN=Users,DC=Targa,DC=com
    GroupCategory     : Security
    GroupScope        : DomainLocal
    Name              : Test-Group-Two
    ObjectClass       : group
    ObjectGUID        : 90458101-b2a1-4984-8e6d-afef5b14f7e1
    SamAccountName    : Test-Group-Two
    SID               : S-1-5-21-725773287-1225889490-525293817-56575
#>
    [CmdLetBinding(
        SupportsShouldProcess=$true, 
        ConfirmImpact='High'
    )]
    Param(
        [Parameter(Mandatory=$true,
                    ValueFromPipeline=$true,
                    ValueFromPipelineByPropertyName=$true, 
                    ValueFromRemainingArguments=$false,
                    ParameterSetName='Scope',
                    Position=0
        )]  # ParameterSet Scope - Scope
        [Alias('GroupScope')] 
        [Microsoft.ActiveDirectory.Management.ADGroupScope[]]$Scope='DomainLocal',

        [Parameter(Mandatory=$true,
                    ValueFromPipeline=$true,
                    ValueFromPipelineByPropertyName=$true,
                    ParameterSetName='Scope',
                    Position=1
        )] # ParameterSet Scope - Name
        [Parameter(Mandatory=$true,
                    ValueFromPipeline=$true,
                    ValueFromPipelineByPropertyName=$true,
                    ParameterSetName='NoScope',
                    Position=1
        )] # ParameterSet NoScope - Name
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [Alias('SAMAccountName')]
        [String[]]$Name,

        [Parameter(Mandatory=$true,
                    ValueFromPipeline=$true,
                    ValueFromPipelineByPropertyName=$true, 
                    ParameterSetName='Scope',
                    Position=2
        )] # ParameterSet Scope - Description
        [Parameter(Mandatory=$true,
                    ValueFromPipeline=$true,
                    ValueFromPipelineByPropertyName=$true, 
                    ParameterSetName='NoScope',
                    Position=2
        )] # ParameterSet NoScope - Description
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [String[]]$Description
    ) # Param

    Begin { 
        if (-not($Creds)) { 
            $Creds = Get-Credential
        } # if (-not($Creds))
    } # Begin
    Process {
            Try {
                $output = new-adgroup -GroupScope $($Scope[0]) -SamAccountName $Name[0] -Name $Name[0] -Description $Description[0] -Credential $Creds -PassThru 
                Write-Output -InputObject $output
            }
            Catch {
                Write-Error -Message "Unable to create group: $_"
            }
    } # Process
    End {} # End

} 

function Get-STUserGroupMembership {
<#
.Synopsis
   Dumps a user's direct group membership to a text file
.DESCRIPTION
   Dumps a user's direct group membership to a text file, default output file is c:\temp\<SAMAccountName>.txt
.EXAMPLE
    Get-STUserGroupMembership User01
        This would drop the groups that User01 is a member of into c:\temp\User01.txt
#>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [String[]]$SAMAccountName
    )

    Begin { }
    Process {
    # TODO: User should be able to specify the directory for the output file
        foreach ($name in $SAMAccountName) {
            [String[]]$Groups = (Get-ADPrincipalGroupMembership -Identity rst73).samaccountname
            # [String]$Groups = $(Get-ADPrincipalGroupMembership -Identity $name)
            # $Groups | Out-File -FilePath "C:\Temp\$name.txt"
            
            $props = @{
                'SAMAccountName' = $name
                'Groups' = $Groups
            }

            $UserInfo = New-Object -TypeName PSObject -Property $props

            Out-File -FilePath "C:\Temp\$name.txt" -InputObject $UserInfo.Groups

            Write-Output -InputObject $UserInfo
        }
    }
    End { }
} 

# Get-ProductKey originally written by Boe Prox
# https://gallery.technet.microsoft.com/scriptcenter/Get-product-keys-of-local-83b4ce97 
function Get-STProductKey {
     <#   
    .SYNOPSIS   
        Retrieves the product key and OS information from a local or remote system/s.
         
    .DESCRIPTION   
        Retrieves the product key and OS information from a local or remote system/s. Queries of 64bit OS from a 32bit OS will result in 
        inaccurate data being returned for the Product Key. You must query a 64bit OS from a system running a 64bit OS.
    .LINK
        https://gallery.technet.microsoft.com/scriptcenter/Get-product-keys-of-local-83b4ce97         
    .PARAMETER Computername
        Name of the local or remote system/s.
         
    .NOTES   
        Author: Boe Prox
        Version: 1.1       
            -Update of function from http://powershell.com/cs/blogs/tips/archive/2012/04/30/getting-windows-product-key.aspx
            -Added capability to query more than one system
            -Supports remote system query
            -Supports querying 64bit OSes
            -Shows OS description and Version in output object
            -Error Handling
     
    .EXAMPLE 
     Get-ProductKey -Computername Server1
     
    OSDescription                                           Computername OSVersion ProductKey                   
    -------------                                           ------------ --------- ----------                   
    Microsoft(R) Windows(R) Server 2003, Enterprise Edition Server1       5.2.3790  bcdfg-hjklm-pqrtt-vwxyy-12345     
         
        Description 
        ----------- 
        Retrieves the product key information from 'Server1'
    #>         
    [cmdletbinding()]
    Param (
        [parameter(ValueFromPipeLine=$True,ValueFromPipeLineByPropertyName=$True)]
        [Alias('CN','__Server','IPAddress','Server')]
        [string[]]$Computername = $Env:Computername
    )
    Begin {   
        $map='BCDFGHJKMPQRTVWXY2346789' 
    }
    Process {
        ForEach ($Computer in $Computername) {
            Write-Verbose ('{0}: Checking network availability' -f $Computer)
            If (Test-Connection -ComputerName $Computer -Count 1 -Quiet) {
                Try {
                    Write-Verbose ('{0}: Retrieving WMI OS information' -f $Computer)
                    $OS = Get-WmiObject -ComputerName $Computer Win32_OperatingSystem -ErrorAction Stop                
                } Catch {
                    $OS = New-Object PSObject -Property @{
                        Caption = $_.Exception.Message
                        Version = $_.Exception.Message
                    }
                }
                Try {
                    Write-Verbose ('{0}: Attempting remote registry access' -f $Computer)
                    $remoteReg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$Computer)
                    If ($OS.OSArchitecture -eq '64-bit') {
                        $value = $remoteReg.OpenSubKey('SOFTWARE\Microsoft\Windows NT\CurrentVersion').GetValue('DigitalProductId4')[0x34..0x42]
                    } Else {                        
                        $value = $remoteReg.OpenSubKey('SOFTWARE\Microsoft\Windows NT\CurrentVersion').GetValue('DigitalProductId')[0x34..0x42]
                    }
                    $ProductKey = ''  
                    Write-Verbose ('{0}: Translating data into product key' -f $Computer)
                    for ($i = 24; $i -ge 0; $i--) { 
                      $r = 0 
                      for ($j = 14; $j -ge 0; $j--) { 
                        $r = ($r * 256) -bxor $value[$j] 
                        $value[$j] = [math]::Floor([double]($r/24)) 
                        $r = $r % 24 
                      } 
                      $ProductKey = $map[$r] + $ProductKey 
                      if (($i % 5) -eq 0 -and $i -ne 0) { 
                        $ProductKey = '-' + $ProductKey 
                      } 
                    }
                } Catch {
                    $ProductKey = $_.Exception.Message
                }        
                $object = New-Object PSObject -Property @{
                    Computername = $Computer
                    ProductKey = $ProductKey
                    OSDescription = $os.Caption
                    OSVersion = $os.Version
                } 
                $object.pstypenames.insert(0,'ProductKey.Info')
                $object
            } Else {
                $object = New-Object PSObject -Property @{
                    Computername = $Computer
                    ProductKey = 'Unreachable'
                    OSDescription = 'Unreachable'
                    OSVersion = 'Unreachable'
                }  
                $object.pstypenames.insert(0,'ProductKey.Info')
                $object                           
            }
        }
    }
} 

# Begin 'fun' functions
# Get-Excuse originally from /r/powershell
# http://www.reddit.com/r/PowerShell/comments/2x8n3y/getexcuse/
function Get-STExcuse {
<#
.Synopsis
   Retrieves an excuse
.DESCRIPTION
   Retrieves an excuse from the BOFH archives. Warning: Some excuses may be career-limiting.
.EXAMPLE
    Get-STExcuse
.LINK
    http://www.reddit.com/r/PowerShell/comments/2x8n3y/getexcuse/
#>

  $url = 'http://pages.cs.wisc.edu/~ballard/bofh/bofhserver.pl'
  $ProgressPreference = 'SilentlyContinue'
  $page = Invoke-WebRequest -Uri $url -UseBasicParsing

  $pattern = '<br><font size = "\+2">(.+)'  

  if ($page.Content -match $pattern)
  {
    Write-Output -inputobject $matches[1]
  }
} 

function Get-STTinyURL {
    param(
    [Parameter(Mandatory=$true,
               ValueFromPipeline=$true,
               Position=0)
    ]
    [String[]]$OriginalURL)
    
    Process {
        $OriginalURL | ForEach-Object {
            Write-Verbose -Message $_
            $url = "http://tinyurl.com/api-create.php?url=$_"
            $webclient = New-Object -TypeName System.Net.WebClient
            return $webclient.DownloadString($url)
        }
    }
} 

function Add-STSignature {
    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$Script,
        [string]$TimeStampServer='http://timestamp.comodoca.com/authenticode', 
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert = (dir cert:currentuser\my\ -CodeSigningCert)
    )

    Set-AuthenticodeSignature -FilePath $Script -Certificate $Cert -TimestampServer $TimeStampServer

}

Export-ModuleMember -Function *-ST*