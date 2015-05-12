$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$sut = (Split-Path -Leaf $MyInvocation.MyCommand.Path).Replace(".Tests.", ".")
$sut = $sut.Replace('ps1','psm1')
import-module "$here\$sut"

Describe "StewsTools" {
    Context "Get-STEmailAddress" {
        $User = "testuser"
        $Users = "testuser","administrator"
        $FakeUser = "BABABOOEY"

        It "returns an email address when provided a user" {
            (Get-STEmailAddress $User).emailaddress | Should Match 'testuser1@'
        }
        
        It "returns multiple email address when provided multiple users by argument" {
            $results = (Get-STEmailAddress $Users) 
            $TotalUsers = $($Users.count)
            $TotalResults = $($Results.count)
            $TotalResults | Should be $TotalUsers
            $Results[0].emailaddress | Should Match 'testuser1@'
            $Results[1].emailaddress | Should Match 'administrator@'
        }

        It "returns multiple email address when provided multiple users by pipeline" {
            $results = ($Users | Get-STEmailAddress) 
            $results.length | Should be $users.length
            $Results[0].emailaddress | Should Match 'testuser1@'
            $Results[1].emailaddress | Should Match 'administrator@'
        }

        It "fails when provided a user who does not exist" {
            {Get-STEmailAddress $FakeUser} | should throw 
        }

    }
    Context "Get-STUserLastLogonInfo" { 
        $User = "testuser"
        $Users = "testuser","rst73"
        $FakeUser = "BABABOOEY"

        It "returns a lastlogondate when provided a user" {
            (Get-STUserLastLogonInfo $User).lastlogondate | Should Not BeNullOrEmpty
        }
        
        It "returns multiple lastlogondates when provided multiple users by argument" {
            $results = (Get-STUserLastLogonInfo $Users) 
            $results.length | Should be $users.length
            $Results[0].lastlogondate | Should Not BeNullOrEmpty
            $Results[1].lastlogondate | Should Not BeNullOrEmpty
        }

        It "returns multiple lastlogondates when provided multiple users by pipeline" {
            $results = ($Users | Get-STUserLastLogonInfo) 
            $results.length | Should be $users.length
            $Results[0].lastlogondate | Should Not BeNullOrEmpty
            $Results[1].lastlogondate | Should Not BeNullOrEmpty
        }

        It "fails when provided a user who does not exist" {
            {Get-STUserLastLogonInfo $FakeUser} | should throw 
        }
    }
    Context "Get-STIsUserDisabled" { 
        It "fails when provided a user who does not exist" {
            { Get-STIsUserDisabled 'FakeUser123' } | should throw 
        }        

        InModuleScope StewsTools {          
            It "should report true if user is enabled" {
                Mock -ModuleName StewsTools Get-ADUser {
                    $props = @{'samaccountname'='testuser'; 'enabled' = "True"}
                    $User = New-Object -TypeName psobject -Property $props
                    return $User
                }
                (Get-STIsUserDisabled testuser).enabled | Should Be $true 
            }
            
            It "should report false if user is disabled" {
                Mock -ModuleName StewsTools Get-ADUser {
                    $props = @{'samaccountname'='testuser'; 'enabled' = 'False'}
                    $User = New-Object -TypeName psobject -Property $props
                    return $User
                }            
                (Get-STIsUserDisabled testuser).enabled | Should Be $false 
            }
        }
    }
    Context "Get-STRealName" {
        $User = "testuser"
        $FakeUser = "FakeUser242"
        

        It "should return a DisplayName when provided a SAMAccountName via property" {
            (Get-STRealName $User).displayname | Should Be "User, Test"
        }

        It "should return a Office when provided a SAMAccountName via property" {
            (Get-STRealName $User).office | Should Be "Houston Corporate Office"
        }

        It "should return a Telephone Number when provided a SAMAccountName via property" {
            (Get-STRealName $User).telephonenumber | Should Be '212-555-1212'
        }

        It "Should accept pipeline input" {
            ($User | Get-STRealName).displayname | Should Be "User, Test"
        }

        It "should return a Office when provided a SAMAccountName via pipeline" {
            ($User | Get-STRealName).office | Should Be "Houston Corporate Office"
        }

        It "should return a Telephone Number when provided a SAMAccountName via pipeline" {
            ($User | Get-STRealName ).telephonenumber | Should Be '212-555-1212'
        }

        It "Should accept pipeline input" {
            ($User | Get-STRealName).displayname | Should Be "User, Test"
        }

        It "should fail when provided a SAMAccountName that does not exist" {
            {Get-STRealName $FakeUser} | should throw
        }

    }
    Context "Get-STSamAccountName" {
        $User = "User, Test"
        $FakeUser = "User, Fake"
        
        It "Should return a SAMAccountName when provided a DisplayName via argument" {
            (Get-STSamAccountName -DisplayName $User).samaccountname | Should Be "testuser"
        }

        It "Should return a Office when provided a DisplayName via argument" {
            (Get-STSamAccountName -DisplayName $User).office | Should Be "Houston Corporate Office"
        }
        
        It "Should return a TelephoneNumber when provided a DisplayName via argument" {
            (Get-STSamAccountName -DisplayName $User).TelephoneNumber | Should Be "212-555-1212"
        }
        
        It "Should accept pipeline input" {
            ($User | Get-STSamAccountName).samaccountname | Should Be "testuser"
        }

        It "should fail when provided a DisplayName that does not exist" {
            {Get-STSamAccountName $FakeUser} | should throw
        }
    }
    Context "New-STGroup" {     }
    Context "Get-STUserGroupMembership" {     }
    Context "Get-STComputerLastLogonInfo" {
        $Computer = "HOUDC01"
        $Computers = "HOUDC01","houvirt22"
        $FakeComputer = "FakeServer01"

        It "returns a lastlogondate when provided a computer" {
            (Get-STComputerLastLogonInfo $Computer).lastlogondate | Should Not BeNullOrEmpty
        }
        
        It "returns multiple lastlogondates when provided multiple computers by argument" {
            $results = (Get-STComputerLastLogonInfo $Computers) 
            $results.length | Should be $Computers.length
            $Results[0].lastlogondate | Should Not BeNullOrEmpty
            $Results[1].lastlogondate | Should Not BeNullOrEmpty
        }

        It "returns multiple lastlogondates when provided multiple computers by pipeline" {
            $results = ($Computers | Get-STComputerLastLogonInfo) 
            $results.length | Should be $Computers.length
            $Results[0].lastlogondate | Should Not BeNullOrEmpty
            $Results[1].lastlogondate | Should Not BeNullOrEmpty
        }

        It "fails when provided a computer who does not exist" {
            {Get-STComputerLastLogonInfo $FakeComputer} | should throw 
        }
    }
    Context "Get-STComputerByUser" {     }
    Context "Get-STOperatingSystemInfo" {     }
    Context "Get-STComputerInfo" {     }
    Context "Get-STBIOSInfo" {     }
    Context "Get-STProductKey" {     }
    Context "Get-STServerInfo" {     }
    Context "Get-STIPInfo" {     }
    Context "Restart-STService" {     }
    Context "Add-STSignature" {     }
    Context "Get-STExcuse" { 
        It "returns an excuse when called" {
            Get-STExcuse | Should Not BeNullOrEmpty 
        }
    }
    Context "Get-STTinyURL" {     }

}
