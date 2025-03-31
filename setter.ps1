function Set_Audit_Policy {
    # ==============================
    # Enable Audit Policies
    # ==============================

    # Account Logon
    AuditPol /set /subcategory:"Credential Validation" /success:enable /failure:enable
    AuditPol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
    AuditPol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable

    # Account Management
    AuditPol /set /subcategory:"User Account Management" /success:enable /failure:enable
    AuditPol /set /subcategory:"Security Group Management" /success:enable /failure:enable
    AuditPol /set /subcategory:"Computer Account Management" /success:enable /failure:enable
    AuditPol /set /subcategory:"Other Account Management Events" /success:enable /failure:enable

    # DS Access
    AuditPol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
    AuditPol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable

    # Logon/Logoff
    AuditPol /set /subcategory:"Logon" /success:enable /failure:enable
    AuditPol /set /subcategory:"Logoff" /success:enable /failure:enable
    AuditPol /set /subcategory:"Special Logon" /success:enable /failure:enable
    AuditPol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable

    # Object Access
    AuditPol /set /subcategory:"File System" /success:enable /failure:enable
    AuditPol /set /subcategory:"Registry" /success:enable /failure:enable
    AuditPol /set /subcategory:"Kernel Object" /success:enable /failure:enable
    AuditPol /set /subcategory:"SAM" /success:enable /failure:enable
    AuditPol /set /subcategory:"Handle Manipulation" /success:enable /failure:enable
    AuditPol /set /subcategory:"Removable Storage" /success:enable /failure:enable

    # Policy Change
    AuditPol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
    AuditPol /set /subcategory:"Authentication Policy Change" /success:enable /failure:enable
    AuditPol /set /subcategory:"Authorization Policy Change" /success:enable /failure:enable
    AuditPol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable /failure:enable
    AuditPol /set /subcategory:"Filtering Platform Policy Change" /success:enable /failure:enable
    AuditPol /set /subcategory:"Other Policy Change Events" /success:enable /failure:enable

    # Privilege Use
    AuditPol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable

    # System
    AuditPol /set /subcategory:"Security System Extension" /success:enable /failure:enable
    AuditPol /set /subcategory:"System Integrity" /success:enable /failure:enable
    AuditPol /set /subcategory:"IPsec Driver" /success:enable /failure:enable
    AuditPol /set /subcategory:"Other System Events" /success:enable /failure:enable

    # Detailed Tracking
    AuditPol /set /subcategory:"Process Creation" /success:enable /failure:enable
    AuditPol /set /subcategory:"Process Termination" /success:enable /failure:enable
    AuditPol /set /subcategory:"DPAPI Activity" /success:enable /failure:enable
    AuditPol /set /subcategory:"RPC Events" /success:enable /failure:enable
    AuditPol /set /subcategory:"Token Right Adjusted Events" /success:enable /failure:enable

    # Filtering Platform & Firewall Events
    AuditPol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable
    AuditPol /set /subcategory:"Filtering Platform Packet Drop" /success:enable /failure:enable

    # ==============================
    # Enable Registry Settings for:
    # - Command Line Logging
    # - PowerShell Script Block Logging
    # ==============================

    # Command Line in Event 4688
    New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -PropertyType DWord -Force

    # PowerShell Script Block Logging
    New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -PropertyType DWord -Force

    Write-Output "✅ All audit policies and registry settings have been configured for Windows Firewall and WFP events as well."
}


function New-SPNUser {
    param(
        [string]$Username = "svc_webapp",
        [string]$DisplayName = "Service Account for Web Application",
        [string]$SPN = "HTTP/myserver.mydomain.local"
    )

    $passwordPlain = "peaceandlove"
    $password = ConvertTo-SecureString $passwordPlain -AsPlainText -Force

    Try {
        # Create the user
        New-ADUser -Name $DisplayName `
                   -SamAccountName $Username `
                   -AccountPassword $password `
                   -Enabled $true `
                   -PasswordNeverExpires $true `
                   -UserPrincipalName "$Username@$(Get-ADDomain).DNSRoot"

        Write-Host "✅ Created service account: $Username"

        # Set the SPN
        Set-ADUser -Identity $Username -ServicePrincipalNames @{Add=$SPN}
        Write-Host "🔐 SPN $SPN registered for user $Username"
    }
    Catch {
        Write-Host "❌ Failed to create SPN user. Error: $_"
    }
}



function Generate-RandomPassword {
    param([int]$length = 12)
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'.ToCharArray()
    return -join (Get-Random -InputObject $chars -Count $length)
}


function Create_Usernames {
    $usersToCreate = 20
    $createdUsers = @()

    # Sample first and last names
    $firstNames = @("john", "michael", "david", "chris", "daniel", "james", "robert", "kevin", "alex", "ryan")
    $lastNames = @("smith", "roberts", "jones", "williams", "miller", "brown", "clark", "lewis", "walker", "hall")

    # Output file path
    $desktopPath = [Environment]::GetFolderPath("Desktop")
    $outputFile = Join-Path $desktopPath "CreatedUsers.txt"

    # Clear the file if it already exists
    if (Test-Path $outputFile) {
        Clear-Content $outputFile
    }

    for ($i = 1; $i -le $usersToCreate; $i++) {
        $firstName = Get-Random -InputObject $firstNames
        $lastName = Get-Random -InputObject $lastNames
        $username = "$firstName.$($lastName.Substring(0,1))"

        $passwordPlain = Generate-RandomPassword
        $password = ConvertTo-SecureString $passwordPlain -AsPlainText -Force

        Try {
            # Create domain user account (adjust OU as needed)
            New-ADUser -Name "$firstName $lastName" `
                       -SamAccountName $username `
                       -AccountPassword $password `
                       -Enabled $true `
                       -PasswordNeverExpires $true `
                       -UserPrincipalName "$username@yourdomain.com"

            $line = "$username : $passwordPlain"
            Add-Content -Path $outputFile -Value $line
            $createdUsers += $username

            Write-Host "✅ Created user: $line"
        } Catch {
            Write-Host "❌ Failed to create user: $username. Error: $_"
        }
    }

    # Randomly pick 4 users to add to Domain Admins
    if ($createdUsers.Count -ge 4) {
        $domainAdmins = Get-Random -InputObject $createdUsers -Count 4
        foreach ($user in $domainAdmins) {
            Try {
                Add-ADGroupMember -Identity "Domain Admins" -Members $user
                Write-Host "⭐ $user added to Domain Admins"
                Add-Content -Path $outputFile -Value "$user ADDED TO DOMAIN ADMINS"
            } Catch {
                Write-Host "❌ Failed to add $user to Domain Admins. Error: $_"
            }
        }
    }

    Write-Host "`n📄 All credentials saved to: $outputFile"
}


function main {
    Import-Module ActiveDirectory
    # Creating users
    Create_Usernames

    # Setting up Audit Policy
    Set_Audit_Policy

    # Setting a SPN user
    New-SPNUser
}


main
