#Security Policy Configuration

function Security-Policy {
    # Set password policy
    secedit /export /cfg C:\SecConfig.cfg
    (Get-Content C:\SecConfig.cfg).replace("MinimumPasswordLength = 0", "MinimumPasswordLength = 12") | Set-Content C:\SecConfig.cfg
    (Get-Content C:\SecConfig.cfg).replace("MaximumPasswordAge = 42", "MaximumPasswordAge = 30") | Set-Content C:\SecConfig.cfg
    (Get-Content C:\SecConfig.cfg).replace("PasswordComplexity = 0", "PasswordComplexity = 1") | Set-Content C:\SecConfig.cfg
    secedit /configure /db secedit.sdb /cfg C:\SecConfig.cfg

    # Set account lockout policy
    (Get-Content C:\SecConfig.cfg).replace("LockoutBadCount = 0", "LockoutBadCount = 5") | Set-Content C:\SecConfig.cfg
    (Get-Content C:\SecConfig.cfg).replace("ResetLockoutCount = 30", "ResetLockoutCount = 15") | Set-Content C:\SecConfig.cfg
    (Get-Content C:\SecConfig.cfg).replace("LockoutDuration = 30", "LockoutDuration = 15") | Set-Content C:\SecConfig.cfg
    secedit /configure /db secedit.sdb /cfg C:\SecConfig.cfg

    # Set user rights assignment
    (Get-Content C:\SecConfig.cfg).replace("SeDenyInteractiveLogonRight = ", "SeDenyInteractiveLogonRight = *S-1-5-32-546") | Set-Content C:\SecConfig.cfg
    secedit /configure /db secedit.sdb /cfg C:\SecConfig.cfg

    # Set audit policy
    Auditpol.exe /set /subcategory:"Logon" /success:enable /failure:enable
    Auditpol.exe /set /subcategory:"Credential Validation" /success:enable /failure:enable
}