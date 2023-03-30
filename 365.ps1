<#
A script that will run as many 365 auditing commands as possible manual checks will still be required.

Version 1.0 - 30th March 2023.
#>

# ASCI ART
$t = @"
__________   _____  .__          __  __________   _____                  _______    __    
\______   \ /  |  | |__|  ____ _/  |_\______   \ /  |  | _______ _______ \   _  \ _/  |_  
 |     ___//   |  |_|  | /    \\   __\|     ___//   |  |_\_  __ \\_  __ \/  /_\  \\   __\ 
 |    |   /    ^   /|  ||   |  \|  |  |    |   /    ^   / |  | \/ |  | \/\  \_/   \|  |   
 |____|   \____   | |__||___|  /|__|  |____|   \____   |  |__|    |__|    \_____  /|__|   
               |__|          \/                     |__|                        \/        
                                                                                          

"@

for ($i = 0; $i -lt $t.length; $i++) {
    if ($i % 2) {
        $c = "green"
    }
    elseif ($i % 5) {
        $c = "green"
    }
    elseif ($i % 7) {
        $c = "green"
    }
    else {
        $c = "green"
    }
    Write-Host $t[$i] -NoNewline -ForegroundColor $c
}

Write-Host "Carrying out 365 Auditing, a tool created by P4intP4rr0t." -ForegroundColor Cyan


Start-Sleep -Seconds 10

Write-Host "Starting 365 Audit" -ForegroundColor DarkYellow
Start-Sleep -Seconds 10

$Username = Read-Host -Prompt “Enter Username”
$orgname = Read-Host -Prompt “Enter Organization Name”
Connect-MsolService
Connect-AzureAD -AccountId $Username
Connect-ExchangeOnline -UserPrincipalName $Username -ShowBanner:$false
Connect-SPOService -Url "https://$orgname-admin.sharepoint.com"
Connect-MicrosoftTeams
Connect-MSGraph -AdminConsent
Connect-MSGraph
Connect-IPPSSession

Write-Host "Authentication Complete" -ForegroundColor DarkYellow
Start-Sleep -Seconds 10

#1.1.2 (L2) Ensure multifactor authentication is enabled for all users in all roles (Manual)
Write-Host "1.1.2 (L2) Ensure multifactor authentication is enabled for all users in all roles" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2


Get-MsolUser -all | Where {$_.islicensed -like "True"} | Select DisplayName,UserPrincipalName,@{Name='MFAStatus';Expression= {If($_.StrongAuthenticationRequirements.Count -ne 0){$_.StrongAuthenticationRequirements[0].State} Else {'Disabled'} } } | Out-File -FilePath "$(Get-Location)\'1.1.2 (L2) Ensure multifactor authentication is enabled for all users in all roles.txt'"

#1.1.3 (L1) Ensure that between two and four global admins are designated (Automated)
Write-Host "1.1.3 (L1) Ensure that between two and four global admins are designated" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

$role = Get-MsolRole -RoleName "Company Administrator" 
Get-MsolRoleMember -RoleObjectId $role.objectid | Out-File -FilePath "$(Get-Location)\'1.1.3 (L1) Ensure that between two and four global admins are designated.txt'"

#1.1.4 (L1) Ensure self-service password reset is enabled (Automated)
Write-Host "1.1.4 (L1) Ensure self-service password reset is enabled" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

(Get-MsolCompanyInformation).SelfServePasswordResetEnabled | Out-File -FilePath "$(Get-Location)\'1.1.4 (L1) Ensure self-service password reset is enabled.txt'"

#1.1.6 (L1) Enable Conditional Access policies to block legacy authentication (Automated)
Write-Host "1.1.6 (L1) Enable Conditional Access policies to block legacy authentication" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

Get-AzureADMSConditionalAccessPolicy | Out-File -FilePath "$(Get-Location)\'1.1.6 (L1) Enable Conditional Access policies to block legacy authentication-1.txt'"

Get-MsolDirSyncFeatures | Out-File -FilePath "$(Get-Location)\'1.1.6 (L1) Enable Conditional Access policies to block legacy authentication-2.txt'"

#1.2 (L1) Ensure modern authentication for Exchange Online is enabled (Automated)
Write-Host "1.2 (L1) Ensure modern authentication for Exchange Online is enabled" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

Get-OrganizationConfig | Format-Table -Auto Name, OAuth* | Out-File -FilePath "$(Get-Location)\'1.2 (L1) Ensure modern authentication for Exchange Online is enabled.txt'"

#Legacy Authentication Protocols should be disabled. 

#1.3 (L1) Ensure modern authentication for Skype for Business Online is enabled (Automated)
Write-Host "1.3 (L1) Ensure modern authentication for Skype for Business Online is enabled" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

Get-CsOAuthConfiguration |fl ClientAdalAuthOverride | Out-File -FilePath "$(Get-Location)\'1.3 (L1) Ensure modern authentication for Skype for Business Online is enabled.txt'"

#1.4 (L1) Ensure modern authentication for SharePoint applications is required (Automated)
Write-Host "1.4 (L1) Ensure modern authentication for SharePoint applications is required" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

Get-SPOTenant | ft LegacyAuthProtocolsEnable | Out-File -FilePath "$(Get-Location)\'1.4 (L1) Ensure modern authentication for SharePoint applications is required.txt'"

#1.5 (L1) Ensure that Office 365 Passwords Are Not Set to Expire (Automated)
Write-Host "1.5 (L1) Ensure that Office 365 Passwords Are Not Set to Expire" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

Get-MSolDomain | Foreach {Get-MsolPasswordPolicy -DomainName $_.name | ft ValidityPeriod} | Out-File -FilePath "$(Get-Location)\'1.5 (L1) Ensure that Office 365 Passwords Are Not Set to Expire.txt'"

#2 Application Permissions
#2.1 (L2) Ensure third party integrated applications are not allowed (Manual)
Write-Host "2.1 (L2) Ensure third party integrated applications are not allowed" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

Get-MsolCompanyInformation | select UsersPermissionToUserConsentToAppEnabled | Out-File -FilePath "$(Get-Location)\'2.1 (L2) Ensure third party integrated applications are not allowed.txt'"

#2.2 (L2) Ensure calendar details sharing with external users is disabled (Automated)
Write-Host "2.2 (L2) Ensure calendar details sharing with external users is disabled" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

Get-SharingPolicy | Where-Object { $_.Domains -like '*CalendarSharing*' } | Out-File -FilePath "$(Get-Location)\'2.2 (L2) Ensure calendar details sharing with external users is disabled.txt'"

#2.3 (L2) Ensure O365 ATP SafeLinks for Office Applications is Enabled (Automated)
Write-Host "2.3 (L2) Ensure O365 ATP SafeLinks for Office Applications is Enabled" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

Get-AtpPolicyForO365 | select EnableSafeLinksForO365Clients | Out-File -FilePath "$(Get-Location)\'2.3 (L2) Ensure O365 ATP SafeLinks for Office Applications is Enabled.txt'"

#2.4 (L2) Ensure Office 365 ATP for SharePoint, OneDrive, and Microsoft Teams is Enabled (Automated)
Write-Host "2.4 (L2) Ensure Office 365 ATP for SharePoint, OneDrive, and Microsoft Teams is Enabled" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

Get-AtpPolicyForO365 | select EnableATPForSPOTeamsODB | Out-File -FilePath "$(Get-Location)\'2.4 (L2) Ensure Office 365 ATP for SharePoint, OneDrive, and Microsoft Teams is Enabled.txt'"

#2.5 (L2) Ensure Office 365 SharePoint infected files are disallowed for download (Automated)
Write-Host "2.5 (L2) Ensure Office 365 SharePoint infected files are disallowed for download" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

Get-SPOTenant | Select-Object DisallowInfectedFileDownload | Out-File -FilePath "$(Get-Location)\'2.5 (L2) Ensure Office 365 SharePoint infected files are disallowed for download.txt'"

#2.6 (L2) Ensure user consent to apps accessing company data on their behalf is not allowed (Automated)
Write-Host "2.6 (L2) Ensure user consent to apps accessing company data on their behalf is not allowed" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

Get-MsolCompanyInformation | Select-Object UsersPermissionToUserConsentToAppEnabled | Out-File -FilePath "$(Get-Location)\'2.6 (L2) Ensure user consent to apps accessing company data on their behalf is not allowed.txt'"

#2.8 (L2) - Ensure users installing Outlook add-ins is not allowed (Automated)
Write-Host "2.8 (L2) - Ensure users installing Outlook add-ins is not allowed" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

Get-EXOMailbox | Select-Object -Unique RoleAssignmentPolicy | ForEach-Object { Get-RoleAssignmentPolicy -Identity $_.RoleAssignmentPolicy | Where-Object {$_.AssignedRoles -like "*Apps*"}} | Select-Object Identity, @{Name="AssignedRoles"; Expression={Get-Mailbox | Select-Object -Unique RoleAssignmentPolicy | ForEach-Object { Get-RoleAssignmentPolicy -Identity $_.RoleAssignmentPolicy | Select-Object -ExpandProperty AssignedRoles | Where-Object {$_ -like "*Apps*"}}}} | Out-File -FilePath "$(Get-Location)\'2.8 (L2) - Ensure users installing Outlook add-ins is not allowed.txt'"

#3 Data Management 
#3.1 (L2) Ensure the customer lockbox feature is enabled (Automated)
Write-Host "3.1 (L2) Ensure the customer lockbox feature is enabled" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

Get-OrganizationConfig |Select-Object CustomerLockBoxEnable | Out-File -FilePath "$(Get-Location)\'3.1 (L2) Ensure the customer lockbox feature is enabled.txt'"

#3.4 (L1) Ensure DLP policies are enabled (Automated) 
Write-Host "3.4 (L1) Ensure DLP policies are enabled" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

Get-DLPPolicy | Out-File -FilePath "$(Get-Location)\'3.4 (L1) Ensure DLP policies are enabled.txt'"


#3.5 (L1) Ensure DLP policies are enabled for Microsoft Teams (Manual) 
Write-Host "3.5 (L1) Ensure DLP policies are enabled for Microsoft Teams" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

Get-DLPCompliancePolicy | Out-File -FilePath "$(Get-Location)\'3.5 (L1) Ensure DLP policies are enabled for Microsoft Teams.txt'"

#3.6 (L2) Ensure that external users cannot share files, folders, and sites they do not own (Automated)
Write-Host "3.6 (L2) Ensure that external users cannot share files, folders, and sites they do not own" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

Get-SPOTenant | ft PreventExternalUsersFromResharing | Out-File -FilePath "$(Get-Location)\'3.6 (L2) Ensure that external users cannot share files, folders, and sites they do not own.txt'"

#3.7 (L2) Ensure external file sharing in Teams is enabled for only approved cloud storage services (Manual)
Write-Host "3.7 (L2) Ensure external file sharing in Teams is enabled for only approved cloud storage services" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

Get-CsTeamsClientConfiguration | select allow | Out-File -FilePath "$(Get-Location)\'3.7 (L2) Ensure external file sharing in Teams is enabled for only approved cloud storage services.txt'"

#4 Email Security / Exchange Online
#4.1 (L1) Ensure the Common Attachment Types Filter is enabled (Automated) 
Write-Host "4.1 (L1) Ensure the Common Attachment Types Filter is enabled" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2
 
Get-MalwareFilterPolicy -Identity Default | Select-Object EnableFileFilter | Out-File -FilePath "$(Get-Location)\'4.1 (L1) Ensure the Common Attachment Types Filter is enabled.txt'"

#4.2 (L1) Ensure Exchange Online Spam Policies are set correctly
Write-Host "4.2 (L1) Ensure Exchange Online Spam Policies are set correctly" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

Get-HostedOutboundSpamFilterPolicy | Select-Object Bcc*, Notify* | Out-File -FilePath "$(Get-Location)\'4.2 (L1) Ensure Exchange Online Spam Policies are set correctly.txt'"

#4.3 (L1) Ensure mail transport rules do not forward email to external domains (Automated) 
Write-Host "4.3 (L1) Ensure mail transport rules do not forward email to external domains" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2
{
    Get-TransportRule | Where-Object {$_.RedirectMessageTo -ne $null} | ft Name,RedirectMessageTo; Get-RemoteDomain Default | fl AllowedOOFType, AutoForwardEnabled; Get-TransportRule | where { $_.Identity -like '*Client Rules To External Block*' } | Out-File -FilePath "$(Get-Location)\'4.3 (L1) Ensure mail transport rules do not forward email to external domains.txt'"
}
#4.4 (L2) Ensure automatic forwarding options are disabled (Automated)
Write-Host "4.4 (L2) Ensure automatic forwarding options are disabled" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

Get-TransportRule | Where-Object {($_.setscl -eq -1 -and $_.SenderDomainIs -ne $null)} | ft Name,SenderDomainIs | Out-File -FilePath "$(Get-Location)\'4.4 (L2) Ensure automatic forwarding options are disabled.txt'"

#4.5 (L1) Ensure mail transport rules do not whitelist specific domains (Automated) 
Write-Host "4.5 (L1) Ensure mail transport rules do not whitelist specific domains" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

(Get-TransportRule | Where-Object { $_.SetSCL -AND ($_.SetSCL -as [int] -LE 0) -AND $_.SenderDomainIs }).Name; (Get-TransportRule | Where { $_.SetSCL -AND ($_.SetSCL -as [int] -LE 0) -AND $_.SenderIPRanges }).Name | Out-File -FilePath "$(Get-Location)\'4.5 (L1) Ensure mail transport rules do not whitelist specific domains.txt'"

#4.6 (L2) Ensure the Client Rules Forwarding Block is enabled (Automated)
Write-Host "4.4 (L2) Ensure automatic forwarding options are disabled" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

Get-TransportRule |  Where-Object {$_.Identity -contains $externalTransportRuleName} | Out-File -FilePath "$(Get-Location)\'4.6 (L2) Ensure the Client Rules Forwarding Block is enabled.txt'"

#4.7 (L2) Ensure the Advanced Threat Protection Safe Links policy is enabled (Automated) 
Write-Host "4.7 (L2) Ensure the Advanced Threat Protection Safe Links policy is enabled" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

Get-SafeLinksPolicy | Out-File -FilePath "$(Get-Location)\'4.7 (L2) Ensure the Advanced Threat Protection Safe Links policy is enabled.txt'"

#4.8 (L2) Ensure the Advanced Threat Protection Safe Attachments policy is enabled (Automated)
Write-Host "4.8 (L2) Ensure the Advanced Threat Protection Safe Attachments policy is enabled" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

Get-SafeAttachmentPolicy | Out-File -FilePath "$(Get-Location)\'4.8 (L2) Ensure the Advanced Threat Protection Safe Attachments policy is enabled.txt'"

#4.9 (L2) Ensure basic authentication for Exchange Online is disabled (Automated)
Write-Host "4.9 (L2) Ensure basic authentication for Exchange Online is disabled" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2
{
    Get-OrganizationConfig | Select-Object -ExpandProperty DefaultAuthenticationPolicy | Out-File -FilePath "$(Get-Location)\'4.9 (L2) Ensure basic authentication for Exchange Online is disabled check1.txt'"

    Get-OrganizationConfig | Select-Object -ExpandProperty DefaultAuthenticationPolicy | ForEach { Get-AuthenticationPolicy $_ | Select-Object AllowBasicAuth* } | Out-File -FilePath "$(Get-Location)\'4.9 (L2) Ensure basic authentication for Exchange Online is disabled check2.txt'"

    Get-User -ResultSize Unlimited | Select-Object UserPrincipalName, AuthenticationPolicy | Out-File -FilePath "$(Get-Location)\'4.9 (L2) Ensure basic authentication for Exchange Online is disabled check3.txt'"
}

#4.10 (L1) Ensure that an anti-phishing policy has been created (Automated)
Write-Host "4.10 (L1) Ensure that an anti-phishing policy has been created" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

Get-AntiPhishPolicy | ft Name | Out-File -FilePath "$(Get-Location)\'4.10 (L1) Ensure that an anti-phishing policy has been created.txt'"

#4.11 (L1) Ensure that DKIM is enabled for all Exchange Online Domains (Automated)
Write-Host "4.11 (L1) Ensure that DKIM is enabled for all Exchange Online Domains" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

Get-DkimSigningConfig | Out-File -FilePath "$(Get-Location)\'4.11 (L1) Ensure that DKIM is enabled for all Exchange Online Domains.txt'"

#4.14 (L1) Ensure notifications for internal users sending malware is Enabled (Automated)
Write-Host "4.14 (L1) Ensure notifications for internal users sending malware is Enabled" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

Get-MalwareFilterPolicy | Format-List Name,EnableInternalSenderNotifications,EnableInternalSenderAdminNotifications,InternalSenderAdminAddress | Out-File -FilePath "$(Get-Location)\'4.14 (L1) Ensure notifications for internal users sending malware is Enabled.txt'"

#4.15 (L2) Ensure MailTips are enabled for end users (Automated)
Write-Host "4.15 (L2) Ensure MailTips are enabled for end users" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

Get-OrganizationConfig |Select-Object MailTipsAllTipsEnabled, MailTipsExternalRecipientsTipsEnabled, MailTipsGroupMetricsEnabled, MailTipsLargeAudienceThreshold | Out-File -FilePath "$(Get-Location)\'4.15 (L2) Ensure MailTips are enabled for end users.txt'"

#5 Auditing
#5.1 (L1) Ensure Microsoft 365 audit log search is Enabled (Automated)
Write-Host "5.1 (L1) Ensure Microsoft 365 audit log search is Enabled" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

Get-AdminAuditLogConfig | Select-Object AdminAuditLogEnabled, UnifiedAuditLogIngestionEnabled | Out-File -FilePath "$(Get-Location)\'5.1 (L1) Ensure Microsoft 365 audit log search is Enabled.txt'"

#5.2 (L1) Ensure mailbox auditing for all users is Enabled (Automated)
Write-Host "5.2 (L1) Ensure mailbox auditing for all users is Enabled" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

Get-mailbox | Where AuditEnabled -Match 'False' | select UserPrincipalName, auditenabled | Out-File -FilePath "$(Get-Location)\'5.2 (L1) Ensure mailbox auditing for all users is Enabled check1.txt'"

#Alternatively. 
Get-OrganizationConfig | Format-List AuditDisabled | Out-File -FilePath "$(Get-Location)\'5.2 (L1) Ensure mailbox auditing for all users is Enabled check2.txt'"

#6 Storage
#6.1 (L2) Ensure document sharing is being controlled by domains with whitelist or blacklist (Automated)
Write-Host "6.1 (L2) Ensure document sharing is being controlled by domains with whitelist or blacklist" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

Get-SPOTenant | fl SharingDomainRestrictionMode,SharingAllowedDomainList | Out-File -FilePath "$(Get-Location)\'6.1 (L2) Ensure document sharing is being controlled by domains with whitelist or blacklist.txt'"


#6.2 (L2) Block OneDrive for Business sync from unmanaged devices (Automated)
Write-Host "6.2 (L2) Block OneDrive for Business sync from unmanaged devices" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

Get-SPOTenantSyncClientRestriction | fl TenantRestrictionEnabled,AllowedDomainList | Out-File -FilePath "$(Get-Location)\'6.2 (L2) Block OneDrive for Business sync from unmanaged devices.txt'"

#6.3 (L1) Ensure expiration time for external sharing links is set (Automated)
Write-Host "6.3 (L1) Ensure expiration time for external sharing links is set" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

Get-SPOTenant | fl RequireAnonymousLinksExpireInDays | Out-File -FilePath "$(Get-Location)\'6.3 (L1) Ensure expiration time for external sharing links is set.txt'"


#6.4 (L2) Ensure external storage providers available in Outlook on the Web are restricted (Automated)
Write-Host "6.4 (L2) Ensure external storage providers available in Outlook on the Web are restricted" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

Get-OwaMailboxPolicy | Format-Table Name, AdditionalStorageProvidersAvailable | Out-File -FilePath "$(Get-Location)\'6.4 (L2) Ensure external storage providers available in Outlook on the Web are restricted.txt'"


#7 Mobile Device Management
#7.1 (L1) Ensure mobile device management polices are set to require advanced security configurations to protect from basic internet attacks (Manual)
Write-Host "7.1 (L1) Ensure mobile device management polices are set to require advanced security configurations to protect from basic internet attacks" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

Get-MobileDeviceMailboxPolicy | select AlphanumericPasswordRequired,PasswordEnabled,AllowSimplePassword,MinPasswordLength,MaxPasswordFailedAttempts,PasswordExpiration,PasswordHistory,MinPasswordComplexCharacters | Out-File -FilePath "$(Get-Location)\'7.1 (L1) Ensure mobile device management polices are set to require advanced security configurations to protect from basic internet attacks.txt'"

#9.1	Default User Role Permissions
Write-Host "9.1	Default User Role Permissions" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

Get-AzureADMSAuthorizationPolicy | Out-File -FilePath "$(Get-Location)\'9.1	Default User Role Permissions.txt'"

#View the DefaultUserRolePermissions setting for permissions. Also AllowEmailVerifiedUsersToJoinOrganization should be set to False. 

#9.2	Mailboxes with IMAP and POP
Write-Host "9.2	Mailboxes with IMAP and POP" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

Get-EXOCASMailbox -Filter {IMAPEnabled -eq $True -or POPEnabled -eq $True} | Out-File -FilePath "$(Get-Location)\'9.2	Mailboxes with IMAP and POP.txt'"
#Any mailboxes displayed will have either iMAP or POP or both enabled. 

#9.3	Rules to block executable attachments.
Write-Host "9.3	Rules to block executable attachments" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

Get-TransportRule | Format-List Name,AttachmentHasExecutableContent,RejectMessage*,DeleteMessage | Out-File -FilePath "$(Get-Location)\'9.3	Rules to block executable attachments.txt'"

#9.4	SMTP Authentication.
Write-Host "9.4	SMTP Authentication" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

Get-TransportConfig | select SmtpClientAuthenticationDisabled | Out-File -FilePath "$(Get-Location)\'9.4	SMTP Authentication.txt'"

#SMTP authentication is used by threat actors to brute-force account passwords without the need to supply MFA. 

#9.5	Find users with forwarding rules
Write-Host "9.5	Find users with forwarding rules" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2
Write-Host "9.5	Find users with forwarding rules - NEDS MANUAL CHECK" -ForegroundColor red
Start-Sleep -Seconds 2
#$mailboxes = Get-EXOMailbox -ResultSize Unlimited
#foreach ($mailbox in $mailboxes){Get-InboxRule -Mailbox $mailbox.UserPrincipalName | Where-Object {($null -ne $_.ForwardTo) -or ($null -ne $_.ForwardAsAttachmentTo) -or ($null -ne $_.RedirectTo)}} | Select-Object MailboxOwnerId, RuleIdentity, Name, ForwardTo, RedirectTo  | Out-File -FilePath "$(Get-Location)\'9.5	Find users with forwarding rules.txt'"


#9.6	Teams P2P File Transfers
Write-Host "9.6	Teams P2P File Transfers" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2
{
    $policies = Get-CsExternalUserCommunicationPolicy
        Foreach ($policy in $policies)
            If ($policy.EnableP2PFileTransfer -eq $true){
              Write-Output $policy.Identity
            }  | Out-File -FilePath "$(Get-Location)\'9.6	Teams P2P File Transfers.txt'"
}

#9.7	Find users who have access to Shared Mailboxes
Write-Host "9.7	Find users who have access to Shared Mailboxes" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

Get-Mailbox -RecipientTypeDetails SharedMailbox -ResultSize:Unlimited | Get-MailboxPermission |Select-Object Identity,User,AccessRights | Out-File -FilePath "$(Get-Location)\'9.7	Find users who have access to Shared Mailboxes.txt'"

#9.8	Enumerate Permissions Users Have to Other Peoples’ Mailboxes
Write-Host "9.8	Enumerate Permissions Users Have to Other Peoples’ Mailboxes" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

Get-Mailbox -resultsize unlimited | Get-MailboxPermission | Select Identity, User, Deny, AccessRights, IsInherited| Where {($_.user -ne "NT AUTHORITY\SELF")} | Out-File -FilePath "$(Get-Location)\'9.8	Enumerate Permissions Users Have to Other Peoples’ Mailboxes.txt'"

#9.9	Enumerate Email Accounts Which Allow Send-On-Behalf-Of
Write-Host "9.9	Enumerate Email Accounts Which Allow Send-On-Behalf-Of" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

Get-EXOMailbox -Resultsize Unlimited | select Name,GrantSendOnBehalfTo | Out-File -FilePath "$(Get-Location)\'9.9	Enumerate Email Accounts Which Allow Send-On-Behalf-Of.txt'"

#9.10	Enumerate Email Accounts Where Non-Owners Have Send-As Permissions
Write-Host "9.10	Enumerate Email Accounts Where Non-Owners Have Send-As Permissions" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

Get-Mailbox -resultsize unlimited | Get-RecipientPermission| where {($_.trustee -ne "NT AUTHORITY\SELF")}|select Identity,Trustee,AccessControlType,AccessRights,IsInherited | Out-File -FilePath "$(Get-Location)\'9.10	Enumerate Email Accounts Where Non-Owners Have Send-As Permissions.txt'"

#9.11	Test To see if Safe Attachment Filters are Skipped
Write-Host "9.11	Test To see if Safe Attachment Filters are Skipped" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

Get-TransportRule | Where { $_.SetHeaderName -eq "X-MS-Exchange-Organization-SkipSafeAttachmentProcessing"} | Out-File -FilePath "$(Get-Location)\'9.11	Test To see if Safe Attachment Filters are Skipped.txt'"

#9.12	Get a List of File Types Which Are Blocked in Email
Write-Host "9.12	Get a List of File Types Which Are Blocked in Email" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

Get-MalwareFilterPolicy |  select -ExpandProperty FileTypes | Out-File -FilePath "$(Get-Location)\'9.12	Get a List of File Types Which Are Blocked in Email.txt'"

#9.13	Bypass Safe Attachments Processing
Write-Host "9.13	Bypass Safe Attachments Processing" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

Get-TransportRule | Where { $_.SetHeaderName -eq "X-MS-Exchange-Organization-SkipSafeAttachmentProcessing" } | select Identity | Out-File -FilePath "$(Get-Location)\'9.13	Bypass Safe Attachments Processing.txt'"

#9.14	Bypass Safe Links Processing
Write-Host "9.14	Bypass Safe Links Processing" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

Get-TransportRule | Where-Object {($_.State -eq "Enabled") -and ($_.SetHeaderName -eq "X-MS-Exchange-Organization-SkipSafeLinksProcessing")} | select Identity | Out-File -FilePath "$(Get-Location)\'9.14	Bypass Safe Links Processing.txt'"

#9.15	Dangerous Default User Permissions
Write-Host "9.15	Dangerous Default User Permissions" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

Get-MsolCompanyInformation | select UsersPermissionToReadOtherUsersEnabled, UsersPermissionToCreateGroupsEnabled,UsersPermissionToCreateLOBAppsEnabled | Out-File -FilePath "$(Get-Location)\'99.15	Dangerous Default User Permissions check1.txt'"

Get-AzureADMSAuthorizationPolicy | select AllowEmailVerifiedUsersToJoinOrganization | Out-File -FilePath "$(Get-Location)\'9.15	Dangerous Default User Permissions check2.txt'"


#9.16	Basic Authentication (Expanded)
Write-Host "9.16	Basic Authentication" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

#Basic authentication does not support MFA. It is therefore used by threat actors to brute force user’s passwords. First test to see if a default authentication policy exists:

Get-OrganizationConfig | select DefaultAuthenticationPolicy | Out-File -FilePath "$(Get-Location)\'9.16	Basic Authentication check1.txt'"


Get-AuthenticationPolicy | select AllowBasicAuthActiveSync,AllowBasicAuthAutodiscover,AllowBasicAuthImap,AllowBasicAuthMapi,AllowBasicAuthOfflineAddressBook,AllowBasicAuthOutlookService,AllowBasicAuthPop,AllowBasicAuthReportingWebServices,AllowBasicAuthRest,AllowBasicAuthRpc,AllowBasicAuthSmtp,AllowBasicAuthWebServices,AllowBasicAuthPowershell | Out-File -FilePath "$(Get-Location)\'9.16	Basic Authentication check2.txt'"


#9.17	Detecting Frames As Spam
Write-Host "9.17	Detecting Frames As Spam" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

Get-HostedContentFilterPolicy | select Name,MarkAsSpamFramesInHtml | Out-File -FilePath "$(Get-Location)\'9.17	Detecting Frames As Spam.txt'"

#9.18	PowerShell Service Principals
Write-Host "9.18	PowerShell Service Principals" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

Get-AzureADServicePrincipal | findstr /sip "PowerShell" | Out-File -FilePath "$(Get-Location)\'9.18	PowerShell Service Principals.txt'"


#9.20	Teams Allowed Domains
Write-Host "9.20	Teams Allowed Domains" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

Get-CsTenantFederationConfiguration | select AllowedDomains,AllowFederatedUsers | Out-File -FilePath "$(Get-Location)\'9.20	Teams Allowed Domains.txt'"

#If AllowedDomains is set to AllowAllKnownDomains and AllowFederatedUsers is set to true then any user from any domain can connect to teams. 

#9.21	Teams Link Previews
Write-Host "9.21	Teams Link Previews" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

Get-CsTeamsMessagingPolicy | select Identity,AllowUrlPreviews | Out-File -FilePath "$(Get-Location)\'9.21	Teams Link Previews.txt'"

#Microsoft Teams by default enables and allows users to preview links in messages. Some organizations may wish to disable this functionality. The Preview can be set to a completely different target than the main URL potentially lulling users into a false sense of security. 

#Please see: https://positive.security/blog/ms-teams-1-feature-4-vulns#2-spoofing

#9.22	Anonymous Access to Teams
Write-Host "9.22	Anonymous Access to Teams" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

Get-CsTeamsMeetingPolicy | select Identity,AllowAnonymousUsersToJoinMeeting | Out-File -FilePath "$(Get-Location)\'9.22	Anonymous Access to Teams.txt'"

#Policies which come back with AllowAnonymousUsersToJoinMeeting set to true allow any user to connect to Teams meetings. Microsoft Teams by default enables and allows anonymous users to join Teams meetings. Some organizations may wish to disable this functionality, or restrict certain users, members, or roles from allowing anonymous users to join meetings.

#9.23	Teams Animations
Write-Host "9.23	Teams Animations" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

Get-CsTeamsMessagingPolicy | select Identity,AllowGiphy,GiphyRatingType,AllowGiphyDisplay,AllowMemes | Out-File -FilePath "$(Get-Location)\'9.23	Teams Animations.txt'"



#Please see here for further information:
#https://resources.infosecinstitute.com/topic/hacking-microsoft-teams-vulnerabilities-a-step-by-step-guide/
#9.24	Reviewing Audit Logs and Reports
#One obvious thing to check is the location that they are logging in from. But we should determine their usual login location first:
Write-Host "9.24	Reviewing Audit Logs and Reports" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

Get-MSOLUser | select DisplayName,UsageLocation | Out-File -FilePath "$(Get-Location)\'9.24	Reviewing Audit Logs and Reports.txt'"


#This will list the users and their normal login location. 

#Then we can download the user sign-ins report using the following cmdlet:
Write-Host "9.24 download the user sign-ins report" -ForegroundColor DarkYellow
Start-Sleep -Seconds 2

Get-AzureADAuditSignInLogs | Select-Object User,UPN,City,State,Region | Out-File -FilePath "$(Get-Location)\'9.24 download the user sign-ins report.txt'"






