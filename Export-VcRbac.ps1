#Requires -Version 7.2
<#
.SYNOPSIS
    Exports and documents the RBAC configuration of a vCenter Server.
.DESCRIPTION
    Exports roles, inventory permissions, global permissions and SSO users/groups to
    rbac-export.json, writes an HTML report, and generates mapping templates
    (domain-map.csv, principal-map.csv, path-map.csv) used by Import-VcRbac.ps1.
.EXAMPLE
    ./Export-VcRbac.ps1 -Server vc01.corp.local -Credential (Get-Credential administrator@vsphere.local)
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Server,
    [Parameter(Mandatory)][pscredential]$Credential,
    [string]$OutputPath = '.',
    [ValidateSet('Permissions', 'GlobalPermissions', 'Sso')]
    [string[]]$Include = @('Permissions', 'GlobalPermissions', 'Sso'),
    [string]$SsoDomain,
    [string]$GlobalDocumentPattern = 'global',
    [switch]$SkipCertificateCheck
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'RbacCommon.psm1') -Force

if (-not $SsoDomain) {
    $SsoDomain = if ($Credential.UserName -match '@(.+)$') { $Matches[1] } else { 'vsphere.local' }
}

$outDir = Join-Path $OutputPath ("rbac-{0}-{1}" -f $Server, (Get-Date -Format 'yyyyMMdd-HHmmss'))
$null = New-Item -ItemType Directory -Path $outDir -Force

if ($SkipCertificateCheck) {
    $null = Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Scope Session -Confirm:$false
}
$vi = Connect-VIServer -Server $Server -Credential $Credential
$sso = $null

try {
    $si = Get-View ServiceInstance -Server $vi
    $authMgr = Get-View $si.Content.AuthorizationManager -Server $vi

    $roleById = @{}
    foreach ($r in $authMgr.RoleList) { $roleById[$r.RoleId] = $r }

    $privInfo = @{}
    foreach ($p in $authMgr.PrivilegeList) { $privInfo[$p.PrivId] = $p }
    $privLabel = @{}
    foreach ($d in $authMgr.Description.Privilege) { $privLabel[$d.Key] = $d.Label }

    $export = [ordered]@{
        Metadata          = [ordered]@{
            ExportedAt    = (Get-Date).ToString('s')
            SourceServer  = $Server
            FullName      = $si.Content.About.FullName
            Version       = $si.Content.About.Version
            Build         = $si.Content.About.Build
            InstanceUuid  = $si.Content.About.InstanceUuid
            SsoDomain     = $SsoDomain
            ExportedBy    = $Credential.UserName
            Included      = $Include
        }
        Roles             = @()
        Permissions       = @()
        GlobalPermissions = @()
        Sso               = $null
    }

    Write-Host 'Exporting roles'
    $export.Roles = @($authMgr.RoleList | Sort-Object Name | ForEach-Object {
            [ordered]@{
                Name       = $_.Name
                Label      = $_.Info.Label
                Summary    = $_.Info.Summary
                SourceId   = $_.RoleId
                IsSystem   = $_.System
                IsBuiltIn  = [bool](Test-RbacBuiltInRole $_)
                Privileges = @($_.Privilege | Sort-Object)
            }
        })

    if ('Permissions' -in $Include) {
        Write-Host 'Building inventory path map'
        $inv = Get-RbacInventoryMap -Server $vi
        Write-Host 'Exporting inventory permissions'
        $export.Permissions = @($authMgr.RetrieveAllPermissions() | ForEach-Object {
                $e = $inv.ByKey[$_.Entity.ToString()]
                [ordered]@{
                    EntityPath        = if ($e) { $e.Path } else { $null }
                    EntityType        = $_.Entity.Type
                    EntityName        = if ($e) { $e.Name } else { $null }
                    EntityMoRef       = $_.Entity.Value
                    Principal         = $_.Principal
                    IsGroup           = $_.Group
                    Role              = $roleById[$_.RoleId].Name
                    Propagate         = $_.Propagate
                    IsSystemPrincipal = [bool](Test-RbacSystemPrincipal $_.Principal)
                }
            } | Sort-Object { $_.EntityPath }, { $_.Principal })
    }

    if ('GlobalPermissions' -in $Include) {
        Write-Host 'Exporting global permissions (vCenter MOB)'
        try {
            $export.GlobalPermissions = @(Get-RbacGlobalPermission -Server $Server -Credential $Credential -GlobalDocumentPattern $GlobalDocumentPattern `
                    -RawPath (Join-Path $outDir 'globalpermissions-mob.html') -SkipCertificateCheck:$SkipCertificateCheck | ForEach-Object {
                    [ordered]@{
                        Principal         = $_.Principal
                        IsGroup           = $_.IsGroup
                        Roles             = @($_.RoleIds | ForEach-Object { $roleById[$_].Name })
                        RoleIds           = $_.RoleIds
                        Propagate         = $_.Propagate
                        Scope             = $_.Scope
                        Document          = $_.Document
                        IsSystemPrincipal = [bool](Test-RbacSystemPrincipal $_.Principal)
                    }
                } | Sort-Object { $_.Scope }, { $_.Principal })
        }
        catch {
            Write-Warning "Global permission export failed: $_"
        }
    }

    if ('Sso' -in $Include) {
        Write-Host "Exporting SSO domain $SsoDomain"
        Import-Module VMware.vSphere.SsoAdmin
        $sso = Connect-SsoAdminServer -Server $Server -User $Credential.UserName -Password $Credential.GetNetworkCredential().Password -SkipCertificateCheck:$SkipCertificateCheck

        $users = @(Get-SsoPersonUser -Domain $SsoDomain -Server $sso | Sort-Object Name | ForEach-Object {
                [ordered]@{
                    Name         = $_.Name
                    FirstName    = $_.FirstName
                    LastName     = $_.LastName
                    EmailAddress = $_.EmailAddress
                    Description  = $_.Description
                    Disabled     = $_.Disabled
                    IsSystem     = ($_.Name -in 'Administrator', 'K/M') -or ($_.Name -like 'krbtgt/*') -or ($_.Name -like 'waiter-*') -or [bool](Test-RbacSystemPrincipal $_.Name)
                }
            })

        $groups = @(Get-SsoGroup -Domain $SsoDomain -Server $sso | Sort-Object Name | ForEach-Object {
                $g = $_
                $members = @(
                    Get-SsoPersonUser -Group $g | ForEach-Object { [ordered]@{ Name = $_.Name; Domain = $_.Domain; Type = 'User' } }
                    Get-SsoGroup -Group $g | ForEach-Object { [ordered]@{ Name = $_.Name; Domain = $_.Domain; Type = 'Group' } }
                )
                [ordered]@{ Name = $g.Name; Description = $g.Description; Members = $members }
            })

        $identitySources = @(Get-IdentitySource -Server $sso | ForEach-Object {
                $o = [ordered]@{ Type = $_.GetType().Name }
                foreach ($p in $_.PSObject.Properties) {
                    if ($p.Value -is [string] -or $p.Value -is [ValueType]) { $o[$p.Name] = $p.Value }
                }
                $o
            })

        $identityProviders = $null
        try {
            $token = Invoke-RestMethod -Method Post -Uri "https://$Server/api/session" -Credential $Credential -Authentication Basic -SkipCertificateCheck:$SkipCertificateCheck
            try {
                $identityProviders = Invoke-RestMethod -Uri "https://$Server/api/vcenter/identity/providers" -Headers @{ 'vmware-api-session-id' = $token } -SkipCertificateCheck:$SkipCertificateCheck
            }
            finally {
                $null = Invoke-RestMethod -Method Delete -Uri "https://$Server/api/session" -Headers @{ 'vmware-api-session-id' = $token } -SkipCertificateCheck:$SkipCertificateCheck
            }
        }
        catch {
            Write-Warning "Identity provider (federation) export failed: $_"
        }

        $export.Sso = [ordered]@{
            Domain            = $SsoDomain
            Users             = $users
            Groups            = $groups
            IdentitySources   = $identitySources
            IdentityProviders = $identityProviders
        }
    }
}
finally {
    if ($sso) { Disconnect-SsoAdminServer -Server $sso }
    Disconnect-VIServer -Server $vi -Confirm:$false
}

$export | ConvertTo-Json -Depth 10 | Set-Content -Path (Join-Path $outDir 'rbac-export.json') -Encoding utf8

# Mapping templates
$principals = [System.Collections.Generic.List[string]]::new()
$export.Permissions | Where-Object { -not $_.IsSystemPrincipal } | ForEach-Object { $principals.Add($_.Principal) }
$export.GlobalPermissions | Where-Object { $_.Scope -eq 'Global' -and -not $_.IsSystemPrincipal } | ForEach-Object { $principals.Add($_.Principal) }
if ($export.Sso) {
    foreach ($g in $export.Sso.Groups) {
        foreach ($m in $g.Members) {
            if (-not (Test-RbacSystemPrincipal $m.Name)) { $principals.Add("$($m.Domain)\$($m.Name)") }
        }
    }
}
$principals = $principals | Sort-Object -Unique

$principals | ForEach-Object { [pscustomobject]@{ SourcePrincipal = $_; TargetPrincipal = '' } } |
    Export-Csv -Path (Join-Path $outDir 'principal-map.csv') -NoTypeInformation -Encoding utf8

$principals | ForEach-Object { if ($_ -match '^([^\\]+)\\') { $Matches[1] } elseif ($_ -match '@(.+)$') { $Matches[1] } } |
    Sort-Object -Unique | ForEach-Object { [pscustomobject]@{ SourceDomain = $_; TargetDomain = $_ } } |
    Export-Csv -Path (Join-Path $outDir 'domain-map.csv') -NoTypeInformation -Encoding utf8

$export.Permissions | ForEach-Object { if ($_.EntityPath -match '^/[^/]+') { $Matches[0] } } | Sort-Object -Unique |
    ForEach-Object { [pscustomobject]@{ SourcePath = $_; TargetPath = $_ } } |
    Export-Csv -Path (Join-Path $outDir 'path-map.csv') -NoTypeInformation -Encoding utf8

# HTML report
$enc = { param($s) ConvertTo-RbacHtmlText $s }
$perms = @($export.Permissions | ForEach-Object { [pscustomobject]$_ })
$globals = @($export.GlobalPermissions | ForEach-Object { [pscustomobject]$_ } | Where-Object Scope -eq 'Global')
$customRoles = @($export.Roles | Where-Object { -not $_.IsBuiltIn })
$builtInRoles = @($export.Roles | Where-Object { $_.IsBuiltIn })

$body = [System.Collections.Generic.List[string]]::new()
$body.Add('<nav><a href="#summary">Summary</a><a href="#roles">Roles</a><a href="#usage">Role usage</a><a href="#perms">Inventory permissions</a><a href="#global">Global permissions</a><a href="#principals">Principals</a><a href="#sso">SSO</a><a href="#privs">Custom role privileges</a></nav>')

$body.Add('<h2 id="summary">Summary</h2>')
$summary = [ordered]@{
    'Source vCenter'                = "$Server ($($export.Metadata.FullName))"
    'Exported at'                   = $export.Metadata.ExportedAt
    'SSO domain'                    = $SsoDomain
    'Custom roles'                  = $customRoles.Count
    'Built-in / system roles'       = $builtInRoles.Count
    'Inventory permissions'         = $perms.Count
    'Of which system principals'    = @($perms | Where-Object IsSystemPrincipal).Count
    'Global permissions'            = $globals.Count
    'SSO local users'               = if ($export.Sso) { $export.Sso.Users.Count } else { 'not exported' }
    'SSO groups'                    = if ($export.Sso) { $export.Sso.Groups.Count } else { 'not exported' }
}
$body.Add((ConvertTo-RbacHtmlTable ($summary.GetEnumerator() | ForEach-Object { [pscustomobject]@{ Item = $_.Key; Value = $_.Value } }) Item, Value))

$body.Add('<h2 id="roles">Roles</h2><h3>Custom roles</h3>')
$body.Add((ConvertTo-RbacHtmlTable ($customRoles | ForEach-Object {
                $n = $_.Name
                $invCount = @($perms | Where-Object Role -eq $n).Count
                $glb = @($globals | Where-Object { $n -in $_.Roles }).Count
                [pscustomobject]@{ Name = $n; Privileges = $_.Privileges.Count; InventoryPermissions = $invCount; GlobalPermissions = $glb; Unused = ($invCount + $glb) -eq 0 }
            }) Name, Privileges, InventoryPermissions, GlobalPermissions, Unused))
$body.Add('<h3>Built-in and system roles</h3>')
$body.Add((ConvertTo-RbacHtmlTable ($builtInRoles | ForEach-Object {
                $n = $_.Name
                [pscustomobject]@{ Name = $n; Label = $_.Label; IsSystem = $_.IsSystem; Privileges = $_.Privileges.Count; InventoryPermissions = @($perms | Where-Object Role -eq $n).Count; GlobalPermissions = @($globals | Where-Object { $n -in $_.Roles }).Count }
            }) Name, Label, IsSystem, Privileges, InventoryPermissions, GlobalPermissions))

$body.Add('<h2 id="usage">Where each role is applied</h2>')
$usage = @($perms | ForEach-Object { [pscustomobject]@{ Role = $_.Role; Scope = 'Inventory'; Path = $_.EntityPath; Type = $_.EntityType; Principal = $_.Principal; IsGroup = $_.IsGroup; Propagate = $_.Propagate } }) +
         @($globals | ForEach-Object { $g = $_; $g.Roles | ForEach-Object { [pscustomobject]@{ Role = $_; Scope = 'Global'; Path = '(global)'; Type = ''; Principal = $g.Principal; IsGroup = $g.IsGroup; Propagate = $g.Propagate } } })
foreach ($grp in ($usage | Group-Object Role | Sort-Object Name)) {
    $body.Add("<details><summary>$(& $enc $grp.Name) ($($grp.Count))</summary>")
    $body.Add((ConvertTo-RbacHtmlTable ($grp.Group | Sort-Object Scope, Path) Scope, Path, Type, Principal, IsGroup, Propagate))
    $body.Add('</details>')
}

$body.Add('<h2 id="perms">Inventory permissions</h2>')
$body.Add((ConvertTo-RbacHtmlTable $perms EntityPath, EntityType, Principal, IsGroup, Role, Propagate, IsSystemPrincipal))

$body.Add('<h2 id="global">Global permissions</h2>')
$body.Add((ConvertTo-RbacHtmlTable ($globals | ForEach-Object { [pscustomobject]@{ Principal = $_.Principal; IsGroup = $_.IsGroup; Roles = $_.Roles -join ', '; Propagate = $_.Propagate; IsSystemPrincipal = $_.IsSystemPrincipal } }) Principal, IsGroup, Roles, Propagate, IsSystemPrincipal))
$mobInventory = @($export.GlobalPermissions | Where-Object { $_.Scope -ne 'Global' })
if ($mobInventory) {
    $body.Add("<details><summary>MOB entries classified as non-global ($($mobInventory.Count)) - verify classification</summary>")
    $body.Add((ConvertTo-RbacHtmlTable ($mobInventory | ForEach-Object { [pscustomobject]@{ Principal = $_.Principal; Roles = $_.Roles -join ', '; Document = $_.Document } }) Principal, Roles, Document))
    $body.Add('</details>')
}

$body.Add('<h2 id="principals">Principals</h2>')
$body.Add((ConvertTo-RbacHtmlTable ($usage | Group-Object Principal | Sort-Object Name | ForEach-Object {
                [pscustomobject]@{
                    Principal   = $_.Name
                    IsGroup     = $_.Group[0].IsGroup
                    Assignments = ($_.Group | ForEach-Object { "$($_.Role) @ $($_.Path)" }) -join '; '
                }
            }) Principal, IsGroup, Assignments))

$body.Add('<h2 id="sso">SSO</h2>')
if ($export.Sso) {
    $body.Add("<h3>Local users ($(& $enc $SsoDomain))</h3>")
    $body.Add((ConvertTo-RbacHtmlTable ($export.Sso.Users | ForEach-Object { [pscustomobject]$_ }) Name, FirstName, LastName, EmailAddress, Disabled, IsSystem))
    $body.Add('<h3>Groups and members</h3>')
    $body.Add((ConvertTo-RbacHtmlTable ($export.Sso.Groups | ForEach-Object {
                    [pscustomobject]@{ Group = $_.Name; Description = $_.Description; Members = ($_.Members | ForEach-Object { "$($_.Domain)\$($_.Name) [$($_.Type)]" }) -join '; ' }
                }) Group, Description, Members))
    $body.Add('<h3>Identity sources</h3>')
    $body.Add((ConvertTo-RbacHtmlTable ($export.Sso.IdentitySources | ForEach-Object { [pscustomobject]@{ Type = $_.Type; Name = $_.Name; Details = (($_.GetEnumerator() | Where-Object { $_.Key -notin 'Type', 'Name' } | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '; ') } }) Type, Name, Details))
    $body.Add('<h3>Identity providers (federation)</h3>')
    $body.Add("<pre>$(& $enc ($export.Sso.IdentityProviders | ConvertTo-Json -Depth 8))</pre>")
}
else {
    $body.Add('<p class="muted">Not exported</p>')
}

$body.Add('<h2 id="privs">Custom role privileges</h2>')
foreach ($r in $customRoles) {
    $body.Add("<details><summary>$(& $enc $r.Name) ($($r.Privileges.Count))</summary>")
    $body.Add((ConvertTo-RbacHtmlTable ($r.Privileges | ForEach-Object {
                    [pscustomobject]@{ Group = $privInfo[$_].PrivGroupName; Privilege = $_; Label = $privLabel[$_] }
                } | Sort-Object Group, Privilege) Group, Privilege, Label))
    $body.Add('</details>')
}

New-RbacHtmlPage -Title "vCenter RBAC report - $Server" -Body $body | Set-Content -Path (Join-Path $outDir 'rbac-report.html') -Encoding utf8

Write-Host "Export written to $outDir"
Get-Item $outDir
