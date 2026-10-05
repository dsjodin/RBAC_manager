#Requires -Version 7.2
<#
.SYNOPSIS
    Rebuilds an exported RBAC configuration on a target vCenter Server.
.DESCRIPTION
    Reads rbac-export.json from Export-VcRbac.ps1 and applies it in merge mode:
    creates missing SSO users/groups/memberships, roles, global permissions and
    inventory permissions, and updates custom roles and permissions that differ.
    Nothing is ever removed from the target. Use -WhatIf for a dry run.
    Principals are remapped with -DomainMap / -PrincipalMap, inventory paths with -PathMap.
.EXAMPLE
    ./Import-VcRbac.ps1 -Server vc02.corp.local -Credential $cred -InputFile ./rbac-vc01/rbac-export.json `
        -DomainMap ./rbac-vc01/domain-map.csv -PrincipalMap ./rbac-vc01/principal-map.csv -PathMap ./rbac-vc01/path-map.csv -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$Server,
    [Parameter(Mandatory)][pscredential]$Credential,
    [Parameter(Mandatory)][string]$InputFile,
    [string]$DomainMap,
    [string]$PrincipalMap,
    [string]$PathMap,
    [ValidateSet('Sso', 'Roles', 'GlobalPermissions', 'Permissions')]
    [string[]]$Include = @('Sso', 'Roles', 'GlobalPermissions', 'Permissions'),
    [securestring]$SsoUserPassword,
    [string]$GlobalDocumentPattern = 'global',
    [string]$ReportPath = '.',
    [switch]$SkipCertificateCheck
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'RbacCommon.psm1') -Force

$cmdlet = $PSCmdlet
$data = Get-Content -Path $InputFile -Raw | ConvertFrom-Json

$domainMapTable = @{}
if ($DomainMap) {
    foreach ($row in Import-Csv $DomainMap) { if ($row.TargetDomain) { $domainMapTable[$row.SourceDomain] = $row.TargetDomain } }
}
$principalMapTable = @{}
if ($PrincipalMap) {
    foreach ($row in Import-Csv $PrincipalMap) { if ($row.TargetPrincipal) { $principalMapTable[$row.SourcePrincipal] = $row.TargetPrincipal } }
}
$pathMapRows = @()
if ($PathMap) {
    $pathMapRows = @(Import-Csv $PathMap | Where-Object { $_.SourcePath -and $_.TargetPath } | Sort-Object { $_.SourcePath.Length } -Descending)
}

# Per-principal map wins (TargetPrincipal = SKIP drops it), then domain map, else unchanged.
function Convert-Principal([string]$Principal) {
    if ($principalMapTable.ContainsKey($Principal)) {
        $t = $principalMapTable[$Principal]
        if ($t -eq 'SKIP') { return $null }
        return $t
    }
    if ($Principal -match '^([^\\]+)\\(.+)$' -and $domainMapTable.ContainsKey($Matches[1])) { return "$($domainMapTable[$Matches[1]])\$($Matches[2])" }
    if ($Principal -match '^(.+)@([^@]+)$' -and $domainMapTable.ContainsKey($Matches[2])) { return "$($Matches[1])@$($domainMapTable[$Matches[2]])" }
    $Principal
}

# Longest SourcePath prefix wins.
function Convert-EntityPath([string]$Path) {
    foreach ($row in $pathMapRows) {
        if ($Path -eq $row.SourcePath -or $Path.StartsWith("$($row.SourcePath)/", [StringComparison]::OrdinalIgnoreCase)) {
            return $row.TargetPath + $Path.Substring($row.SourcePath.Length)
        }
    }
    $Path
}

$results = [System.Collections.Generic.List[object]]::new()
function Add-Result($Section, $Action, $Object, $Detail, $Result = '') {
    $results.Add([pscustomobject]@{ Section = $Section; Action = $Action; Object = $Object; Detail = $Detail; Result = $Result })
}
function Invoke-Change($Section, $Action, $Object, $Detail, [scriptblock]$Change) {
    if ($cmdlet.ShouldProcess($Object, "$Section $Action")) {
        try {
            & $Change
            Add-Result $Section $Action $Object $Detail 'Done'
        }
        catch {
            Add-Result $Section $Action $Object $Detail "Failed: $($_.Exception.Message)"
        }
    }
    else {
        Add-Result $Section $Action $Object $Detail 'WhatIf'
    }
}

if ($SkipCertificateCheck) {
    $null = Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Scope Session -Confirm:$false -WhatIf:$false
}
$vi = Connect-VIServer -Server $Server -Credential $Credential
$sso = $null

try {
    $si = Get-View ServiceInstance -Server $vi
    $authMgr = Get-View $si.Content.AuthorizationManager -Server $vi
    $userDir = Get-View $si.Content.UserDirectory -Server $vi

    $principalCache = @{}
    function Test-TargetPrincipal([string]$Principal, [bool]$IsGroup) {
        if ($principalCache.ContainsKey($Principal)) { return $principalCache[$Principal] }
        $found = 'Unknown'
        if ($Principal -match '^([^\\]+)\\(.+)$') {
            try { $found = [bool]$userDir.RetrieveUserGroups($Matches[1], $Matches[2], $null, $null, $true, -not $IsGroup, $IsGroup) } catch { }
        }
        $principalCache[$Principal] = $found
        $found
    }

    # SSO users, groups and memberships first, so principals exist before permissions reference them
    if ('Sso' -in $Include -and $data.Sso) {
        Import-Module VMware.vSphere.SsoAdmin
        $sso = Connect-SsoAdminServer -Server $Server -User $Credential.UserName -Password $Credential.GetNetworkCredential().Password -SkipCertificateCheck:$SkipCertificateCheck
        $srcSso = $data.Sso.Domain
        $tgtSso = if ($domainMapTable.ContainsKey($srcSso)) { $domainMapTable[$srcSso] } else { $srcSso }
        $plainPassword = if ($SsoUserPassword) { [System.Net.NetworkCredential]::new('', $SsoUserPassword).Password }

        foreach ($u in @($data.Sso.Users | Where-Object { -not $_.IsSystem })) {
            $obj = "$tgtSso\$($u.Name)"
            if (Get-SsoPersonUser -Name $u.Name -Domain $tgtSso -Server $sso | Where-Object Name -eq $u.Name) {
                Add-Result 'SsoUser' 'NoChange' $obj 'Exists'
                continue
            }
            if (-not $plainPassword) {
                Add-Result 'SsoUser' 'Skip' $obj 'Missing on target; pass -SsoUserPassword to create'
                continue
            }
            $newUser = @{ UserName = $u.Name; Password = $plainPassword; Server = $sso }
            foreach ($k in 'FirstName', 'LastName', 'EmailAddress', 'Description') { if ($u.$k) { $newUser[$k] = $u.$k } }
            $uName = $u.Name
            $uDisabled = [bool]$u.Disabled
            Invoke-Change 'SsoUser' 'Create' $obj "Disabled=$uDisabled; initial password from -SsoUserPassword" {
                $null = New-SsoPersonUser @newUser
                if ($uDisabled) {
                    $null = Get-SsoPersonUser -Name $uName -Domain $tgtSso -Server $sso | Where-Object Name -eq $uName | Set-SsoPersonUser -Enable $false
                }
            }
        }

        foreach ($g in @($data.Sso.Groups)) {
            $obj = "$tgtSso\$($g.Name)"
            $gName = $g.Name
            $gDescription = [string]$g.Description
            $tg = Get-SsoGroup -Name $gName -Domain $tgtSso -Server $sso | Where-Object Name -eq $gName
            if ($tg) {
                Add-Result 'SsoGroup' 'NoChange' $obj 'Exists'
            }
            else {
                Invoke-Change 'SsoGroup' 'Create' $obj $gDescription { $null = New-SsoGroup -Name $gName -Description $gDescription -Server $sso }
                $tg = Get-SsoGroup -Name $gName -Domain $tgtSso -Server $sso | Where-Object Name -eq $gName
            }

            $currentMembers = @{}
            if ($tg) {
                Get-SsoPersonUser -Group $tg | ForEach-Object { $currentMembers["$($_.Domain)\$($_.Name)"] = $true }
                Get-SsoGroup -Group $tg | ForEach-Object { $currentMembers["$($_.Domain)\$($_.Name)"] = $true }
            }

            foreach ($m in @($g.Members)) {
                $src = "$($m.Domain)\$($m.Name)"
                if (Test-RbacSystemPrincipal $src) {
                    Add-Result 'SsoMember' 'Skip' "$obj <- $src" 'System principal'
                    continue
                }
                $mapped = Convert-Principal $src
                if (-not $mapped) {
                    Add-Result 'SsoMember' 'Skip' "$obj <- $src" 'Principal mapped to SKIP'
                    continue
                }
                if ($currentMembers.ContainsKey($mapped)) {
                    Add-Result 'SsoMember' 'NoChange' "$obj <- $mapped" $m.Type
                    continue
                }
                if ($mapped -match '^([^\\]+)\\(.+)$') { $mDomain = $Matches[1]; $mName = $Matches[2] }
                else { $null = $mapped -match '^(.+)@([^@]+)$'; $mName = $Matches[1]; $mDomain = $Matches[2] }
                $mType = $m.Type
                Invoke-Change 'SsoMember' 'Add' "$obj <- $mapped" $mType {
                    if (-not $tg) { throw "Group $obj not found on target" }
                    if ($mType -eq 'User') {
                        $member = Get-SsoPersonUser -Name $mName -Domain $mDomain -Server $sso | Where-Object Name -eq $mName
                        if (-not $member) { throw "User $mapped not found" }
                        $null = Add-UserToSsoGroup -User $member -TargetGroup $tg
                    }
                    else {
                        $member = Get-SsoGroup -Name $mName -Domain $mDomain -Server $sso | Where-Object Name -eq $mName
                        if (-not $member) { throw "Group $mapped not found" }
                        $null = Add-GroupToSsoGroup -Group $member -TargetGroup $tg
                    }
                }
            }
        }
    }

    # Roles: create missing, set custom roles to the exact source privilege set. Built-in roles are never modified.
    $pendingRoles = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    if ('Roles' -in $Include) {
        $targetRoles = @{}
        foreach ($r in $authMgr.RoleList) { $targetRoles[$r.Name] = $r }
        $targetPrivs = [System.Collections.Generic.HashSet[string]]::new([string[]]@($authMgr.PrivilegeList.PrivId))

        foreach ($role in @($data.Roles | Where-Object { -not $_.IsSystem })) {
            $privs = [string[]]@($role.Privileges | Where-Object { $targetPrivs.Contains($_) })
            $unknown = @($role.Privileges | Where-Object { -not $targetPrivs.Contains($_) })
            if ($unknown) { Add-Result 'Role' 'Warning' $role.Name "Privileges not present on target, dropped: $($unknown -join ', ')" }

            $t = $targetRoles[$role.Name]
            if (-not $t) {
                if ($role.IsBuiltIn) {
                    Add-Result 'Role' 'Skip' $role.Name 'Built-in role not present on target'
                    continue
                }
                $rName = $role.Name
                Invoke-Change 'Role' 'Create' $rName "$($privs.Count) privileges" { $null = $authMgr.AddAuthorizationRole($rName, $privs) }
                $null = $pendingRoles.Add($rName)
                continue
            }

            $tSet = [System.Collections.Generic.HashSet[string]]::new([string[]]@($t.Privilege))
            $sSet = [System.Collections.Generic.HashSet[string]]::new($privs)
            $added = @($privs | Where-Object { -not $tSet.Contains($_) })
            $removed = @($t.Privilege | Where-Object { -not $sSet.Contains($_) })
            if (-not $added -and -not $removed) {
                Add-Result 'Role' 'NoChange' $role.Name ''
                continue
            }
            $detail = "Add: $($added -join ', ') | Remove: $($removed -join ', ')"
            if ($role.IsBuiltIn -or (Test-RbacBuiltInRole $t)) {
                Add-Result 'Role' 'Skip' $role.Name "Built-in role differs, not modified. $detail"
                continue
            }
            $tRole = $t
            Invoke-Change 'Role' 'Update' $role.Name $detail { $authMgr.UpdateAuthorizationRole($tRole.RoleId, $tRole.Name, $privs) }
        }
        $authMgr.UpdateViewData('RoleList')
    }

    $roleIdByName = @{}
    $roleNameById = @{}
    foreach ($r in $authMgr.RoleList) { $roleIdByName[$r.Name] = $r.RoleId; $roleNameById[$r.RoleId] = $r.Name }

    if ('GlobalPermissions' -in $Include) {
        $targetGlobal = $null
        try {
            $targetGlobal = @(Get-RbacGlobalPermission -Server $Server -Credential $Credential -GlobalDocumentPattern $GlobalDocumentPattern -SkipCertificateCheck:$SkipCertificateCheck |
                    Where-Object Scope -eq 'Global')
        }
        catch {
            Add-Result 'GlobalPermission' 'Error' $Server "Cannot read target global permissions: $($_.Exception.Message)"
        }

        if ($null -ne $targetGlobal) {
            $targetGlobalIdx = @{}
            foreach ($tgp in $targetGlobal) { $targetGlobalIdx[$tgp.Principal] = $tgp }

            foreach ($gp in @($data.GlobalPermissions | Where-Object Scope -eq 'Global')) {
                if ($gp.IsSystemPrincipal) {
                    Add-Result 'GlobalPermission' 'Skip' $gp.Principal 'System principal'
                    continue
                }
                $gPrincipal = Convert-Principal $gp.Principal
                if (-not $gPrincipal) {
                    Add-Result 'GlobalPermission' 'Skip' $gp.Principal 'Principal mapped to SKIP'
                    continue
                }
                $missingRoles = @($gp.Roles | Where-Object { -not $roleIdByName.ContainsKey($_) -and -not $pendingRoles.Contains($_) })
                if ($missingRoles) {
                    Add-Result 'GlobalPermission' 'Missing' $gPrincipal "Role not on target: $($missingRoles -join ', ')"
                    continue
                }
                $gRoleIds = [int[]]@($gp.Roles | ForEach-Object { $roleIdByName[$_] })
                $gGroup = [bool]$gp.IsGroup
                $gPropagate = [bool]$gp.Propagate
                $cur = $targetGlobalIdx[$gPrincipal]
                if ($cur -and (($cur.RoleIds | Sort-Object) -join ',') -eq (($gRoleIds | Sort-Object) -join ',') -and $cur.Propagate -eq $gPropagate) {
                    Add-Result 'GlobalPermission' 'NoChange' $gPrincipal "Roles=$($gp.Roles -join ', ')"
                    continue
                }
                $action = if ($cur) { 'Update' } else { 'Create' }
                $detail = "Roles=$($gp.Roles -join ', ') Propagate=$gPropagate PrincipalFound=$(Test-TargetPrincipal $gPrincipal $gGroup)"
                if ($cur) { $detail += " (was Roles=$(($cur.RoleIds | ForEach-Object { $roleNameById[$_] }) -join ', ') Propagate=$($cur.Propagate))" }
                Invoke-Change 'GlobalPermission' $action $gPrincipal $detail {
                    Add-RbacGlobalPermission -Server $Server -Credential $Credential -Principal $gPrincipal -IsGroup $gGroup -RoleIds $gRoleIds -Propagate $gPropagate -SkipCertificateCheck:$SkipCertificateCheck
                }
            }
        }
    }

    if ('Permissions' -in $Include) {
        $inv = Get-RbacInventoryMap -Server $vi
        $existing = @{}
        foreach ($p in $authMgr.RetrieveAllPermissions()) { $existing["$($p.Entity.ToString())|$($p.Principal)"] = $p }

        foreach ($perm in @($data.Permissions)) {
            $srcLabel = "$($perm.EntityPath) [$($perm.EntityType)] $($perm.Principal)"
            if ($perm.IsSystemPrincipal) {
                Add-Result 'Permission' 'Skip' $srcLabel 'System principal'
                continue
            }
            if (-not $perm.EntityPath) {
                Add-Result 'Permission' 'Missing' $srcLabel 'Entity path was not resolved at export'
                continue
            }
            $principal = Convert-Principal $perm.Principal
            if (-not $principal) {
                Add-Result 'Permission' 'Skip' $srcLabel 'Principal mapped to SKIP'
                continue
            }
            $path = Convert-EntityPath $perm.EntityPath
            $obj = "$path [$($perm.EntityType)] $principal"
            $entity = $inv.ByTypePath["$($perm.EntityType)|$path"]
            if (-not $entity) {
                Add-Result 'Permission' 'Missing' $obj 'Entity not found on target'
                continue
            }
            $roleId = $roleIdByName[$perm.Role]
            if ($null -eq $roleId -and -not $pendingRoles.Contains($perm.Role)) {
                Add-Result 'Permission' 'Missing' $obj "Role '$($perm.Role)' not on target"
                continue
            }
            $cur = $existing["$($entity.MoRef.ToString())|$principal"]
            if ($cur -and $cur.RoleId -eq $roleId -and $cur.Propagate -eq [bool]$perm.Propagate) {
                Add-Result 'Permission' 'NoChange' $obj "Role=$($perm.Role)"
                continue
            }
            $action = if ($cur) { 'Update' } else { 'Create' }
            $detail = "Role=$($perm.Role) Propagate=$($perm.Propagate) PrincipalFound=$(Test-TargetPrincipal $principal ([bool]$perm.IsGroup))"
            if ($cur) { $detail += " (was Role=$($roleNameById[$cur.RoleId]) Propagate=$($cur.Propagate))" }
            $vimPermission = New-Object VMware.Vim.Permission -Property @{
                Principal = $principal
                Group     = [bool]$perm.IsGroup
                RoleId    = [int]$roleId
                Propagate = [bool]$perm.Propagate
            }
            $moRef = $entity.MoRef
            Invoke-Change 'Permission' $action $obj $detail { $authMgr.SetEntityPermissions($moRef, @($vimPermission)) }
        }
    }
}
finally {
    if ($sso) { Disconnect-SsoAdminServer -Server $sso }
    Disconnect-VIServer -Server $vi -Confirm:$false -WhatIf:$false
}

$null = New-Item -ItemType Directory -Path $ReportPath -Force -WhatIf:$false
$mode = if ($WhatIfPreference) { 'whatif' } else { 'apply' }
$reportBase = Join-Path $ReportPath ("rbac-import-{0}-{1}-{2}" -f $Server, $mode, (Get-Date -Format 'yyyyMMdd-HHmmss'))
$results | ConvertTo-Json -Depth 4 | Set-Content -Path "$reportBase.json" -Encoding utf8 -WhatIf:$false

$summaryRows = $results | Group-Object Section, Action, Result | Sort-Object Name | ForEach-Object {
    [pscustomobject]@{ Section = $_.Group[0].Section; Action = $_.Group[0].Action; Result = $_.Group[0].Result; Count = $_.Count }
}
$body = @(
    "<p>Source: $(ConvertTo-RbacHtmlText $data.Metadata.SourceServer) ($(ConvertTo-RbacHtmlText $data.Metadata.FullName)), exported $(ConvertTo-RbacHtmlText $data.Metadata.ExportedAt)<br>Target: $(ConvertTo-RbacHtmlText $Server)<br>Mode: $mode</p>"
    '<h2>Summary</h2>'
    (ConvertTo-RbacHtmlTable $summaryRows Section, Action, Result, Count)
    '<h2>Changes, warnings and missing objects</h2>'
    (ConvertTo-RbacHtmlTable ($results | Where-Object { $_.Action -notin 'NoChange', 'Skip' }) Section, Action, Object, Detail, Result)
    '<h2>Skipped</h2>'
    (ConvertTo-RbacHtmlTable ($results | Where-Object Action -eq 'Skip') Section, Object, Detail)
    '<details><summary>No change</summary>'
    (ConvertTo-RbacHtmlTable ($results | Where-Object Action -eq 'NoChange') Section, Object, Detail)
    '</details>'
)
New-RbacHtmlPage -Title "vCenter RBAC import - $Server ($mode)" -Body $body | Set-Content -Path "$reportBase.html" -Encoding utf8 -WhatIf:$false

$summaryRows | Format-Table -AutoSize | Out-Host
Write-Host "Report written to $reportBase.html"
