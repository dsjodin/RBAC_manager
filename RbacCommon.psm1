# Shared helpers for Export-VcRbac.ps1 and Import-VcRbac.ps1

$script:BuiltInRoleNames = @(
    'NoAccess', 'Anonymous', 'View', 'ReadOnly', 'Admin', 'NoCryptoAdmin', 'NoTrustedAdmin', 'TrustedAdmin',
    'VirtualMachinePowerUser', 'VirtualMachineUser', 'ResourcePoolAdministrator', 'VMwareConsolidatedBackupUser',
    'DatastoreConsumer', 'NetworkConsumer', 'VirtualMachineConsoleUser', 'InventoryService.Tagging.TaggingAdmin',
    'com.vmware.Content.Admin', 'com.vmware.Content.Registry.Admin', 'SyncUsers', 'AutoUpdateUser',
    'vStatsAdmin', 'vStatsUser', 'WorkloadStorageManagement', 'vSphereKubernetesManager',
    'VMOperatorController', 'VMOperatorControllerManager', 'vSphereClientSolutionUsers',
    'NsxAdministrator', 'NsxAuditor', 'NsxViAdministrator', 'SupervisorServicesManager'
)

$script:GuidPattern = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'

# System, sample and solution roles are vendor managed. Custom roles have Label == Name.
function Test-RbacBuiltInRole {
    param([Parameter(Mandatory)]$Role)
    $Role.System -or ($Role.Name -in $script:BuiltInRoleNames) -or ($Role.Info.Label -and $Role.Info.Label -ne $Role.Name)
}

# Solution users and machine accounts are tied to one vCenter instance and must never be copied.
function Test-RbacSystemPrincipal {
    param([Parameter(Mandatory)][string]$Principal)
    $Principal -match $script:GuidPattern
}

# Returns ByKey (MoRef string -> entity) and ByTypePath ("Type|/path" -> entity).
function Get-RbacInventoryMap {
    param([Parameter(Mandatory)]$Server)

    $si = Get-View ServiceInstance -Server $Server
    $rootKey = $si.Content.RootFolder.ToString()
    $viewMgr = Get-View $si.Content.ViewManager -Server $Server
    $cv = Get-View ($viewMgr.CreateContainerView($si.Content.RootFolder, [string[]]@('ManagedEntity'), $true)) -Server $Server
    try {
        $views = @()
        if ($cv.View) { $views = @(Get-View -Id $cv.View -Property Name, Parent -Server $Server) }
    }
    finally { $cv.DestroyView() }

    $raw = @{}
    foreach ($v in $views) {
        $parent = $v.Parent
        if (-not $parent -and $v.MoRef.Type -eq 'VirtualMachine') {
            $parent = (Get-View -Id $v.MoRef -Property ParentVApp -Server $Server).ParentVApp
        }
        $raw[$v.MoRef.ToString()] = @{ Name = $v.Name; Parent = if ($parent) { $parent.ToString() }; MoRef = $v.MoRef }
    }

    $paths = @{ $rootKey = '/' }
    $resolve = {
        param($key)
        $chain = [System.Collections.Generic.List[string]]::new()
        while (-not $paths.ContainsKey($key) -and $raw.ContainsKey($key)) {
            $chain.Insert(0, $key)
            $key = $raw[$key].Parent
        }
        $base = if ($paths.ContainsKey($key)) { $paths[$key] } else { '/?' }
        foreach ($k in $chain) {
            $base = if ($base -eq '/') { "/$($raw[$k].Name)" } else { "$base/$($raw[$k].Name)" }
            $paths[$k] = $base
        }
    }

    $byKey = @{}
    $byTypePath = @{}
    $rootEntity = [pscustomobject]@{ Path = '/'; Type = 'Folder'; Name = (Get-View $si.Content.RootFolder -Property Name -Server $Server).Name; MoRef = $si.Content.RootFolder }
    $byKey[$rootKey] = $rootEntity
    $byTypePath["Folder|/"] = $rootEntity
    foreach ($key in $raw.Keys) {
        & $resolve $key
        $e = [pscustomobject]@{ Path = $paths[$key]; Type = $raw[$key].MoRef.Type; Name = $raw[$key].Name; MoRef = $raw[$key].MoRef }
        $byKey[$key] = $e
        $byTypePath["$($e.Type)|$($e.Path)"] = $e
    }
    @{ ByKey = $byKey; ByTypePath = $byTypePath }
}

# Global permissions have no public API. They are read and written through the
# private authorization service exposed by the vCenter MOB (/invsvc/mob3).
function Invoke-RbacMobMethod {
    param(
        [Parameter(Mandatory)][string]$Server,
        [Parameter(Mandatory)][pscredential]$Credential,
        [Parameter(Mandatory)][string]$Method,
        [string]$Body,
        [switch]$SkipCertificateCheck
    )
    $url = "https://$Server/invsvc/mob3/?moid=authorizationService&method=AuthorizationService.$Method"
    $common = @{ SkipCertificateCheck = $SkipCertificateCheck.IsPresent }

    $page = Invoke-WebRequest -Uri $url -Credential $Credential -SessionVariable mob -Method Get @common
    if ($page.Content -notmatch 'name="vmware-session-nonce" type="hidden" value="?([^\s"]+)"') {
        throw "MOB login failed or vmware-session-nonce not found at $url"
    }
    $form = "vmware-session-nonce=$([uri]::EscapeDataString($Matches[1]))"
    if ($Body) { $form += "&$Body" }
    try {
        $content = (Invoke-WebRequest -Uri $url -WebSession $mob -Method Post -Body $form -ContentType 'application/x-www-form-urlencoded' @common).Content
    }
    finally {
        $null = Invoke-WebRequest -Uri "https://$Server/invsvc/mob3/logout" -WebSession $mob -Method Get @common
    }
    if ($content -match '(?i)faultCause|faultMessage') {
        $text = [System.Net.WebUtility]::HtmlDecode(($content -replace '<[^>]+>', ' ' -replace '\s+', ' ')).Trim()
        throw "MOB $Method returned a fault: $($text.Substring(0, [Math]::Min(800, $text.Length)))"
    }
    $content
}

# Parses AuthorizationService.GetAllPermissions output. Each ACL entry carries
# principal name, group, roles and propagate. The 'document' field follows the
# ACL entries it belongs to and tells global ACLs apart from inventory ACLs.
function Get-RbacGlobalPermission {
    param(
        [Parameter(Mandatory)][string]$Server,
        [Parameter(Mandatory)][pscredential]$Credential,
        [string]$GlobalDocumentPattern = 'global',
        [string]$RawPath,
        [switch]$SkipCertificateCheck
    )
    $html = Invoke-RbacMobMethod -Server $Server -Credential $Credential -Method GetAllPermissions -SkipCertificateCheck:$SkipCertificateCheck
    if ($RawPath) { Set-Content -Path $RawPath -Value $html -Encoding utf8 }

    $field = '(?s)<td class="c2">(?<f>name|group|roles|propagate|document)</td>\s*<td class="c1">[^<]*</td>\s*<td>(?<v>.*?)</td>'
    $entries = [System.Collections.Generic.List[object]]::new()
    $pending = [System.Collections.Generic.List[object]]::new()
    $current = $null
    foreach ($m in [regex]::Matches($html, $field)) {
        $value = [System.Net.WebUtility]::HtmlDecode(($m.Groups['v'].Value -replace '<[^>]+>', ' ')).Trim().Trim('"').Trim()
        switch ($m.Groups['f'].Value) {
            'name' {
                $current = [pscustomobject]@{ Principal = $value; IsGroup = $false; RoleIds = @(); Propagate = $true; Document = $null; Scope = $null }
                $entries.Add($current)
                $pending.Add($current)
            }
            'group' { if ($current) { $current.IsGroup = $value -eq 'true' } }
            'propagate' { if ($current) { $current.Propagate = $value -eq 'true' } }
            'roles' {
                if ($current) { $current.RoleIds = @([regex]::Matches($m.Groups['v'].Value, '<li>\s*(-?\d+)\s*</li>') | ForEach-Object { [int]$_.Groups[1].Value }) }
            }
            'document' {
                foreach ($p in $pending) { $p.Document = $value }
                $pending.Clear()
            }
        }
    }
    foreach ($e in $entries) { $e.Scope = if ($e.Document -match $GlobalDocumentPattern) { 'Global' } else { 'Inventory' } }
    $entries
}

function Add-RbacGlobalPermission {
    param(
        [Parameter(Mandatory)][string]$Server,
        [Parameter(Mandatory)][pscredential]$Credential,
        [Parameter(Mandatory)][string]$Principal,
        [Parameter(Mandatory)][bool]$IsGroup,
        [Parameter(Mandatory)][int[]]$RoleIds,
        [Parameter(Mandatory)][bool]$Propagate,
        [switch]$SkipCertificateCheck
    )
    $roles = ($RoleIds | ForEach-Object { "<roles>$_</roles>" }) -join ''
    $xml = "<permissions><principal><name>$([System.Security.SecurityElement]::Escape($Principal))</name><group>$($IsGroup.ToString().ToLower())</group></principal>$roles<propagate>$($Propagate.ToString().ToLower())</propagate></permissions>"
    $null = Invoke-RbacMobMethod -Server $Server -Credential $Credential -Method AddGlobalAccessControlList -Body "permissions=$([uri]::EscapeDataString($xml))" -SkipCertificateCheck:$SkipCertificateCheck
}

function ConvertTo-RbacHtmlTable {
    param($Rows, [string[]]$Property)
    if (-not $Rows) { return '<p class="muted">None</p>' }
    ($Rows | ConvertTo-Html -Fragment -Property $Property) -join "`n"
}

function New-RbacHtmlPage {
    param([string]$Title, [string[]]$Body)
    $t = [System.Net.WebUtility]::HtmlEncode($Title)
    @"
<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>$t</title>
<style>
body { font-family: Segoe UI, Arial, sans-serif; font-size: 13px; margin: 24px; color: #222; background: #fff; }
h1 { font-size: 22px; } h2 { font-size: 17px; margin-top: 32px; border-bottom: 2px solid #1d6fa5; padding-bottom: 4px; } h3 { font-size: 14px; margin-top: 18px; }
table { border-collapse: collapse; margin: 8px 0 16px 0; }
th, td { border: 1px solid #ccc; padding: 4px 8px; text-align: left; vertical-align: top; }
th { background: #eef3f7; }
tr:nth-child(even) td { background: #fafafa; }
.muted { color: #888; } pre { background: #f5f5f5; padding: 8px; overflow-x: auto; }
details { margin: 4px 0; } summary { cursor: pointer; font-weight: 600; }
nav a { margin-right: 12px; }
</style></head><body>
<h1>$t</h1>
$($Body -join "`n")
</body></html>
"@
}

function ConvertTo-RbacHtmlText {
    param([string]$Text)
    [System.Net.WebUtility]::HtmlEncode($Text)
}

Export-ModuleMember -Function *-Rbac*
