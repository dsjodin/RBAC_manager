# RBAC_manager

PowerCLI scripts that document the RBAC setup of a vCenter Server and rebuild it on another vCenter.

| File | Purpose |
|---|---|
| `Export-VcRbac.ps1` | Reads RBAC from a source vCenter. Writes JSON, an HTML report and mapping templates. |
| `Import-VcRbac.ps1` | Applies the export to a target vCenter in merge mode. Supports `-WhatIf`. |
| `RbacCommon.psm1` | Shared helpers: inventory path map, global permissions via MOB, HTML. |

## Requirements

- PowerShell 7.2+
- VCF.PowerCLI 9.x (or VMware.PowerCLI 13.x)
- VMware.vSphere.SsoAdmin (only for the `Sso` section)
- An SSO administrator account (e.g. `administrator@vsphere.local`). Global permissions and SSO need it.
- Source: vCenter 8.x. Target: vCenter 8.x or 9.x.

```powershell
Install-Module VCF.PowerCLI, VMware.vSphere.SsoAdmin -Scope CurrentUser
```

## What is covered

| Section | Export | Import |
|---|---|---|
| Roles | All roles, privileges, system/built-in flag | Creates missing custom roles. Sets existing custom roles to the source privilege set. Built-in and system roles are never changed. |
| Inventory permissions | Every explicit permission with entity path, type, principal, role, propagate | Creates missing, updates differing role/propagate. Matches entities by type + path after path remapping. |
| Global permissions | Read from the vCenter MOB (`/invsvc/mob3`, private API) | Added through the same MOB endpoint. Roles are matched by name, not ID. |
| Sso | Local users and groups in the SSO domain, group members, identity sources, identity providers (federation) | Creates missing groups and memberships. Local users only with `-SsoUserPassword`. Identity sources and providers are documentation only. |

Nothing is ever deleted on the target.

Not covered: permissions on tags/categories, content libraries and other objects outside the vpxd inventory; identity source and ADFS configuration (set these up on the target first); local SSO user passwords.

## Workflow

### 1. Export from the source

```powershell
$cred = Get-Credential administrator@vsphere.local
./Export-VcRbac.ps1 -Server vc-old.corp.local -Credential $cred -OutputPath ./exports -SkipCertificateCheck
```

Output folder `./exports/rbac-<server>-<timestamp>/`:

| File | Content |
|---|---|
| `rbac-export.json` | Full export, input for the import |
| `rbac-report.html` | Documentation: roles, where each role is applied, permissions, global permissions, principals, SSO, privileges per custom role |
| `domain-map.csv` | `SourceDomain,TargetDomain` - prefilled 1:1 |
| `principal-map.csv` | `SourcePrincipal,TargetPrincipal` - one row per principal, target empty |
| `path-map.csv` | `SourcePath,TargetPath` - prefilled with datacenters 1:1 |
| `globalpermissions-mob.html` | Raw MOB response, for verifying global permission parsing |

### 2. Review and edit the mapping files

**Principals** are resolved in this order:

1. `principal-map.csv`: if `TargetPrincipal` is set it is used. `SKIP` drops the principal.
2. `domain-map.csv`: the domain part is replaced. Works for `DOMAIN\name` and `name@domain`.
3. Unchanged.

Example for a move from integrated AD to ADFS where the domain is written differently:

```csv
SourceDomain,TargetDomain
CORP,corp.example.com
VSPHERE.LOCAL,VSPHERE.LOCAL
```

Exceptions (renamed groups, groups not synced to ADFS) go in `principal-map.csv`:

```csv
SourcePrincipal,TargetPrincipal
CORP\vc-old-admins,corp.example.com\vc-admins
CORP\legacy-svc,SKIP
```

The SSO domain itself is also remapped through `domain-map.csv` (e.g. `vsphere.local` -> `vsphere.corp`).

**Inventory paths** look like `/DC1/host/Cluster01`, `/DC1/vm/Prod/App01`, `/DC1/network/dvs-01`. The root folder is `/`. The longest matching `SourcePath` prefix is replaced:

```csv
SourcePath,TargetPath
/DC1,/DC-NEW
/DC1/vm/Prod,/DC-NEW/vm/Production
/DC1/host/Cluster01/esx01.corp.local,/DC-NEW/host/CL01/esx101.corp.local
```

### 3. Dry run against the target

```powershell
./Import-VcRbac.ps1 -Server vc-new.corp.local -Credential $cred `
    -InputFile ./exports/rbac-vc-old.corp.local-20261005-120000/rbac-export.json `
    -DomainMap ./exports/.../domain-map.csv `
    -PrincipalMap ./exports/.../principal-map.csv `
    -PathMap ./exports/.../path-map.csv `
    -ReportPath ./reports -SkipCertificateCheck -WhatIf
```

The report (`rbac-import-<server>-whatif-<timestamp>.html/.json`) lists every planned change and every problem:

| Action | Meaning |
|---|---|
| Create / Update | Change that will be (or was) applied. Result `WhatIf`, `Done` or `Failed: ...` |
| NoChange | Already matches |
| Skip | Intentionally not applied (system principal, built-in role, `SKIP` mapping, no password for SSO user) |
| Missing | Entity or role not found on target - fix `path-map.csv` or create the object |
| Warning | Privileges that do not exist on the target version are dropped from a role |

`PrincipalFound=False` in the detail column means vCenter could not find the principal on the target. Check the mapping and identity source before applying.

### 4. Apply

Run the same command without `-WhatIf`. Run it again afterwards: everything should report `NoChange`.

Order of apply: SSO users/groups/members, roles, global permissions, inventory permissions. Limit with `-Include`, e.g. `-Include Roles,Permissions`.

## Behaviour details

- **System principals**: principals containing a GUID (solution users such as `vpxd-extension-<guid>`, `machine-<guid>`) belong to one vCenter instance. They are exported for documentation and always skipped on import.
- **Built-in roles**: a role is built-in if it is a system role, has a known built-in name, or its label differs from its name (custom roles have label = name). Built-in roles are never created or modified on the target. Permissions using them are still applied.
- **8.x -> 9.x**: privileges missing on the target are dropped and reported as `Warning`. New 9.x privileges are not added to custom roles.
- **Local SSO users**: passwords cannot be exported. Pass `-SsoUserPassword (Read-Host -AsSecureString)` to create missing users with that initial password, then reset them. Without it they are reported as `Skip`.
- **Global permissions**: there is no public API. `GetAllPermissions` on the MOB returns global and inventory ACLs; entries whose `document` matches `-GlobalDocumentPattern` (default `global`) are treated as global. Check the "Global permissions" section in the HTML report and `globalpermissions-mob.html` on first use. If the classification is wrong, adjust `-GlobalDocumentPattern`.

## Limitations to verify on first run

- The MOB HTML parsing and `AddGlobalAccessControlList` have not been tested against vCenter 9.x. If the MOB is unavailable, run with `-Include` without `GlobalPermissions` and add those manually from the report.
- Federated (ADFS) principals: `PrincipalFound` may report `False` or `Unknown` for federated domains even when the principal works. Verify one permission manually.
