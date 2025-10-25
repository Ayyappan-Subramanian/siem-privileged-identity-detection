## Audit Policy Configuration

1. Open **CMD/PowerShell as Administrator** on Windows DC and Client.  
2. Apply audit policies using `auditpol` commands based on category and sub-category as required for the project scenario

The following commands gives you the audit polices enable/disable based on [audit policies](../config/gpo/audit_policies.txt)

```bash
# === System ===
auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable
auditpol /set /subcategory:"Other System Events" /success:enable /failure:enable
auditpol /set /subcategory:"Security State Change" /success:enable

# === Logon/Logoff ===
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable
auditpol /set /subcategory:"Account Lockout" /success:enable
auditpol /set /subcategory:"Special Logon" /success:enable
auditpol /set /subcategory:"Network Policy Server" /success:enable /failure:enable

# === Policy Change ===
auditpol /set /subcategory:"Audit Policy Change" /success:enable
auditpol /set /subcategory:"Authentication Policy Change" /success:enable

# === Account Management ===
auditpol /set /subcategory:"Computer Account Management" /success:enable
auditpol /set /subcategory:"Security Group Management" /success:enable
auditpol /set /subcategory:"User Account Management" /success:enable

# === DS Access ===
auditpol /set /subcategory:"Directory Service Access" /success:enable

# === Account Logon ===
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable
auditpol /set /subcategory:"Credential Validation" /success:enable
```
### Verify Applied Policies via cmd

After that, run the command to apply the policies:
```bash
gpupdate/force
```
This command forces an immediate update of Group Policy settings instead of waiting for the next automatic refresh cycle.

Ypu can also, run the command
```bash
auditpol /get /category:*       #to verify the applied policies
```

### Verify Applied Policies via Event Viewer
You can also verify in the windows log -> Security by creating a new user. 

Once you crate a new user you can see a log with an event id 4720 and task category “User Account Management” for a new user account creation (member02)

Similarly, you can perform suitable actions, confirm events like 4720 (user created), 4769 (TGS request), 4624 (successful logon) appear in the Security log.
