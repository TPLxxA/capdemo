import boto3
client = boto3.client('iam')
resource = boto3.resource('iam')
def lambda_handler(event,context)
    try
        roles = client.list_roles()
        N_delete = []
        for r in roles['Roles']
            role = resource.Role(name=r['RoleName'])
            
            if role != 'AWSServiceRoleForOrganizations'
                # Get all Managed Policies and detatch them
                [role.detach_policy(PolicyArn=policy.arn)
                for policy in role.attached_policies.all()]
                
                # Get all Instance Profiles and detatch them
                [profile.remove_role(RoleName=role.name)
                for profile in role.instance_profiles.all()]
                
                # Get all Inline Policies and delete them
                [role_policy.delete() for role_policy in role.policies.all()]
                role.delete()
            
    except
        N_delete.append(role)
    
    print(N_delete)