CloudFormation do
  
  iam_policies = external_parameters.fetch(:iam_policies, [])
  IAM_Role(:LambdaRoleKeyRotator) {
    AssumeRolePolicyDocument service_assume_role_policy('lambda')
    Policies iam_role_policies(iam_policies)
  }

  mfa_tags = []
  mfa_tags.push({ Key: 'EnvironmentName', Value: Ref(:EnvironmentName) })
  mfa_tags.push({ Key: 'EnvironmentType', Value: Ref(:EnvironmentType) })
  
  users = external_parameters.fetch(:users, [])
  
  users.each do |user|
    
    resource_name = user['name'].capitalize.gsub(/[^a-zA-Z0-9]/, '')
    
    policies = [
      {
        PolicyName: 'assume-role',
        PolicyDocument: {
          Version: "2012-10-17",
          Statement: [
            {
              Effect: "Allow",
              Action: "sts:AssumeRole",
              Resource: user['roles']
            }
          ]
        }        
      }
    ]
    
    user_tags = mfa_tags.clone()
    user_tags.push({ Key: 'Name', Value: "jenkins-mfa-user-#{user['name']}" })
    
    IAM_User("#{resource_name}User") {
      UserName user['name']
      Path '/ciinabox/mfa/'
      Policies policies
      Tags user_tags
    }
    
    IAM_AccessKey("#{resource_name}AccessKey") {
      UserName Ref("#{resource_name}User")
      Serial user['manually_rotate'] if user.has_key?('manually_rotate')
    }
    
    secret_tags = mfa_tags.clone()
    secret_tags.push({ Key: 'ciinabox:iam:user', Value: user['name'] })
    secret_tags.push({ Key: 'jenkins:credentials:type', Value: 'usernamePassword' })
    secret_tags.push({ Key: 'jenkins:credentials:username', Value: Ref("#{resource_name}AccessKey") })
    
    SecretsManager_Secret("#{resource_name}Secret") {
      Name FnSub("/${EnvironmentName}/jenkins/mfa/#{user['name']}")
      Description "IAM user access key for #{user['name']}"
      SecretString FnGetAtt("#{resource_name}AccessKey", :SecretAccessKey)
      Tags secret_tags
    }
    
    rotation = user.has_key?('rotation') ? user['rotation'] : 7
    
    SecretsManager_RotationSchedule("#{resource_name}SecretRotationSchedule") {
      SecretId Ref("#{resource_name}Secret")
      RotationLambdaARN FnGetAtt(:CiinaboxKeyRotator, :Arn)
      RotationRules({
        AutomaticallyAfterDays: rotation.to_i
      })
    }
    
  end
  

end
