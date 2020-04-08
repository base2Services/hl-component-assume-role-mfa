CloudFormation do
  
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
      Name FnSub("/${EnvironmentName}/jenkins/mfa/#{user['user']}")
      Description "IAM user access key for #{user['user']}"
      SecretString FnGetAtt("#{resource_name}AccessKey", :SecretAccessKey)
      Tags secret_tags
    }
    
    rotation = user.has_key?('rotation') ? user['rotation'] : 7
        
    payload = {
      User: Ref("#{resource_name}User"),
      SecretId: Ref("#{resource_name}Secret")
    }
    
    Events_Rule("#{resource_name}RotationSchedule") {
      Description "rotate the IAM user access key for #{user['user']} every #{rotation} days"
      State 'ENABLED'
      ScheduleExpression "rate(#{rotation} days)"
      Targets([
        {
          Arn: FnGetAtt(:CiinaboxKeyRotator, :Arn),
          Id: "#{resource_name}RotationSchedule",
          Input: payload.to_json
        }
      ])
    }
    
    Lambda_Permission("#{resource_name}RotationPermissions") {
      FunctionName FnGetAtt(:CiinaboxKeyRotator, :Arn)
      Action 'lambda:InvokeFunction'
      Principal 'events.amazonaws.com'
      SourceAccount Ref('AWS::AccountId')
      SourceArn FnGetAtt("#{resource_name}RotationSchedule", :Arn)
    }
    
  end
  

end
