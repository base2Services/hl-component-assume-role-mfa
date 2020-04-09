CfhighlanderTemplate do
  Name 'assume-role-mfa'
  Description "assume-role-mfa - #{component_version}"
  
  DependsOn 'lib-iam@0.1.0'
  
  Parameters do
    ComponentParam 'EnvironmentName', 'dev', isGlobal: true
    ComponentParam 'EnvironmentType', 'development', allowedValues: ['development','production'], isGlobal: true
  end

  LambdaFunctions 'key_rotator'

end
