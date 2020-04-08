CfhighlanderTemplate do
  Name 'assume-role-mfa'
  Description "assume-role-mfa - #{component_version}"

  Parameters do
    ComponentParam 'EnvironmentName', 'dev', isGlobal: true
    ComponentParam 'EnvironmentType', 'development', allowedValues: ['development','production'], isGlobal: true
  end

  LambdaFunctions 'key_rotator'

end
