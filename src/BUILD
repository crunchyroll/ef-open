from os import environ

python_binary(
  name = 'ef-cf',
  source = 'ef-cf.py',
  dependencies = [
    ':boto3',
    ':ef-open-lib'
  ]
 )

python_binary(
  name = 'ef-check-config',
  source = 'ef-check-config.py',
  dependencies = [
    ':boto3',
    ':ef-open-lib'
  ]
)

python_binary(
  name = 'ef-generate',
  source = 'ef-generate.py',
  dependencies = [
    ':boto3',
    ':ef-open-lib'
  ]
)

python_binary(
  name = 'ef-resolve-config',
  source = 'ef-resolve-config.py',
  dependencies = [
    ':boto3',
    ':ef-open-lib'
  ]
)

python_binary(
  name = 'ef-version',
  source = 'ef-version.py',
  dependencies = [
    ':boto3',
    ':ef-open-lib'
  ]
)

python_requirement_library(
  name = 'boto3',
  requirements = [
    python_requirement("boto3")
  ]
)

python_library(
  name = 'ef-open-lib',
  dependencies = [
    environ["EF_SITE_CONFIG"]+":siteconfig"
  ],
  sources = globs('ef_*.py', exclude=['ef_site_config.py'])
)
