python_binary(
  name = 'ef-cf',
  source = 'ef-cf.py',
  repositories = [
    'ef-open',
    'ellation_formation'
  ],
  dependencies = [
    ':boto3',
    ':siteconfig',
    ':tools'
  ]
 )

python_binary(
  name = 'ef-check-config',
  source = 'ef-check-config.py',
  dependencies = [
    ':boto3',
    ':tools'
  ]
)

python_binary(
  name = 'ef-generate',
  source = 'ef-generate.py',
  dependencies = [
    ':boto3',
    ':tools'
  ]
)

python_binary(
  name = 'ef-resolve-config',
  source = 'ef-resolve-config.py',
  dependencies = [
    ':boto3',
    ':tools'
  ]
)

python_binary(
  name = 'ef-version',
  source = 'ef-version.py',
  dependencies = [
    ':boto3',
    ':tools'
  ]
)

python_requirement_library(
  name = 'boto3',
  requirements = [
    python_requirement("boto3")
  ]
)

python_library(
  name = 'tools',
  sources = globs('ef_*.py')
)

python_library(
  name = 'siteconfig',
  sources = [
    'ef_site_config.py'
  ]
)
