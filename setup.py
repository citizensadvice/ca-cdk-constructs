from setuptools import setup

setup(name='cdk-constructs',
      version='0.0.1',
      description='Constructs for Python AWS CDK',
      url='https://github.com/citizensadvice/cdk_constructs',
      author='Citizens Advice',
      author_email='ca-devops@citizensadvice.org.uk',
      license='MIT',
      packages=['cdk_constructs'],
      package_data={'cdk_constructs': ['assets/*.json']},
      include_package_data=True)
