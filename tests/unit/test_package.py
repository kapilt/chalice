import os
import mock

import pytest
from chalice.config import Config
from chalice import package
from chalice.deploy.deployer import ApplicationGraphBuilder
from chalice.deploy.deployer import DependencyBuilder
from chalice.deploy.deployer import BuildStage
from chalice.deploy import models
from chalice.deploy.swagger import SwaggerGenerator
from chalice.constants import LAMBDA_TRUST_POLICY
from chalice.utils import OSUtils


@pytest.fixture
def mock_swagger_generator():
    return mock.Mock(spec=SwaggerGenerator)


def test_can_create_app_packager():
    config = Config()
    packager = package.create_app_packager(config)
    assert isinstance(packager, package.AppPackager)


def test_can_create_terraform_app_packager():
    config = Config()
    packager = package.create_app_packager(config, 'terraform')
    assert isinstance(packager, package.AppPackager)


def test_template_post_processor_moves_files_once():
    mock_osutils = mock.Mock(spec=OSUtils)
    p = package.SAMPostProcessor(mock_osutils)
    template = {
        'Resources': {
            'foo': {
                'Type': 'AWS::Serverless::Function',
                'Properties': {
                    'CodeUri': 'old-dir.zip',
                }
            },
            'bar': {
                'Type': 'AWS::Serverless::Function',
                'Properties': {
                    'CodeUri': 'old-dir.zip',
                }
            },
        }
    }
    p.process(template, config=None,
              outdir='outdir', chalice_stage_name='dev')
    mock_osutils.copy.assert_called_with(
        'old-dir.zip', os.path.join('outdir', 'deployment.zip'))
    assert mock_osutils.copy.call_count == 1
    assert template['Resources']['foo']['Properties']['CodeUri'] == (
        './deployment.zip'
    )
    assert template['Resources']['bar']['Properties']['CodeUri'] == (
        './deployment.zip'
    )


def test_terraform_post_processor_moves_files_once():
    mock_osutils = mock.Mock(spec=OSUtils)
    p = package.TerraformPostProcessor(mock_osutils)
    template = {
        'resource': {
            'aws_lambda_function': {
                'foo': {'filename': 'old-dir.zip'},
                'bar': {'filename': 'old-dir.zip'},
            }
        }
    }

    p.process(template, config=None,
              outdir='outdir', chalice_stage_name='dev')
    mock_osutils.copy.assert_called_with(
        'old-dir.zip', os.path.join('outdir', 'deployment.zip'))
    assert mock_osutils.copy.call_count == 1
    assert template['resource']['aws_lambda_function'][
        'foo']['filename'] == ('./deployment.zip')
    assert template['resource']['aws_lambda_function'][
        'bar']['filename'] == ('./deployment.zip')


def test_template_generator_default():
    tgen = package.TemplateGenerator()

    with pytest.raises(package.UnsupportedFeatureError):
        tgen.dispatch(models.Model(), {})


class TemplateTestBase(object):

    template_gen_factory = None

    def setup_method(self):
        self.resource_builder = package.ResourceBuilder(
            application_builder=ApplicationGraphBuilder(),
            deps_builder=DependencyBuilder(),
            build_stage=mock.Mock(spec=BuildStage)
        )
        self.template_gen = self.template_gen_factory()

    def generate_template(self, config, chalice_stage_name):
        resources = self.resource_builder.construct_resources(
            config, chalice_stage_name)
        return self.template_gen.generate(resources)

    def lambda_function(self):
        return models.LambdaFunction(
            resource_name='foo',
            function_name='app-dev-foo',
            environment_variables={},
            runtime='python27',
            handler='app.app',
            tags={'foo': 'bar'},
            timeout=120,
            memory_size=128,
            deployment_package=models.DeploymentPackage(filename='foo.zip'),
            role=models.PreCreatedIAMRole(role_arn='role:arn'),
            security_group_ids=[],
            subnet_ids=[],
            layers=[],
            reserved_concurrency=None,
        )


class TestTerraformTemplate(TemplateTestBase):

    template_gen_factory = package.TerraformGenerator

    EmptyPolicy = {
        'Version': '2012-10-18',
        'Statement': {
            'Sid': '',
            'Effect': 'Allow',
            'Action': 'lambda:*'
        }
    }

    def generate_template(self, config, chalice_stage_name):
        resources = self.resource_builder.construct_resources(
            config, 'dev')

        # Patch up resources that have mocks (due to build stage)
        # that we need to serialize to json.
        for r in resources:
            # For terraform rest api construction, we need a swagger
            # doc on the api resource as we'll be serializing it to
            # json.
            if isinstance(r, models.RestAPI):
                r.swagger_doc = {
                    'info': {'title': 'some-app'},
                    'x-amazon-apigateway-binary-media-types': []
                }
            # Same for iam policies on roles
            elif isinstance(r, models.FileBasedIAMPolicy):
                r.document = self.EmptyPolicy

        return self.template_gen.generate(resources)

    def get_function(self, template):
        functions = list(template['resource'][
            'aws_lambda_function'].values())
        assert len(functions) == 1
        return functions[0]

    def test_supports_precreated_role(self):
        builder = DependencyBuilder()
        resources = builder.build_dependencies(
            models.Application(
                stage='dev',
                resources=[self.lambda_function()],
            )
        )
        template = self.template_gen.generate(resources)
        assert template['resource'][
            'aws_lambda_function']['foo']['role'] == 'role:arn'

    def test_adds_env_vars_when_provided(self, sample_app):
        function = self.lambda_function()
        function.environment_variables = {'foo': 'bar'}
        template = self.template_gen.generate([function])
        tf_resource = self.get_function(template)
        assert tf_resource['environment'] == {
            'variables': {
                'foo': 'bar'
            }
        }

    def test_adds_vpc_config_when_provided(self):
        function = self.lambda_function()
        function.security_group_ids = ['sg1', 'sg2']
        function.subnet_ids = ['sn1', 'sn2']
        template = self.template_gen.generate([function])
        tf_resource = self.get_function(template)
        assert tf_resource['vpc_config'] == {
            'subnet_ids': ['sn1', 'sn2'],
            'security_group_ids': ['sg1', 'sg2']}

    def test_adds_layers_when_provided(self):
        function = self.lambda_function()
        function.layers = layers = ['arn://layer1', 'arn://layer2']
        template = self.template_gen.generate([function])
        tf_resource = self.get_function(template)
        assert tf_resource['layers'] == layers

    def test_adds_reserved_concurrency_when_provided(self, sample_app):
        function = self.lambda_function()
        function.reserved_concurrency = 5
        template = self.template_gen.generate([function])
        tf_resource = self.get_function(template)
        assert tf_resource['reserved_concurrent_executions'] == 5

    def test_can_generate_scheduled_event(self):
        function = self.lambda_function()
        event = models.ScheduledEvent(
            resource_name='foo-event',
            rule_name='myrule',
            schedule_expression='rate(5 minutes)',
            lambda_function=function,
        )
        template = self.template_gen.generate(
            [function, event]
        )
        rule = template['resource'][
            'aws_cloudwatch_event_rule'][event.resource_name]

        assert rule == {
            'name': event.resource_name,
            'schedule_expression': 'rate(5 minutes)'}

    def test_can_generate_rest_api(self, sample_app_with_auth):
        config = Config.create(chalice_app=sample_app_with_auth,
                               project_dir='.',
                               api_gateway_stage='api')
        template = self.generate_template(config, 'dev')
        resources = template['resource']
        # Lambda function should be created.
        assert resources['aws_lambda_function']
        # Along with permission to invoke from API Gateway.
        assert list(resources['aws_lambda_permission'].values())[0] == {
            'function_name': '${aws_lambda_function.api_handler.arn}',
            'action': 'lambda:InvokeFunction',
            'principal': 'apigateway.amazonaws.com',
            'source_arn': (
                '${aws_api_gateway_rest_api.rest_api.execution_arn}/*/*/*')
        }
        assert resources['aws_api_gateway_rest_api']
        # We should also create the auth lambda function.
        assert 'myauth' in resources['aws_lambda_function']

        # Along with permission to invoke from API Gateway.
        assert resources['aws_lambda_permission']['myauth_invoke'] == {
            'action': 'lambda:InvokeFunction',
            'function_name': '${aws_lambda_function.myauth.arn}',
            'principal': 'apigateway.amazonaws.com',
            'source_arn': (
                '${aws_api_gateway_rest_api.myauth.execution_arn}/*/*/*')
        }

        # Also verify we add the expected outputs when using
        # a Rest API.
        assert template['output'] == {
            'EndpointURL': {
                'value': '${aws_api_gateway_stage.rest_api.invoke_url}'}
        }

    def test_can_package_s3_event_handler_sans_filters(self, sample_app):
        @sample_app.on_s3_event(bucket='foo')
        def handler(event):
            pass

        config = Config.create(chalice_app=sample_app,
                               project_dir='.',
                               api_gateway_stage='api')

        template = self.generate_template(config, 'dev')
        assert template['resource']['aws_s3_bucket_notification'][
            'handler-s3event'] == {
                'bucket': 'foo',
                'lambda_function': {
                    'events': ['s3:ObjectCreated:*'],
                    'lambda_function_arn': (
                        '${aws_lambda_function.handler.arn}')
                }
        }

    def test_can_package_s3_event_handler(self, sample_app):
        @sample_app.on_s3_event(
            bucket='foo', prefix='incoming', suffix='.csv')
        def handler(event):
            pass

        config = Config.create(chalice_app=sample_app,
                               project_dir='.',
                               api_gateway_stage='api')

        template = self.generate_template(config, 'dev')
        assert template['resource']['aws_lambda_permission'][
            'handler-s3event'] == {
                'action': 'lambda:InvokeFunction',
                'function_name': '${aws_lambda_function.handler.arn}',
                'principal': 's3.amazonaws.com',
                'source_arn': 'arn:aws:s3:::foo',
                'statement_id': 'handler-s3event'
        }

        assert template['resource']['aws_s3_bucket_notification'][
            'handler-s3event'] == {
                'bucket': 'foo',
                'lambda_function': {
                    'events': ['s3:ObjectCreated:*'],
                    'filter_prefix': 'incoming',
                    'filter_suffix': '.csv',
                    'lambda_function_arn': (
                        '${aws_lambda_function.handler.arn}')
                }
        }

    def test_can_package_sns_handler(self, sample_app):
        @sample_app.on_sns_message(topic='foo')
        def handler(event):
            pass

        config = Config.create(chalice_app=sample_app,
                               project_dir='.',
                               api_gateway_stage='api')
        template = self.generate_template(config, 'dev')

        assert template['resource']['aws_sns_topic_subscription'][
            'handler-sns-subscription'] == {
                'topic_arn': ('arn:aws:sns:${aws_region.chalice.name}:'
                              '${aws_caller_identity.chalice.account_id}:foo'),
                'protocol': 'lambda',
                'endpoint': '${aws_lambda_function.handler.arn}'
        }

    def test_can_package_sns_arn_handler(self, sample_app):
        arn = 'arn:aws:sns:space-leo-1:1234567890:foo'

        @sample_app.on_sns_message(topic=arn)
        def handler(event):
            pass

        config = Config.create(chalice_app=sample_app,
                               project_dir='.',
                               api_gateway_stage='api')
        template = self.generate_template(config, 'dev')

        assert template['resource']['aws_sns_topic_subscription'][
            'handler-sns-subscription'] == {
                'topic_arn': arn,
                'protocol': 'lambda',
                'endpoint': '${aws_lambda_function.handler.arn}'
        }

        assert template['resource']['aws_lambda_permission'][
            'handler-sns-subscription'] == {
                'function_name': '${aws_lambda_function.handler.arn}',
                'action': 'lambda:InvokeFunction',
                'principal': 'sns.amazonaws.com',
                'source_arn': 'arn:aws:sns:space-leo-1:1234567890:foo'
        }

    def test_can_package_sqs_handler(self, sample_app):
        @sample_app.on_sqs_message(queue='foo', batch_size=5)
        def handler(event):
            pass

        config = Config.create(chalice_app=sample_app,
                               project_dir='.',
                               api_gateway_stage='api')
        template = self.generate_template(config, 'dev')

        assert template['resource'][
            'aws_lambda_event_source_mapping'][
                'handler-sqs-event-source'] == {
                    'event_source_arn': (
                        'arn:aws:sqs:${aws_region.chalice.name}:'
                        '${aws_caller_identity.chalice.account_id}:foo'),
                    'function_name': '${aws_lambda_function.handler.arn}',
                    'batch_size': 5
        }


class TestSAMTemplate(TemplateTestBase):

    template_gen_factory = package.SAMTemplateGenerator

    def test_sam_generates_sam_template_basic(self, sample_app):
        config = Config.create(chalice_app=sample_app,
                               project_dir='.',
                               api_gateway_stage='api')
        template = self.generate_template(config, 'dev')
        # Verify the basic structure is in place.  The specific parts
        # are validated in other tests.
        assert template['AWSTemplateFormatVersion'] == '2010-09-09'
        assert template['Transform'] == 'AWS::Serverless-2016-10-31'
        assert 'Outputs' in template
        assert 'Resources' in template
        assert list(sorted(template['Resources'])) == [
            'APIHandler', 'APIHandlerInvokePermission',
            # This casing on the ApiHandlerRole name is unfortunate, but the 3
            # other resources in this list are hardcoded from the old deployer.
            'ApiHandlerRole',
            'RestAPI',
        ]

    def test_supports_precreated_role(self):
        builder = DependencyBuilder()
        resources = builder.build_dependencies(
            models.Application(
                stage='dev',
                resources=[self.lambda_function()],
            )
        )
        template = self.template_gen.generate(resources)
        assert template['Resources']['Foo']['Properties']['Role'] == 'role:arn'

    def test_sam_injects_policy(self, sample_app):
        function = models.LambdaFunction(
            resource_name='foo',
            function_name='app-dev-foo',
            environment_variables={},
            runtime='python27',
            handler='app.app',
            tags={'foo': 'bar'},
            timeout=120,
            memory_size=128,
            deployment_package=models.DeploymentPackage(filename='foo.zip'),
            role=models.ManagedIAMRole(
                resource_name='role',
                role_name='app-role',
                trust_policy={},
                policy=models.AutoGenIAMPolicy(document={'iam': 'policy'}),
            ),
            security_group_ids=[],
            subnet_ids=[],
            layers=[],
            reserved_concurrency=None,
        )
        template = self.template_gen.generate([function])
        cfn_resource = list(template['Resources'].values())[0]
        assert cfn_resource == {
            'Type': 'AWS::Serverless::Function',
            'Properties': {
                'CodeUri': 'foo.zip',
                'Handler': 'app.app',
                'MemorySize': 128,
                'Role': {'Fn::GetAtt': ['Role', 'Arn']},
                'Runtime': 'python27',
                'Tags': {'foo': 'bar'},
                'Timeout': 120
            },
        }

    def test_adds_env_vars_when_provided(self, sample_app):
        function = self.lambda_function()
        function.environment_variables = {'foo': 'bar'}
        template = self.template_gen.generate([function])
        cfn_resource = list(template['Resources'].values())[0]
        assert cfn_resource['Properties']['Environment'] == {
            'Variables': {
                'foo': 'bar'
            }
        }

    def test_adds_vpc_config_when_provided(self):
        function = self.lambda_function()
        function.security_group_ids = ['sg1', 'sg2']
        function.subnet_ids = ['sn1', 'sn2']
        template = self.template_gen.generate([function])
        cfn_resource = list(template['Resources'].values())[0]
        assert cfn_resource['Properties']['VpcConfig'] == {
            'SecurityGroupIds': ['sg1', 'sg2'],
            'SubnetIds': ['sn1', 'sn2'],
        }

    def test_adds_reserved_concurrency_when_provided(self, sample_app):
        function = self.lambda_function()
        function.reserved_concurrency = 5
        template = self.template_gen.generate([function])
        cfn_resource = list(template['Resources'].values())[0]
        assert cfn_resource['Properties']['ReservedConcurrentExecutions'] == 5

    def test_adds_layers_when_provided(self, sample_app):
        function = self.lambda_function()
        function.layers = ['arn:aws:layer1', 'arn:aws:layer2']
        template = self.template_gen.generate([function])
        cfn_resource = list(template['Resources'].values())[0]
        assert cfn_resource['Properties']['Layers'] == [
            'arn:aws:layer1',
            'arn:aws:layer2'
            ]

    def test_duplicate_resource_name_raises_error(self):
        one = self.lambda_function()
        two = self.lambda_function()
        one.resource_name = 'foo_bar'
        two.resource_name = 'foo__bar'
        with pytest.raises(package.DuplicateResourceNameError):
            self.template_gen.generate([one, two])

    def test_role_arn_inserted_when_necessary(self):
        function = models.LambdaFunction(
            resource_name='foo',
            function_name='app-dev-foo',
            environment_variables={},
            runtime='python27',
            handler='app.app',
            tags={'foo': 'bar'},
            timeout=120,
            memory_size=128,
            deployment_package=models.DeploymentPackage(filename='foo.zip'),
            role=models.PreCreatedIAMRole(role_arn='role:arn'),
            security_group_ids=[],
            subnet_ids=[],
            layers=[],
            reserved_concurrency=None,
        )
        template = self.template_gen.generate([function])
        cfn_resource = list(template['Resources'].values())[0]
        assert cfn_resource == {
            'Type': 'AWS::Serverless::Function',
            'Properties': {
                'CodeUri': 'foo.zip',
                'Handler': 'app.app',
                'MemorySize': 128,
                'Role': 'role:arn',
                'Runtime': 'python27',
                'Tags': {'foo': 'bar'},
                'Timeout': 120
            },
        }

    def test_can_generate_cloud_watch_event(self):
        function = self.lambda_function()
        event = models.CloudWatchEvent(
            resource_name='foo-event',
            rule_name='myrule',
            event_pattern='{"source": ["aws.ec2"]}',
            lambda_function=function,
        )
        template = self.template_gen.generate_sam_template(
            [function, event]
        )
        resources = template['Resources']
        assert len(resources) == 1
        cfn_resource = list(resources.values())[0]
        assert cfn_resource['Properties']['Events'] == {
            'FooEvent': {
                'Type': 'CloudWatchEvent',
                'Properties': {
                    'Pattern': {
                        'source': [
                            'aws.ec2'
                        ]
                    }
                },
            },
        }

    def test_can_generate_scheduled_event(self):
        function = self.lambda_function()
        event = models.ScheduledEvent(
            resource_name='foo-event',
            rule_name='myrule',
            schedule_expression='rate(5 minutes)',
            lambda_function=function,
        )
        template = self.template_gen.generate(
            [function, event]
        )
        resources = template['Resources']
        assert len(resources) == 1
        cfn_resource = list(resources.values())[0]
        assert cfn_resource['Properties']['Events'] == {
            'FooEvent': {
                'Type': 'Schedule',
                'Properties': {
                    'Schedule': 'rate(5 minutes)'
                },
            },
        }

    def test_can_generate_rest_api_without_compression(
            self, sample_app_with_auth):
        config = Config.create(chalice_app=sample_app_with_auth,
                               project_dir='.',
                               api_gateway_stage='api',
                               )
        template = self.generate_template(config, 'dev')
        resources = template['Resources']
        assert 'MinimumCompressionSize' not in \
            resources['RestAPI']['Properties']

    def test_can_generate_rest_api(self, sample_app_with_auth):
        config = Config.create(chalice_app=sample_app_with_auth,
                               project_dir='.',
                               api_gateway_stage='api',
                               minimum_compression_size=100,
                               )
        template = self.generate_template(config, 'dev')
        resources = template['Resources']
        # Lambda function should be created.
        assert resources['APIHandler']['Type'] == 'AWS::Serverless::Function'
        # Along with permission to invoke from API Gateway.
        assert resources['APIHandlerInvokePermission'] == {
            'Type': 'AWS::Lambda::Permission',
            'Properties': {
                'Action': 'lambda:InvokeFunction',
                'FunctionName': {'Ref': 'APIHandler'},
                'Principal': 'apigateway.amazonaws.com',
                'SourceArn': {
                    'Fn::Sub': [
                        ('arn:aws:execute-api:${AWS::Region}:${AWS::AccountId}'
                         ':${RestAPIId}/*'),
                        {'RestAPIId': {'Ref': 'RestAPI'}}]}},
        }
        assert resources['RestAPI']['Type'] == 'AWS::Serverless::Api'
        assert resources['RestAPI']['Properties']['MinimumCompressionSize'] \
            == 100
        # We should also create the auth lambda function.
        assert resources['Myauth']['Type'] == 'AWS::Serverless::Function'
        # Along with permission to invoke from API Gateway.
        assert resources['MyauthInvokePermission'] == {
            'Type': 'AWS::Lambda::Permission',
            'Properties': {
                'Action': 'lambda:InvokeFunction',
                'FunctionName': {'Fn::GetAtt': ['Myauth', 'Arn']},
                'Principal': 'apigateway.amazonaws.com',
                'SourceArn': {
                    'Fn::Sub': [
                        ('arn:aws:execute-api:${AWS::Region}:${AWS::AccountId}'
                         ':${RestAPIId}/*'),
                        {'RestAPIId': {'Ref': 'RestAPI'}}]}},
        }
        # Also verify we add the expected outputs when using
        # a Rest API.
        assert template['Outputs'] == {
            'APIHandlerArn': {
                'Value': {
                    'Fn::GetAtt': ['APIHandler', 'Arn']
                }
            },
            'APIHandlerName': {'Value': {'Ref': 'APIHandler'}},
            'EndpointURL': {
                'Value': {
                    'Fn::Sub': (
                        'https://${RestAPI}.execute-api.'
                        '${AWS::Region}.amazonaws.com/api/'
                    )
                }
            },
            'RestAPIId': {'Value': {'Ref': 'RestAPI'}}
        }

    def test_managed_iam_role(self):
        role = models.ManagedIAMRole(
            resource_name='default_role',
            role_name='app-dev',
            trust_policy=LAMBDA_TRUST_POLICY,
            policy=models.AutoGenIAMPolicy(document={'iam': 'policy'}),
        )
        template = self.template_gen.generate([role])
        resources = template['Resources']
        assert len(resources) == 1
        cfn_role = resources['DefaultRole']
        assert cfn_role['Type'] == 'AWS::IAM::Role'
        assert cfn_role['Properties']['Policies'] == [
            {'PolicyName': 'DefaultRolePolicy',
             'PolicyDocument': {'iam': 'policy'}}
        ]
        # Ensure the RoleName is not in the resource properties
        # so we don't require CAPABILITY_NAMED_IAM.
        assert 'RoleName' not in cfn_role['Properties']

    def test_single_role_generated_for_default_config(self,
                                                      sample_app_lambda_only):
        # The sample_app has one lambda function.
        # We'll add a few more and verify they all share the same role.
        @sample_app_lambda_only.lambda_function()
        def second(event, context):
            pass

        @sample_app_lambda_only.lambda_function()
        def third(event, context):
            pass

        config = Config.create(chalice_app=sample_app_lambda_only,
                               project_dir='.',
                               autogen_policy=True,
                               api_gateway_stage='api')
        template = self.generate_template(config, 'dev')
        roles = [resource for resource in template['Resources'].values()
                 if resource['Type'] == 'AWS::IAM::Role']
        assert len(roles) == 1
        # The lambda functions should all reference this role.
        functions = [
            resource for resource in template['Resources'].values()
            if resource['Type'] == 'AWS::Serverless::Function'
        ]
        role_names = [
            function['Properties']['Role'] for function in functions
        ]
        assert role_names == [
            {'Fn::GetAtt': ['DefaultRole', 'Arn']},
            {'Fn::GetAtt': ['DefaultRole', 'Arn']},
            {'Fn::GetAtt': ['DefaultRole', 'Arn']},
        ]

    def test_vpc_config_added_to_function(self, sample_app_lambda_only):
        config = Config.create(chalice_app=sample_app_lambda_only,
                               project_dir='.',
                               autogen_policy=True,
                               api_gateway_stage='api',
                               security_group_ids=['sg1', 'sg2'],
                               subnet_ids=['sn1', 'sn2'])
        template = self.generate_template(config, 'dev')
        resources = template['Resources'].values()
        lambda_fns = [resource for resource in resources
                      if resource['Type'] == 'AWS::Serverless::Function']
        assert len(lambda_fns) == 1

        vpc_config = lambda_fns[0]['Properties']['VpcConfig']
        assert vpc_config['SubnetIds'] == ['sn1', 'sn2']
        assert vpc_config['SecurityGroupIds'] == ['sg1', 'sg2']

    def test_helpful_error_message_on_s3_event(self, sample_app):
        @sample_app.on_s3_event(bucket='foo')
        def handler(event):
            pass

        config = Config.create(chalice_app=sample_app,
                               project_dir='.',
                               api_gateway_stage='api')
        with pytest.raises(NotImplementedError) as excinfo:
            self.generate_template(config, 'dev')
        # Should mention the decorator name.
        assert '@app.on_s3_event' in str(excinfo.value)
        # Should mention you can use `chalice deploy`.
        assert 'chalice deploy' in str(excinfo.value)

    def test_can_package_sns_handler(self, sample_app):
        @sample_app.on_sns_message(topic='foo')
        def handler(event):
            pass

        config = Config.create(chalice_app=sample_app,
                               project_dir='.',
                               api_gateway_stage='api')
        template = self.generate_template(config, 'dev')
        sns_handler = template['Resources']['Handler']
        assert sns_handler['Properties']['Events'] == {
            'HandlerSnsSubscription': {
                'Type': 'SNS',
                'Properties': {
                    'Topic': {
                        'Fn::Sub': (
                            'arn:aws:sns:${AWS::Region}:${AWS::AccountId}:foo'
                        )
                    }
                },
            }
        }

    def test_can_package_sns_arn_handler(self, sample_app):
        arn = 'arn:aws:sns:space-leo-1:1234567890:foo'

        @sample_app.on_sns_message(topic=arn)
        def handler(event):
            pass

        config = Config.create(chalice_app=sample_app,
                               project_dir='.',
                               api_gateway_stage='api')
        template = self.generate_template(config, 'dev')
        sns_handler = template['Resources']['Handler']
        assert sns_handler['Properties']['Events'] == {
            'HandlerSnsSubscription': {
                'Type': 'SNS',
                'Properties': {
                    'Topic': arn,
                }
            }
        }

    def test_can_package_sqs_handler(self, sample_app):
        @sample_app.on_sqs_message(queue='foo', batch_size=5)
        def handler(event):
            pass

        config = Config.create(chalice_app=sample_app,
                               project_dir='.',
                               api_gateway_stage='api')
        template = self.generate_template(config, 'dev')
        sns_handler = template['Resources']['Handler']
        assert sns_handler['Properties']['Events'] == {
            'HandlerSqsEventSource': {
                'Type': 'SQS',
                'Properties': {
                    'Queue': {
                        'Fn::Sub': (
                            'arn:aws:sqs:${AWS::Region}:${AWS::AccountId}:foo'
                        )
                    },
                    'BatchSize': 5,
                },
            }
        }
