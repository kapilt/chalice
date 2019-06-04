import json
import os
import copy

from typing import Any, Dict, List, Set, Union  # noqa
from typing import cast

from chalice.deploy.swagger import (
    CFNSwaggerGenerator, TerraformSwaggerGenerator)
from chalice.utils import OSUtils, UI, serialize_to_json, to_cfn_resource_name
from chalice.config import Config  # noqa
from chalice.deploy import models
from chalice.deploy.deployer import ApplicationGraphBuilder
from chalice.deploy.deployer import DependencyBuilder
from chalice.deploy.deployer import BuildStage  # noqa
from chalice.deploy.deployer import create_build_stage


def create_app_packager(config, package_format='cloudformation'):
    # type: (Config, str) -> AppPackager
    osutils = OSUtils()
    ui = UI()
    application_builder = ApplicationGraphBuilder()
    deps_builder = DependencyBuilder()
    post_processor = None  # type: Union[None, TemplatePostProcessor]
    generator = None  # type: Union[None, TemplateGenerator]

    if package_format == 'cloudformation':
        build_stage = create_build_stage(
            osutils, ui, CFNSwaggerGenerator())
        post_processor = SAMPostProcessor(osutils=osutils)
        generator = SAMTemplateGenerator()
    else:
        build_stage = create_build_stage(
            osutils, ui, TerraformSwaggerGenerator())
        generator = TerraformGenerator()
        post_processor = TerraformPostProcessor(osutils=osutils)

    resource_builder = ResourceBuilder(
        application_builder, deps_builder, build_stage)

    return AppPackager(
        generator,
        resource_builder,
        post_processor,
        osutils)


class UnsupportedFeatureError(Exception):
    pass


class DuplicateResourceNameError(Exception):
    pass


class ResourceBuilder(object):
    def __init__(self,
                 application_builder,  # type: ApplicationGraphBuilder
                 deps_builder,         # type: DependencyBuilder
                 build_stage,          # type: BuildStage
                 ):
        # type: (...) -> None
        self._application_builder = application_builder
        self._deps_builder = deps_builder
        self._build_stage = build_stage

    def construct_resources(self, config, chalice_stage_name):
        # type: (Config, str) -> List[models.Model]
        application = self._application_builder.build(
            config, chalice_stage_name)
        resources = self._deps_builder.build_dependencies(application)
        self._build_stage.execute(config, resources)
        return resources


class TemplateGenerator(object):

    template_file = None  # type: str

    def dispatch(self, resource, template):
        # type: (models.Model, Dict[str, Any]) -> None
        name = '_generate_%s' % resource.__class__.__name__.lower()
        handler = getattr(self, name, self._default)
        handler(resource, template)

    def generate(self, resources):
        # type: (List[models.Model]) -> Dict[str, Any]
        raise NotImplementedError()

    def _generate_filebasediampolicy(self, resource, template):
        # type: (models.FileBasedIAMPolicy, Dict[str, Any]) -> None
        pass

    def _generate_autogeniampolicy(self, resource, template):
        # type: (models.AutoGenIAMPolicy, Dict[str, Any]) -> None
        pass

    def _generate_deploymentpackage(self, resource, template):
        # type: (models.DeploymentPackage, Dict[str, Any]) -> None
        pass

    def _generate_precreatediamrole(self, resource, template):
        # type: (models.PreCreatedIAMRole, Dict[str, Any]) -> None
        pass

    def _default(self, resource, template):
        # type: (models.Model, Dict[str, Any]) -> None
        raise UnsupportedFeatureError(resource)


class SAMTemplateGenerator(TemplateGenerator):

    _BASE_TEMPLATE = {
        'AWSTemplateFormatVersion': '2010-09-09',
        'Transform': 'AWS::Serverless-2016-10-31',
        'Outputs': {},
        'Resources': {},
    }

    template_file = "sam.json"

    def __init__(self):
        # type: () -> None
        self._seen_names = set([])  # type: Set[str]

    def generate(self, resources):
        # type: (List[models.Model]) -> Dict[str, Any]
        template = copy.deepcopy(self._BASE_TEMPLATE)
        self._seen_names.clear()
        for resource in resources:
            self.dispatch(resource, template)
        return template

    def _generate_scheduledevent(self, resource, template):
        # type: (models.ScheduledEvent, Dict[str, Any]) -> None
        function_cfn_name = to_cfn_resource_name(
            resource.lambda_function.resource_name)
        function_cfn = template['Resources'][function_cfn_name]
        event_cfn_name = self._register_cfn_resource_name(
            resource.resource_name)
        function_cfn['Properties']['Events'] = {
            event_cfn_name: {
                'Type': 'Schedule',
                'Properties': {
                    'Schedule': resource.schedule_expression,
                }
            }
        }

    def _generate_lambdafunction(self, resource, template):
        # type: (models.LambdaFunction, Dict[str, Any]) -> None
        resources = template['Resources']
        cfn_name = self._register_cfn_resource_name(resource.resource_name)
        lambdafunction_definition = {
            'Type': 'AWS::Serverless::Function',
            'Properties': {
                'Runtime': resource.runtime,
                'Handler': resource.handler,
                'CodeUri': resource.deployment_package.filename,
                'Tags': resource.tags,
                'Timeout': resource.timeout,
                'MemorySize': resource.memory_size,
            },
        }  # type: Dict[str, Any]

        if resource.environment_variables:
            environment_config = {
                'Environment': {
                    'Variables': resource.environment_variables
                }
            }  # type: Dict[str, Dict[str, Dict[str, str]]]
            lambdafunction_definition['Properties'].update(environment_config)
        if resource.security_group_ids and resource.subnet_ids:
            vpc_config = {
                'VpcConfig': {
                    'SecurityGroupIds': resource.security_group_ids,
                    'SubnetIds': resource.subnet_ids,
                }
            }  # type: Dict[str, Dict[str, List[str]]]
            lambdafunction_definition['Properties'].update(vpc_config)
        if resource.reserved_concurrency is not None:
            reserved_concurrency_config = {
                'ReservedConcurrentExecutions': resource.reserved_concurrency
            }
            lambdafunction_definition['Properties'].update(
                reserved_concurrency_config)
        resources[cfn_name] = lambdafunction_definition
        self._add_iam_role(resource, resources[cfn_name])

    def _add_iam_role(self, resource, cfn_resource):
        # type: (models.LambdaFunction, Dict[str, Any]) -> None
        role = resource.role
        if isinstance(role, models.ManagedIAMRole):
            cfn_resource['Properties']['Role'] = {
                'Fn::GetAtt': [
                    to_cfn_resource_name(role.resource_name), 'Arn'
                ],
            }
        else:
            # resource is a PreCreatedIAMRole.  This is the only other
            # subclass of IAMRole.
            role = cast(models.PreCreatedIAMRole, role)
            cfn_resource['Properties']['Role'] = role.role_arn

    def _generate_restapi(self, resource, template):
        # type: (models.RestAPI, Dict[str, Any]) -> None
        resources = template['Resources']
        resources['RestAPI'] = {
            'Type': 'AWS::Serverless::Api',
            'Properties': {
                'StageName': resource.api_gateway_stage,
                'DefinitionBody': resource.swagger_doc,
            }
        }
        handler_cfn_name = to_cfn_resource_name(
            resource.lambda_function.resource_name)
        api_handler = template['Resources'].pop(handler_cfn_name)
        template['Resources']['APIHandler'] = api_handler
        resources['APIHandlerInvokePermission'] = {
            'Type': 'AWS::Lambda::Permission',
            'Properties': {
                'FunctionName': {'Ref': 'APIHandler'},
                'Action': 'lambda:InvokeFunction',
                'Principal': 'apigateway.amazonaws.com',
                'SourceArn': {
                    'Fn::Sub': [
                        ('arn:aws:execute-api:${AWS::Region}:${AWS::AccountId}'
                         ':${RestAPIId}/*'),
                        {'RestAPIId': {'Ref': 'RestAPI'}},
                    ]
                },
            }
        }
        for auth in resource.authorizers:
            auth_cfn_name = to_cfn_resource_name(auth.resource_name)
            resources[auth_cfn_name + 'InvokePermission'] = {
                'Type': 'AWS::Lambda::Permission',
                'Properties': {
                    'FunctionName': {'Fn::GetAtt': [auth_cfn_name, 'Arn']},
                    'Action': 'lambda:InvokeFunction',
                    'Principal': 'apigateway.amazonaws.com',
                    'SourceArn': {
                        'Fn::Sub': [
                            ('arn:aws:execute-api:${AWS::Region}:'
                             '${AWS::AccountId}:${RestAPIId}/*'),
                            {'RestAPIId': {'Ref': 'RestAPI'}},
                        ]
                    },
                }
            }
        self._inject_restapi_outputs(template)

    def _inject_restapi_outputs(self, template):
        # type: (Dict[str, Any]) -> None
        # The 'Outputs' of the SAM template are considered
        # part of the public API of chalice and therefore
        # need to maintain backwards compatibility.  This
        # method uses the same output key names as the old
        # deployer.
        # For now, we aren't adding any of the new resources
        # to the Outputs section until we can figure out
        # a consist naming scheme.  Ideally we don't use
        # the autogen'd names that contain the md5 suffixes.
        stage_name = template['Resources']['RestAPI'][
            'Properties']['StageName']
        outputs = template['Outputs']
        outputs['RestAPIId'] = {
            'Value': {'Ref': 'RestAPI'}
        }
        outputs['APIHandlerName'] = {
            'Value': {'Ref': 'APIHandler'}
        }
        outputs['APIHandlerArn'] = {
            'Value': {'Fn::GetAtt': ['APIHandler', 'Arn']}
        }
        outputs['EndpointURL'] = {
            'Value': {
                'Fn::Sub': (
                    'https://${RestAPI}.execute-api.${AWS::Region}'
                    # The api_gateway_stage is filled in when
                    # the template is built.
                    '.amazonaws.com/%s/'
                ) % stage_name
            }
        }

    # The various IAM roles/policies are handled in the
    # Lambda function generation.  We're creating these
    # noop methods to indicate we've accounted for these
    # resources.

    def _generate_managediamrole(self, resource, template):
        # type: (models.ManagedIAMRole, Dict[str, Any]) -> None
        role_cfn_name = self._register_cfn_resource_name(
            resource.resource_name)
        template['Resources'][role_cfn_name] = {
            'Type': 'AWS::IAM::Role',
            'Properties': {
                'AssumeRolePolicyDocument': resource.trust_policy,
                'Policies': [
                    {'PolicyDocument': resource.policy.document,
                     'PolicyName': role_cfn_name + 'Policy'},
                ],
            }
        }

    def _generate_s3bucketnotification(self, resource, template):
        # type: (models.S3BucketNotification, Dict[str, Any]) -> None
        message = (
            "Unable to package chalice apps that @app.on_s3_event decorator. "
            "CloudFormation does not support modifying the event "
            "notifications of existing buckets. "
            "You can deploy this app using `chalice deploy`."
        )
        raise NotImplementedError(message)

    def _generate_snslambdasubscription(self, resource, template):
        # type: (models.SNSLambdaSubscription, Dict[str, Any]) -> None
        function_cfn_name = to_cfn_resource_name(
            resource.lambda_function.resource_name)
        function_cfn = template['Resources'][function_cfn_name]
        sns_cfn_name = self._register_cfn_resource_name(
            resource.resource_name)

        if resource.topic.startswith('arn:aws:sns:'):
            topic_arn = resource.topic  # type: Union[str, Dict[str, str]]
        else:
            topic_arn = {
                'Fn::Sub': (
                    'arn:aws:sns:${AWS::Region}:${AWS::AccountId}:%s' %
                    resource.topic
                )
            }
        function_cfn['Properties']['Events'] = {
            sns_cfn_name: {
                'Type': 'SNS',
                'Properties': {
                    'Topic': topic_arn,
                }
            }
        }

    def _generate_sqseventsource(self, resource, template):
        # type: (models.SQSEventSource, Dict[str, Any]) -> None
        function_cfn_name = to_cfn_resource_name(
            resource.lambda_function.resource_name)
        function_cfn = template['Resources'][function_cfn_name]
        sns_cfn_name = self._register_cfn_resource_name(
            resource.resource_name)
        function_cfn['Properties']['Events'] = {
            sns_cfn_name: {
                'Type': 'SQS',
                'Properties': {
                    'Queue': {
                        'Fn::Sub': (
                            'arn:aws:sqs:${AWS::Region}:${AWS::AccountId}:%s' %
                            resource.queue
                        )
                    },
                    'BatchSize': resource.batch_size,
                }
            }
        }

    def _register_cfn_resource_name(self, name):
        # type: (str) -> str
        cfn_name = to_cfn_resource_name(name)
        if cfn_name in self._seen_names:
            raise DuplicateResourceNameError(
                'A duplicate resource name was generated for '
                'the SAM template: %s' % cfn_name,
            )
        self._seen_names.add(cfn_name)
        return cfn_name


class TerraformGenerator(TemplateGenerator):

    template_file = "chalice.tf.json"

    def generate(self, resources):
        # type: (List[models.Model]) -> Dict[str, Any]
        template = {
            'resource': {},
            'terraform': {
                'required_version': '> 0.11.0'
            },
            'data': {
                'aws_caller_identity': {'chalice': {}},
                'aws_region': {'chalice': {}}
            }
        }
        for resource in resources:
            self.dispatch(resource, template)
        return template

    def _fref(self, lambda_function, attr='arn'):
        # type: (models.ManagedModel, str) -> str
        return '${aws_lambda_function.%s.%s}' % (
            lambda_function.resource_name, attr)

    def _arnref(self, arn_template, **kw):
        # type: (str, str) -> str
        d = dict(
            region='${aws_region.chalice.name}',
            account_id='${aws_caller_identity.chalice.account_id}')
        d.update(kw)
        return arn_template % d

    def _generate_managediamrole(self, resource, template):
        # type: (models.ManagedIAMRole, Dict[str, Any]) -> None
        template['resource'].setdefault('aws_iam_role', {})[
            resource.resource_name] = {
                'name': resource.role_name,
                'assume_role_policy': json.dumps(resource.trust_policy)
        }

        template['resource'].setdefault('aws_iam_role_policy', {})[
            resource.resource_name] = {
                'name': resource.resource_name + 'Policy',
                'policy': json.dumps(resource.policy.document),
                'role': '${aws_iam_role.%s.id}' % resource.resource_name,
        }

    def _generate_s3bucketnotification(self, resource, template):
        # type: (models.S3BucketNotification, Dict[str, Any]) -> None

        bnotify = {
            'events': resource.events,
            'lambda_function_arn': self._fref(resource.lambda_function)
        }

        if resource.prefix:
            bnotify['filter_prefix'] = resource.prefix
        if resource.suffix:
            bnotify['filter_suffix'] = resource.suffix

        template['resource'].setdefault('aws_s3_bucket_notification', {})[
            resource.resource_name] = {
                'bucket': resource.bucket,
                'lambda_function': bnotify
        }

        template['resource'].setdefault('aws_lambda_permission', {})[
            resource.resource_name] = {
                'statement_id': resource.resource_name,
                'action': 'lambda:InvokeFunction',
                'function_name': self._fref(resource.lambda_function),
                'principal': 's3.amazonaws.com',
                'source_arn': 'arn:aws:s3:::%s' % resource.bucket
        }

    def _generate_sqseventsource(self, resource, template):
        # type: (models.SQSEventSource, Dict[str, Any]) -> None
        template['resource'].setdefault('aws_lambda_event_source_mapping', {})[
            resource.resource_name] = {
                'event_source_arn': self._arnref(
                    "arn:aws:sqs:%(region)s:%(account_id)s:%(queue)s",
                    queue=resource.queue),
                'batch_size': resource.batch_size,
                'function_name': self._fref(resource.lambda_function),
        }

    def _generate_snslambdasubscription(self, resource, template):
        # type: (models.SNSLambdaSubscription, Dict[str, Any]) -> None

        if resource.topic.startswith('arn:aws'):
            topic_arn = resource.topic
        else:
            topic_arn = self._arnref(
                'arn:aws:sns:%(region)s:%(account_id)s:%(topic)s',
                topic=resource.topic)

        template['resource'].setdefault('aws_sns_topic_subscription', {})[
            resource.resource_name] = {
                'topic_arn': topic_arn,
                'protocol': 'lambda',
                'endpoint': self._fref(resource.lambda_function)
        }
        template['resource'].setdefault('aws_lambda_permission', {})[
            resource.resource_name] = {
                'function_name': self._fref(
                    resource.lambda_function),
                'action': 'lambda:InvokeFunction',
                'principal': 'sns.amazonaws.com',
                'source_arn': topic_arn
        }

    def _generate_scheduledevent(self, resource, template):
        # type: (models.ScheduledEvent, Dict[str, Any]) -> None

        template['resource'].setdefault(
            'aws_cloudwatch_event_rule', {})[
                resource.resource_name] = {
                    'name': resource.resource_name,
                    'schedule_expression': resource.schedule_expression
        }
        template['resource'].setdefault(
            'aws_cloudwatch_event_target', {})[
                resource.resource_name] = {
                    'rule': '${aws_cloudwatch_event_rule.%s.name}' % (
                        resource.resource_name),
                    'target_id': resource.resource_name,
                    'arn': self._fref(resource.lambda_function)
        }
        template['resource'].setdefault(
            'aws_lambda_permission', {})[
                resource.resource_name] = {
                    'function_name': self._fref(resource.lambda_function),
                    'action': 'lambda:InvokeFunction',
                    'principal': 'events.amazonaws.com',
                    'source_arn': "${aws_cloudwatch_event_rule.%s.arn}" % (
                        resource.resource_name)
        }

    def _generate_lambdafunction(self, resource, template):
        # type: (models.LambdaFunction, Dict[str, Any]) -> None

        func_definition = {
            'function_name': resource.function_name,
            'runtime': resource.runtime,
            'handler': resource.handler,
            'memory_size': resource.memory_size,
            'tags': resource.tags,
            'timeout': resource.timeout,
            'source_code_hash': '${filebase64sha256("%s")}' % (
                resource.deployment_package.filename),
            'filename': resource.deployment_package.filename}

        if resource.security_group_ids and resource.subnet_ids:
            func_definition['vpc_config'] = {
                'subnet_ids': resource.subnet_ids,
                'security_group_ids': resource.security_group_ids
            }
        if resource.reserved_concurrency is not None:
            func_definition['reserved_concurrent_executions'] = (
                resource.reserved_concurrency
            )
        if resource.environment_variables:
            func_definition['environment'] = {
                'variables': resource.environment_variables
            }
        if resource.layers:
            func_definition['layers'] = list(resource.layers)

        if isinstance(resource.role, models.ManagedIAMRole):
            func_definition['role'] = '${aws_iam_role.%s.arn}' % (
                resource.role.resource_name)
        else:
            # resource is a PreCreatedIAMRole.
            role = cast(models.PreCreatedIAMRole, resource.role)
            func_definition['role'] = role.role_arn

        template['resource'].setdefault('aws_lambda_function', {})[
            resource.resource_name] = func_definition

    def _generate_restapi(self, resource, template):
        # type: (models.RestAPI, Dict[str, Any]) -> None

        # typechecker happiness
        swagger_doc = cast(Dict, resource.swagger_doc)
        template['resource'].setdefault('aws_api_gateway_rest_api', {})[
            resource.resource_name] = {
                'body': json.dumps(swagger_doc),
                # Terraform will diff explicitly configured attributes
                # to the current state of the resource. Attributes configured
                # via swagger on the REST api need to be duplicated here, else
                # terraform will set them back to empty.
                'name': swagger_doc['info']['title'],
                'binary_media_types': swagger_doc[
                    'x-amazon-apigateway-binary-media-types']
        }

        template['resource'].setdefault('aws_api_gateway_stage', {})[
            resource.resource_name] = {
                'rest_api_id': '${aws_api_gateway_rest_api.%s.id}' % (
                    resource.resource_name),
                'stage_name': resource.api_gateway_stage,
                'deployment_id': '${aws_api_gateway_deployment.%s.id}' % (
                    resource.resource_name)
        }

        template['resource'].setdefault('aws_api_gateway_deployment', {})[
            resource.resource_name] = {
                'rest_api_id': '${aws_api_gateway_rest_api.%s.id}' % (
                    resource.resource_name),
        }

        template['resource'].setdefault('aws_lambda_permission', {})[
            resource.resource_name + '_invoke'] = {
                'function_name': self._fref(resource.lambda_function),
                'action': 'lambda:InvokeFunction',
                'principal': 'apigateway.amazonaws.com',
                'source_arn':
                    "${aws_api_gateway_rest_api.%s.execution_arn}/*/*/*" % (
                        resource.resource_name)
        }

        template.setdefault('output', {})[
            'EndpointURL'] = {
                'value': '${aws_api_gateway_stage.%s.invoke_url}' % (
                    resource.resource_name)
        }

        for auth in resource.authorizers:
            template['resource']['aws_lambda_permission'][
                auth.resource_name + '_invoke'] = {
                    'function_name': self._fref(auth),
                    'action': 'lambda:InvokeFunction',
                    'principal': 'apigateway.amazonaws.com',
                    'source_arn': (
                        "${aws_api_gateway_rest_api.%s.execution_arn}" % (
                            auth.resource_name) + "/*/*/*")
            }


class AppPackager(object):
    def __init__(self,
                 templater,         # type: TemplateGenerator
                 resource_builder,  # type: ResourceBuilder
                 post_processor,    # type: TemplatePostProcessor
                 osutils,           # type: OSUtils
                 ):
        # type: (...) -> None
        self._templater = templater
        self._resource_builder = resource_builder
        self._template_post_processor = post_processor
        self._osutils = osutils

    def _to_json(self, doc):
        # type: (Any) -> str
        return serialize_to_json(doc)

    def package_app(self, config, outdir, chalice_stage_name):
        # type: (Config, str, str) -> None
        # Deployment package
        resources = self._resource_builder.construct_resources(
            config, chalice_stage_name)

        template = self._templater.generate(resources)
        if not self._osutils.directory_exists(outdir):
            self._osutils.makedirs(outdir)
        self._template_post_processor.process(
            template, config, outdir, chalice_stage_name)
        self._osutils.set_file_contents(
            filename=os.path.join(outdir, self._templater.template_file),
            contents=self._to_json(template),
            binary=False
        )


class TemplatePostProcessor(object):
    def __init__(self, osutils):
        # type: (OSUtils) -> None
        self._osutils = osutils

    def process(self, template, config, outdir, chalice_stage_name):
        # type: (Dict[str, Any], Config, str, str) -> None
        raise NotImplementedError()


class SAMPostProcessor(TemplatePostProcessor):

    def process(self, template, config, outdir, chalice_stage_name):
        # type: (Dict[str, Any], Config, str, str) -> None
        self._fixup_deployment_package(template, outdir)

    def _fixup_deployment_package(self, template, outdir):
        # type: (Dict[str, Any], str) -> None
        # NOTE: This isn't my ideal way to do this.  I'd like
        # to move this into the build step where something
        # copies the DeploymentPackage.filename over to the
        # outdir.  That would require plumbing through user
        # provided params such as "outdir" into the build stage
        # somehow, which isn't currently possible.
        copied = False
        for resource in template['Resources'].values():
            if resource['Type'] != 'AWS::Serverless::Function':
                continue
            original_location = resource['Properties']['CodeUri']
            new_location = os.path.join(outdir, 'deployment.zip')
            if not copied:
                self._osutils.copy(original_location, new_location)
                copied = True
            resource['Properties']['CodeUri'] = './deployment.zip'


class TerraformPostProcessor(TemplatePostProcessor):

    def process(self, template, config, outdir, chalice_stage_name):
        # type: (Dict[str, Any], Config, str, str) -> None

        copied = False
        for r in template['resource'].get('aws_lambda_function', {}).values():
            if not copied:
                asset_path = os.path.join(outdir, 'deployment.zip')
                self._osutils.copy(r['filename'], asset_path)
                copied = True
            r['filename'] = "./deployment.zip"
            r['source_code_hash'] = '${filebase64sha256("./deployment.zip")}'
