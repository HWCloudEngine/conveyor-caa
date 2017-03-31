# Copyright 2014 IBM Corp.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import boto3
import json

from oslo_config import cfg

from botocore import exceptions
from conveyorcaa.driver import exception_ex
from conveyorcaa.i18n import _LE
from oslo_log import log as logging
from oslo_utils import excutils

aws_opts = [
    cfg.StrOpt('aws_access_key',
               help='AK value to use to connect to AWS.'),
    cfg.StrOpt('aws_secret_key',
               help='SK value to use to connect to AWS.'),
    cfg.StrOpt('aws_region',
               help='region value to use to connect to AWS.'),
    cfg.StrOpt('aws_volume_type_config_path',
               default='/etc/conveyorcaa/aws_volume_types.json',
               help='region value to use to connect to AWS.'),
    cfg.StrOpt('aws_instance_type_config_path',
               default='/etc/conveyorcaa/aws_instance_types.json',
               help='region value to use to connect to AWS.'),
]


CONF = cfg.CONF
CONF.register_opts(aws_opts, group='aws')

LOG = logging.getLogger(__name__)


class AwsClient(object):
    def __init__(self, *args, **kwargs):

        self._boto3client = None
        super(AwsClient, self).__init__(*args, **kwargs)

    def create_ec2_client(self, context=None):

        access_key = CONF.aws.aws_access_key
        secret_key = CONF.aws.aws_secret_key
        region_name = CONF.aws.aws_region
        kwargs = {}
        kwargs['aws_access_key_id'] = access_key
        kwargs['aws_secret_access_key'] = secret_key
        kwargs['region_name'] = region_name

        return boto3.client('ec2', **kwargs)

    def get_aws_client(self, context):
        if not self._boto3client:
            try:
                ec2_client = self.create_ec2_client(context)
                self._boto3client = AwsClientPlugin(ec2_client)
            except Exception as e:
                LOG.error(_LE('Create aws client failed: %s'), e)
                raise exception_ex.OsAwsConnectFailed

        return self._boto3client


class AwsClientPlugin(object):
    def __init__(self, ec2_client, **kwargs):
        self._ec2_client = ec2_client

    def create_tags(self, **kwargs):
        self._ec2_client.create_tags(**kwargs)

    def create_volume(self, **kwargs):
        vol = None
        try:
            vol = self._ec2_client.create_volume(**kwargs)
            waiter = self._ec2_client.get_waiter('volume_available')
            waiter.wait(VolumeIds=[vol['VolumeId']])
        except Exception as e:
            if vol:
                self.delete_volume(VolumeId=vol['VolumeId'])
            if isinstance(e, exceptions.ClientError):
                reason = e.response.get('Error', {}).get('Message', 'Unkown')
                LOG.error(_LE("Aws create volume failed! error_msg: %s"),
                          reason)
                raise exception_ex.ProviderCreateVolumeFailed(reason=reason)
            else:
                raise
        else:
            return vol

    def delete_volume(self, **kwargs):
        try:
            self._ec2_client.delete_volume(**kwargs)
            waiter = self._ec2_client.get_waiter('volume_deleted')
            waiter.wait(VolumeIds=[kwargs['VolumeId']])
        except Exception as e:
            if isinstance(e, exceptions.ClientError):
                reason = e.response.get('Error', {}).get('Message', 'Unkown')
                LOG.error(_LE("Aws delete volume failed! error_msg: %s"),
                          reason)
                raise exception_ex.ProviderDeleteVolumeFailed(reason=reason)
            else:
                raise

    def create_snapshot(self, **kwargs):
        snapshot = None
        try:
            snapshot = self._ec2_client.create_snapshot(**kwargs)
            waiter = self._ec2_client.get_waiter('snapshot_completed')
            waiter.wait(SnapshotIds=[snapshot['SnapshotId']])
        except Exception as e:
            if snapshot:
                self.delete_snapshot(SnapshotId=snapshot['SnapshotId'])
            if isinstance(e, exceptions.ClientError):
                reason = e.response.get('Error', {}).get('Message', 'Unkown')
                LOG.error(_LE("Aws create snapshot failed! error_msg: %s"),
                          reason)
                raise exception_ex.ProviderCreateSnapshotFailed(reason=reason)
            else:
                raise
        else:
            return snapshot

    def describe_volumes(self, **kwargs):
        response = self._ec2_client.describe_volumes(**kwargs)
        volumes = response.get('Volumes', [])
        return volumes

    def describe_snapshots(self, **kwargs):
        response = self._ec2_client.describe_snapshots(**kwargs)
        snapshots = response.get('Snapshots', [])
        return snapshots

    def delete_snapshot(self, **kwargs):
        try:
            self._ec2_client.delete_snapshot(**kwargs)
        except Exception as e:
            if isinstance(e, exceptions.ClientError):
                reason = e.response.get('Error', {}).get('Message', 'Unkown')
                LOG.error(_LE("Aws delete snapshot failed! error_msg: %s"),
                          reason)
                raise exception_ex.ProviderDeleteSnapshotFailed(reason=reason)
            else:
                raise

    def create_instance(self, **kwargs):
        instance_ids = []
        try:
            response = self._ec2_client.run_instances(**kwargs)
            instances = response.get('Instances', [])
            for instance in instances:
                instance_ids.append(instance.get('InstanceId'))
            waiter = self._ec2_client.get_waiter('instance_running')
            waiter.wait(InstanceIds=instance_ids)
            return instance_ids
        except Exception:
            with excutils.save_and_reraise_exception():
                if instance_ids:
                    self.delete_instances(InstanceIds=instance_ids)
        return instance_ids

    def start_instances(self, **kwargs):
        self._ec2_client.start_instances(**kwargs)
        instance_ids = kwargs.get('InstanceIds', [])
        if instance_ids:
            waiter = self._ec2_client.get_waiter('instance_running')
            waiter.wait(InstanceIds=instance_ids)

    def stop_instances(self, **kwargs):
        self._ec2_client.stop_instances(**kwargs)
        instance_ids = kwargs.get('InstanceIds', [])
        if instance_ids:
            waiter = self._ec2_client.get_waiter('instance_stopped')
            waiter.wait(InstanceIds=instance_ids)

    def delete_instances(self, **kwargs):
        self._ec2_client.terminate_instances(**kwargs)
        instance_ids = kwargs.get('InstanceIds', [])
        if instance_ids:
            waiter = self._ec2_client.get_waiter('instance_terminated')
            waiter.wait(InstanceIds=instance_ids)

    def describe_instances(self, **kwargs):
        instances = []
        response = self._ec2_client.describe_instances(**kwargs)
        reservations = response.get('Reservations', [])
        for reservation in reservations:
            instances.extend(reservation.get('Instances'))
        return instances

    def reboot_instances(self, **kwargs):
        self._ec2_client.reboot_instances(**kwargs)

    def detach_volume(self, **kwargs):
        self._ec2_client.detach_volume(**kwargs)
        volume_id = kwargs.get('VolumeId')
        if volume_id:
            volume_ids = [volume_id]
            waiter = self._ec2_client.get_waiter('volume_available')
            waiter.wait(VolumeIds=volume_ids)

    def attach_volume(self, **kwargs):
        self._ec2_client.attach_volume(**kwargs)
        volume_id = kwargs.get('VolumeId')
        if volume_id:
            volume_ids = [volume_id]
            waiter = self._ec2_client.get_waiter('volume_in_use')
            waiter.wait(VolumeIds=volume_ids)

    def describe_images(self, **kwargs):
        response = self._ec2_client.describe_images(**kwargs)
        images = response.get('Images', [])
        return images

    def allocate_address(self, **kwargs):
        return self._ec2_client.allocate_address(**kwargs)

    def release_address(self, **kwargs):
        return self._ec2_client.release_address(**kwargs)

    def assign_private_ip_addresses(self, **kwargs):
        return self._ec2_client.assign_private_ip_addresses(**kwargs)

    def unassign_private_ip_addresses(self, **kwargs):
        return self._ec2_client.unassign_private_ip_addresses(**kwargs)

    def associate_address(self, **kwargs):
        return self._ec2_client.associate_address(**kwargs)

    def disassociate_address(self, **kwargs):
        return self._ec2_client.disassociate_address(**kwargs)

    def describe_addresses(self, **kwargs):
        return self._ec2_client.describe_addresses(**kwargs)

    def describe_network_interfaces(self, **kwargs):
        return self._ec2_client.describe_network_interfaces(**kwargs)

    def create_network_interface(self, **kwargs):
        response = self._ec2_client.create_network_interface(**kwargs)
        interface = response.get('NetworkInterface')
        return interface

    def delete_network_interface(self, **kwargs):
        self._ec2_client.delete_network_interface(**kwargs)

    def describe_volume_types(self, **kwargs):

        file_path = CONF.aws.aws_volume_type_config_path
        try:
            content = open(file_path).read()
            con_json = json.loads(content)
        except Exception as e:
            LOG.error(_LE("Query aws volume types error: %s"), e)
            raise exception_ex.VolumeTypeNotFoundError(type_id="")

        return con_json

    def describe_volume_type(self, volume_type_id, **kwargs):

        file_path = CONF.aws.aws_volume_type_config_path
        try:
            content = open(file_path).read()
            con_json = json.loads(content)
            type_info = con_json.get(volume_type_id, None)
        except Exception as e:
            LOG.error(_LE("Query aws volume type %(type)s error: %(error)s"),
                      {'type': volume_type_id, 'error': e})
            raise exception_ex.VolumeTypeNotFoundError(type_id=volume_type_id)

        return type_info

    def describe_instance_types(self, **kwargs):

        file_path = CONF.aws.aws_instance_type_config_path
        try:
            content = open(file_path).read()
            con_json = json.loads(content)
        except Exception as e:
            LOG.error(_LE("Query aws instance types error: %s"), e)
            raise exception_ex.FlavorError()

        return con_json

    def describe_instance_type(self, instance_type_id, **kwargs):

        file_path = CONF.aws.aws_instance_type_config_path
        try:
            content = open(file_path).read()
            con_json = json.loads(content)
            type_info = con_json.get(instance_type_id, None)
        except Exception as e:
            LOG.error(_LE("Query aws instance type %(type)s error: %(error)s"),
                      {'type': instance_type_id, 'error': e})
            raise exception_ex.FlavorNotFound(flavor_id=instance_type_id)

        return type_info

    def describe_security_groups(self, **kwargs):
        response = self._ec2_client.describe_security_groups(**kwargs)
        security_groups = response.get('SecurityGroups', [])
        return security_groups

    def describe_subnets(self, **kwargs):
        response = self._ec2_client.describe_subnets(**kwargs)
        subnets = response.get('Subnets', [])
        return subnets

    def describe_internet_gateways(self, **kwargs):
        response = self._ec2_client.describe_internet_gateways(**kwargs)
        gateways = response.get('InternetGateways', [])
        return gateways
