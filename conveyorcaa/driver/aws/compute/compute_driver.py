# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

""" A connection to aws through boto3.
"""

import botocore

from conveyorcaa import context as req_context
from conveyorcaa import exception

from conveyorcaa.driver.aws import client
from conveyorcaa.driver import exception_ex
from conveyorcaa.driver.aws.compute import driver
from conveyorcaa.i18n import _LE
from oslo_log import log as logging
from oslo_serialization import jsonutils
from oslo_utils import excutils
import re
import string
import uuid

LOG = logging.getLogger(__name__)


AWS_INSTANCE_PENDING = 0
AWS_INSTANCE_RUNNING = 16
AWS_INSTANCE_SHUTTING_DOWN = 32
AWS_INSTANCE_TERMINATED = 48
AWS_INSTANCE_STOPPING = 64
AWS_INSTANCE_STOPPED = 80

NOSTATE = 0x00
RUNNING = 0x01
PAUSED = 0x03
SHUTDOWN = 0x04  # the VM is powered off
CRASHED = 0x06
SUSPENDED = 0x07

AWS_POWER_STATE = {
    AWS_INSTANCE_RUNNING: 0x01,
    AWS_INSTANCE_STOPPED: 0x04,
    AWS_INSTANCE_TERMINATED: 0x06,
    AWS_INSTANCE_PENDING: 0x00,
    AWS_INSTANCE_SHUTTING_DOWN:  0x00,
    AWS_INSTANCE_STOPPING: 0x00
}
AWS_VM_STATE = {
    AWS_INSTANCE_RUNNING: 'active',
    AWS_INSTANCE_PENDING: 'building',
    AWS_INSTANCE_STOPPED: 'stopped',
    AWS_INSTANCE_TERMINATED: 'deleted',
    AWS_INSTANCE_SHUTTING_DOWN: 'active',
    AWS_INSTANCE_STOPPING: 'active'
}


class AwsComputeDriver(driver.ComputeDriver):
    def __init__(self):
        self.aws_client = client.AwsClient()
        super(AwsComputeDriver, self).__init__()

    def after_detach_volume_fail(self, job_detail_info, **kwargs):
        pass

    def after_detach_volume_success(self, job_detail_info, **kwargs):
        pass

    def _trans_device_name(self, orig_device_name):
        return '/dev/sd' + orig_device_name[-1]

    def _get_device_name(self, context, instance_id):
        try:
            kwargs = {'InstanceIds': [instance_id]}
            instances = self.aws_client.get_aws_client(context)\
                            .describe_instances(**kwargs)
            bdms = instances[0].get('BlockDeviceMappings')
            used_letters = set()
            prefix = ''
            if bdms:
                for bdm in bdms:
                    device_name = bdm.get('DeviceName')
                    if not prefix:
                        m = re.compile('^/dev/(xv|s|h)d').match(device_name)
                        if m:
                            prefix = m.group()
                    used_letters.add(self._get_device_letter(device_name))
            unused = self._get_unused_letter(used_letters)
            return (prefix or '/dev/sd') + unused
        except Exception as e:
            LOG.error(_LE('Get device name error. '
                          'Error=%(e)s'), {'e': e})
            raise exception_ex.AttachVolumeFailed()

    def _strip_dev(self, device_name):
        """remove leading '/dev/'."""
        _dev = re.compile('^/dev/')
        return _dev.sub('', device_name) if device_name else device_name

    def _strip_prefix(self, device_name):
        """remove both leading /dev/ and xvd or sd or hd."""
        _pref = re.compile('^((xv|s|h)d)')
        device_name = self._strip_dev(device_name)
        return _pref.sub('', device_name)

    def _get_device_letter(self, device_name):
        _nums = re.compile('\d+')
        letter = self._strip_prefix(device_name)
        # NOTE(vish): delete numbers in case we have something like
        #             /dev/sda1
        return _nums.sub('', letter)

    def _get_unused_letter(self, used_letters):
        all_letters = set(list(string.ascii_lowercase))
        letters = list(all_letters - used_letters)
        # NOTE(vish): prepend ` so all shorter sequences sort first
        letters.sort(key=lambda x: x.rjust(2, '`'))
        return letters[0]

    def list_instance_uuids(self):
        """List VM instances from all nodes."""
        uuids = []
        try:
            context = req_context.RequestContext(is_admin=True,
                                                 project_id='default')
            servers = self.aws_client.get_aws_client(context)\
                                     .describe_instances()
        except botocore.exceptions.ClientError as e:
            reason = e.response.get('Error', {}).get('Message', 'Unkown')
            LOG.warn('List instances failed, the error is: %s' % reason)
            return uuids
        for server in servers:
            server_id = server.get('InstanceId')
            uuids.append(server_id)
        LOG.debug('List_instance_uuids: %s' % uuids)
        return uuids

    def attach_volume(self, context, volume_id, instance_id,
                      mountpoint=None,
                      disk_bus=None, device_type=None,
                      encryption=None):
        """Attach the disk to the instance at mountpoint using info."""
        LOG.debug('Start to attach volume %s to instance %s'
                  % (volume_id, instance_id))
        try:
            if mountpoint:
                device_name = self._trans_device_name(mountpoint)
            else:
                device_name = self._get_device_name(context, instance_id)
            LOG.debug(_LE('Attach volume %s to instance %s on aws')
                      % (volume_id, instance_id))
            self.aws_client.get_aws_client(context)\
                           .attach_volume(VolumeId=volume_id,
                                          InstanceId=instance_id,
                                          Device=device_name)
            LOG.debug('Attach volume %s to instance %s success'
                      % (volume_id, instance_id))
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE('Error from attach volume. '
                              'Error=%(e)s'), {'e': e})

    def detach_volume(self, volume, instance_id, mountpoint=None,
                      encryption=None):
        """Detach the disk attached to the instance."""
        volume_id = volume.get('VolumeId', None)
        LOG.debug(_LE('Start to detach volume %s from instance %s')
                  % (volume_id, instance_id))
        context = req_context.RequestContext(is_admin=True,
                                             project_id='default')
        try:
            LOG.debug(_LE('Detach volume %s from instance %s on aws')
                      % (volume_id, instance_id))
            self.aws_client.get_aws_client(context)\
                           .detach_volume(VolumeId=volume_id,
                                          InstanceId=instance_id)
            LOG.debug(_LE('Detach volume %s from instance %s success')
                      % (volume_id, instance_id))
        except botocore.exceptions.ClientError as e:
            reason = e.response.get('Error', {}).get('Message', 'Unkown')
            LOG.error(_LE('Detach volume failed, the error is: %s') % reason)
            error_code = e.response.get('Error', {}).get('Code', 'Unkown')
            if error_code == 'InvalidVolume.NotFound':
                LOG.warn('The volume %s not found on aws' % volume_id)
            elif error_code == 'InvalidInstanceID.NotFound':
                LOG.error(_LE('Detach volume failed, error is: %s') % reason)
                raise exception.InstanceNotFound(instance_id=instance_id)
            elif error_code == 'IncorrectState':
                kwargs = {'VolumeIds': [volume_id]}
                volumes = self.aws_client.get_aws_client(context)\
                                         .describe_volumes(**kwargs)
                volume_state = volumes[0].get('State')
                if volume_state == 'available':
                    LOG.warn(_LE('The volume %s is available on aws')
                             % volume_id)
                else:
                    with excutils.save_and_reraise_exception():
                        pass
            else:
                with excutils.save_and_reraise_exception():
                        pass
        except botocore.exceptions.WaiterError as e:
            reason = e.message
            LOG.warn(_LE('Cannot detach volume,operation time out'))
            with excutils.save_and_reraise_exception():
                LOG.error(_LE('Error from detach volume. '
                              'Error=%(e)s'), {'e': e})
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE('Error from detach volume '
                              'Error=%(e)s'), {'e': e})

    def show_instance_type(self, instance_type_id, ctxt=None):
        instance_type = self._aws_client.get_aws_client(ctxt). \
            describe_instance_type(instance_type_id)
        return self._format_instance_type(instance_type)

    def get_all_instance_types(self, ctxt=None, **kwargs):
        aws_types = self._aws_client.get_aws_client(ctxt). \
            describe_instance_types(**kwargs)
        instances_types = []
        for aws_type in aws_types:
            instance_type = self._format_instance_type(aws_type)
            instances_types.append(instance_type)
        return instances_types

    def _format_instance_type(self, aws_instance_type):
        instance_type = {}
        instance_type['id'] = aws_instance_type.get('id')
        instance_type['name'] = aws_instance_type.get('name')
        instance_type['vcpus'] = aws_instance_type.get('vcpus')
        instance_type['ram'] = aws_instance_type.get('ram')
        instance_type['os-flavor-access:is_public'] = 'true'
        return instance_type

    def get_instance(self, context, instance_id):
        LOG.debug('Get info of instance: %s' % instance_id)
        kwargs = {'InstanceIds': [instance_id]}
        try:
            instances_tmp = self.aws_client.get_aws_client(context)\
                                           .describe_instances(**kwargs)
            if instances_tmp:
                return self._format_instance(context, instances_tmp)
        except Exception as e:
            LOG.error(_LE('Get info of instance %(instance_id) error '
                          'Error=%(e)s'),
                      {'instance_id': instance_id,
                       'e': e})
            raise exception_ex.InstanceNotFound(instance_id=instance_id)

    def list_instances(self, context):
        LOG.debug('List instance info')
        try:
            instances = []
            instances_tmps = self.aws_client.get_aws_client(context)\
                                            .describe_instances()
            for ins in instances_tmps:
                instance = self._format_instance(context, ins)
                instances.append(instance)
                return instances
        except Exception as e:
            LOG.error(_LE('list instance error '
                          'Error=%(e)s'), {'e': e})
            raise exception_ex.InstanceError()

    def _format_instance(self, context, instance):
        instance_dict = {}
        tags = instance.get('Tags')
        if tags:
            for tag in tags:
                if tag.get('Key') == 'Name':
                    instance_dict['name'] = tag.get('Value')
                    break
        instance_dict['id'] = instance.get('InstanceId')
        instance_dict['OS-EXT-SRV-ATTR:ramdisk_id'] = instance.get(
            'RamdiskId')
        instance_dict['updated'] = None
        instance_dict['hostId'] = instance.get('Placement', {}) \
                                          .get('HostId', None)
        instance_dict['OS-EXT-SRV-ATTR:host'] = None
        nics = instance.get('NetworkInterfaces', None)
        if nics:
            instance_dict['addresses'] = self._format_address(nics)
        instance_dict['links'] = []
        instance_dict['tags'] = instance.get('Tags', [])
        instance_dict['key_name'] = instance.get('KeyName')
        instance_dict['image'] = ''
        userdata = self.aws_client.get_aws_client(context) \
                                  .describe_instance_attribute(
            instance.get('InstanceId'), Attribute='userData').get('UserData',
                                                                  {})
        instance_dict['OS-EXT-SRV-ATTR:user_data'] = userdata.get('Value')
        instance_dict['OS-EXT-STS:task_state'] = None
        instance_dict['OS-EXT-STS:vm_state'] = AWS_VM_STATE.get(
            instance.get('State').get('Code'))
        instance_dict['OS-EXT-STS:power_state'] = AWS_POWER_STATE.get(
            instance.get('State').get('Code'))
        instance_dict['OS-EXT-SRV-ATTR:instance_name'] = ''
        instance_dict['OS-EXT-SRV-ATTR:root_device_name'] = instance.get(
            'RootDeviceName')
        instance_dict['OS-SRV-USG:launched_at'] = instance.get('LaunchTime')
        instance_dict['locked'] = 'false'
        instance_dict['flavor'] = {'id': instance.get('InstanceType')}
        securityGroups = instance.get('SecurityGroups')
        if securityGroups:
            instance_dict['security_groups'] = self._format_sg(securityGroups)
        instance_dict['description'] = None
        instance_dict['OS-EXT-SRV-ATTR:kernel_id'] = instance.get('KernelId')
        instance_dict['host_status'] = 'UP'
        instance_dict['OS-EXT-AZ:availability_zone'] = instance.get(
            'Placement').get('AvailabilityZone')
        instance_dict['user_id'] = ''
        instance_dict['OS-EXT-SRV-ATTR:launch_index'] = instance.get(
            'AmiLaunchIndex')
        bdms = instance.get('BlockDeviceMappings')
        if bdms:
            instance_dict['os-extended-volumes:volumes_attached'] = \
                self._format_bdms(bdms)
        else:
            instance_dict['os-extended-volumes:volumes_attached'] = []
        instance_dict['created'] = None
        instance_dict['tenant_id'] = ''
        instance_dict['OS-DCF:diskConfig'] = ''
        instance_dict['OS-EXT-SRV-ATTR:hypervisor_hostname'] = ''
        instance_dict['accessIPv4'] = ''
        instance_dict['accessIPv6'] = ''
        instance_dict['OS-EXT-SRV-ATTR:reservation_id'] = ''
        instance_dict['OS-EXT-SRV-ATTR:hostname'] = ''
        instance_dict['progress'] = 0
        instance_dict['config_drive'] = ''
        instance_dict['OS-SRV-USG:terminated_at'] = None
        instance_dict['metadata'] = {}
        return instance_dict

    def _format_bdms(self, bdms):
        bdm_list = []
        for bdm in bdms:
            block_device_mapping = {}
            block_device_mapping['id'] = bdm.get('Ebs').get('VolumeId')
            block_device_mapping['delete_on_termination'] = bdm.get(
                'Ebs').get('DeleteOnTermination')
            bdm_list.append(block_device_mapping)
        return bdm_list

    def _format_sg(self, securityGroups):
        sg_list = []
        for sg in securityGroups:
            securityGroup = {}
            securityGroup['name'] = securityGroups.get('GroupName')
            securityGroup['id'] = securityGroups.get('GroupId')
            sg_list.append(securityGroup)
        return sg_list

    def _format_address(self, nics):
        address_list = []
        for nic in nics:
            address = {}
            address['OS-EXT-IPS-MAC:mac_addr'] = nic.get('MacAddress')
            if nic.get('Ipv6Addresses'):
                address['version'] = 6
            else:
                address['version'] = 4
            address['addr'] = nic.get('PrivateIpAddress')
            address['OS-EXT-IPS:type'] = 'fixed'
            address_list.append(address)
            association = nic.get('Association')
            if association:
                f_addr = {}
                f_addr['OS-EXT-IPS-MAC:mac_addr'] = None
                f_addr['version'] = 4
                f_addr['addr'] = association.get('PublicIp')
                f_addr['OS-EXT-IPS:type'] = 'floating'
                address_list.append(f_addr)
        return address_list
