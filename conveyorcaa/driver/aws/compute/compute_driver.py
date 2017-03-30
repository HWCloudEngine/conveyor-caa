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

LOG = logging.getLogger(__name__)


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

    def list_instances(self):
        """List VM instances from all nodes.

        :return: list of instance id. e.g.['id_001', 'id_002', ...]
        """
        instances = []
        context = req_context.RequestContext(is_admin=True,
                                             project_id='default')
        try:
            servers = self.aws_client.get_aws_client(context)\
                                     .describe_instances()
        except botocore.exceptions.ClientError as e:
            reason = e.response.get('Error', {}).get('Message', 'Unkown')
            LOG.warn('List instances failed, the error is: %s' % reason)
            return instances
        for server in servers:
            tags = server.get('Tags')
            server_name = None
            for tag in tags:
                if tag.get('key') == 'Name':
                    server_name = tag.get('Value')
                    break
            if server_name:
                instances.append(server_name)
        LOG.debug('List_instance: %s' % instances)
        return instances

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
