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

"""
Volume Drivers for Amazon EC2 Block Storage
"""

from conveyorcaa.driver.aws import client
from conveyorcaa.driver import exception_ex
from conveyorcaa.i18n import _LE
from conveyorcaa.driver.aws.volume import driver

from oslo_config import cfg
from oslo_log import log as logging

LOG = logging.getLogger(__name__)

aws_opts = [

]
CONF = cfg.CONF
CONF.register_opts(aws_opts)


class AwsVolumeDriver(driver.VolumeDriver):
    CLOUD_DRIVER = True

    def __init__(self, *args, **kwargs):
        self._aws_client = client.AwsClient()
        super(AwsVolumeDriver, self).__init__(*args, **kwargs)

    def list_volumes(self, ctxt=None):
        aws_volumes = []
        try:
            aws_volumes = self._aws_client.get_aws_client(ctxt). \
                describe_volumes()
        except Exception as e:
            LOG.error(_LE("Query AWS volumes error: %s"), e)
            raise exception_ex.VolumeError
        return self.format_volumes(aws_volumes)

    def show_volume_type(self, volume_type_id, ctxt=None):
        volume_type = self._aws_client.get_aws_client(ctxt). \
            describe_volume_type(volume_type_id)

        volume_type = self._format_volume_type(volume_type)
        return volume_type

    def get_all_volume_types(self, ctxt=None, **kwargs):
        aws_types = self._aws_client.get_aws_client(ctxt). \
            describe_volume_types(**kwargs)

        volume_types = []
        for aws_type in aws_types:
            volume_type = self._format_volume_type(aws_type)
            volume_types.append(volume_type)

        return volume_types

    def format_volumes(self, aws_volumes):
        volumes = []
        for aws_volume in aws_volumes:
            volume = self._format_volume(aws_volume)
            volumes.append(volume)
        return volumes

    def _format_volume(self, aws_volume):
        volume = {}
        volume["availability_zone"] = aws_volume.get('AvailabilityZone', None)
        volume["os-vol-host-attr:host"] = None
        volume["encrypted"] = aws_volume.get('Encrypted', None)
        volume["updated_at"] = None
        volume["replication_status"] = None
        volume["snapshot_id"] = aws_volume.get('SnapshotId', None)
        volume["id"] = aws_volume.get('VolumeId', None)
        volume["size"] = aws_volume.get('Size', None)
        volume["user_id"] = None
        volume["os-vol-tenant-attr:tenant_id"] = None
        volume["os-vol-mig-status-attr:migstat"] = None
        volume["status"] = aws_volume.get('State', None)
        volume["display_description"] = ""
        volume["multiattach"] = None
        volume["source_volid"] = None
        volume["consistencygroup_id"] = None
        volume["os-vol-mig-status-attr:name_id"] = None
        volume["bootable"] = None
        volume["created_at"] = aws_volume.get('CreateTime', None)
        volume["volume_type"] = aws_volume.get('VolumeType', None)
        volume["migration_status"] = None

        tags = aws_volume.get('Tags', [])
        metadata = {}
        for tag in tags:
            key = tag.get('Key', '')
            value = tag.get('Value', '')
            if 'Name' == key:
                volume['display_name'] = value
            else:
                metadata[key] = value

        volume["volume_metadata"] = metadata

        attachments = aws_volume.get('Attachments', [])
        attaches = []
        for attachment in attachments:
            a = {'id': attachment.get('VolumeId', None),
                 'attachment_id': attachment.get('InstanceId', None),
                 'volume_id': attachment.get('VolumeId', None),
                 'server_id': attachment.get('InstanceId', None),
                 'attach_status': attachment.get('State', None),
                 'device': attachment.get('Device', None)
                 }
            attaches.append(a)

        volume["attachments"] = attaches

        return volume

    def _format_volume_type(self, aws_volume_type):

        volume_type = {}
        volume_type['id'] = aws_volume_type.get('id', None)
        volume_type['name'] = aws_volume_type.get('name', None)
        volume_type['extra_specs'] = aws_volume_type.get('extra_specs', None)
        volume_type['qos_specs_id'] = \
            aws_volume_type.get('qos_specs_id', None)
        volume_type['description'] = aws_volume_type.get('description', None)
