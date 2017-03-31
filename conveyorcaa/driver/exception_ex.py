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

from conveyorcaa.exception import ConveyorCaaException
from conveyorcaa.i18n import _


class MultiInstanceConfusion(ConveyorCaaException):
    msg_fmt = _("More than one instance are found")


class MultiVolumeConfusion(ConveyorCaaException):
    msg_fmt = _("More than one volume are found")


class ProviderCreateInstanceFailed(ConveyorCaaException):
    msg_fmt = _("Provider create instance failed,error msg: %(reason)s")


class ProviderCreateVolumeFailed(ConveyorCaaException):
    msg_fmt = _("Provider create volume failed,error msg: %(reason)s")


class ProviderDeleteVolumeFailed(ConveyorCaaException):
    msg_fmt = _("Provider delete volume failed,error msg: %(reason)s")


class ProviderCreateSnapshotFailed(ConveyorCaaException):
    msg_fmt = _("Provider create volume failed,error msg: %(reason)s")


class ProviderDeleteSnapshotFailed(ConveyorCaaException):
    msg_fmt = _("Provider delete volume failed,error msg: %(reason)s")


class AccountNotConfig(ConveyorCaaException):
    msg_fmt = _('os account info not config')


class OsAwsConnectFailed(ConveyorCaaException):
    msg_fmt = _("connect aws failed!")


class AvailabilityZoneNotFoundError(ConveyorCaaException):
    msg_fmt = _("can not get availability zone.")


class VolumeTypeNotFoundError(ConveyorCaaException):
    msg_fmt = _("can not find volume type %(type_id)s.")


class VolumeError(ConveyorCaaException):
    msg_fmt = _("Query volumes failed.")


class InstanceError(ConveyorCaaException):
    msg_fmt = _("Query instance failed.")


class FlavorError(ConveyorCaaException):
    msg_fmt = _("Query flavor failed.")


class FlavorNotFound(ConveyorCaaException):
    msg_fmt = _("can not find flavor %(flavor_id)s.")


class InstanceNotFound(ConveyorCaaException):
    msg_fmt = _("can not find flavor %(instance_id)s.")


class ProviderImageNotFound(ConveyorCaaException):
    msg_fmt = _("Provider delete volume failed,error msg: %(reason)s")


class AttachVolumeFailed(ConveyorCaaException):
    msg_fmt = _("Attach volume on provider cloud failed")


class FloatingIPException(ConveyorCaaException):
    msg_fmt = _('FloatingIP Operation Failed')
