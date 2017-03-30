# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
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
"""Drivers for volumes."""

from oslo_concurrency import processutils
from oslo_config import cfg
from oslo_config import types
from oslo_log import log as logging
from oslo_utils import excutils
import six

LOG = logging.getLogger(__name__)


volume_opts = [
    cfg.IntOpt('num_shell_tries',
               default=3,
               help='Number of times to attempt to run flakey shell commands'),
    cfg.IntOpt('reserved_percentage',
               default=0,
               min=0, max=100,
               help='The percentage of backend capacity is reserved'),
    cfg.IntOpt('num_volume_device_scan_tries',
               default=3,
               help='The maximum number of times to rescan targets'
                    ' to find volume'),
    cfg.StrOpt('driver_client_cert_key',
               help='The path to the client certificate key for verification, '
                    'if the driver supports it.'),
    cfg.StrOpt('driver_client_cert',
               help='The path to the client certificate for verification, '
                    'if the driver supports it.'),
    cfg.BoolOpt('driver_use_ssl',
                default=False,
                help='Tell driver to use SSL for connection to backend '
                     'storage if the driver supports it.'),
    cfg.StrOpt('driver_data_namespace',
               help='Namespace for driver private data values to be '
                    'saved in.'),
    cfg.StrOpt('filter_function',
               help='String representation for an equation that will be '
                    'used to filter hosts. Only used when the driver '
                    'filter is set to be used by the Cinder scheduler.'),
    cfg.BoolOpt('driver_ssl_cert_verify',
                default=False,
                help='If set to True the http client will validate the SSL '
                     'certificate of the backend endpoint.'),
    cfg.StrOpt('driver_ssl_cert_path',
               help='Can be used to specify a non default path to a '
               'CA_BUNDLE file or directory with certificates of '
               'trusted CAs, which will be used to validate the backend'),
    cfg.ListOpt('trace_flags',
                help='List of options that control which trace info '
                     'is written to the DEBUG log level to assist '
                     'developers. Valid values are method and api.')
]

# for backward compatibility

CONF = cfg.CONF
CONF.register_opts(volume_opts)


class VolumeDriver(object):
    """This class will be deprecated soon.

    Please use the abstract classes above for new drivers.
    """
    def check_for_setup_error(self):
        raise NotImplementedError()

    def create_volume(self, volume):
        raise NotImplementedError()

    def create_volume_from_snapshot(self, volume, snapshot):
        raise NotImplementedError()

    def create_replica_test_volume(self, volume, src_vref):
        raise NotImplementedError()

    def delete_volume(self, volume):
        raise NotImplementedError()

    def create_snapshot(self, snapshot):
        raise NotImplementedError()

    def delete_snapshot(self, snapshot):
        raise NotImplementedError()

    def local_path(self, volume):
        raise NotImplementedError()

    def clear_download(self, context, volume):
        pass

    def extend_volume(self, volume, new_size):
        msg = _("Extend volume not implemented")
        raise NotImplementedError(msg)

    def manage_existing(self, volume, existing_ref):
        msg = _("Manage existing volume not implemented.")
        raise NotImplementedError(msg)

    def manage_existing_get_size(self, volume, existing_ref):
        msg = _("Manage existing volume not implemented.")
        raise NotImplementedError(msg)

    def unmanage(self, volume):
        pass

    def manage_existing_snapshot(self, snapshot, existing_ref):
        msg = _("Manage existing snapshot not implemented.")
        raise NotImplementedError(msg)

    def manage_existing_snapshot_get_size(self, snapshot, existing_ref):
        msg = _("Manage existing snapshot not implemented.")
        raise NotImplementedError(msg)

    def unmanage_snapshot(self, snapshot):
        """Unmanage the specified snapshot from Cinder management."""

    def retype(self, context, volume, new_type, diff, host):
        return False, None

    def reenable_replication(self, context, volume):
        msg = _("sync_replica not implemented.")
        raise NotImplementedError(msg)

    def promote_replica(self, context, volume):
        msg = _("promote_replica not implemented.")
        raise NotImplementedError(msg)

    # #######  Interface methods for DataPath (Connector) ########
    def ensure_export(self, context, volume):
        raise NotImplementedError()

    def create_export(self, context, volume, connector):
        raise NotImplementedError()

    def create_export_snapshot(self, context, snapshot, connector):
        raise NotImplementedError()

    def remove_export(self, context, volume):
        raise NotImplementedError()

    def remove_export_snapshot(self, context, snapshot):
        raise NotImplementedError()

    def initialize_connection(self, volume, connector, **kwargs):
        raise NotImplementedError()

    def initialize_connection_snapshot(self, snapshot, connector, **kwargs):
        """Allow connection from connector for a snapshot."""

    def terminate_connection(self, volume, connector, **kwargs):
        """Disallow connection from connector"""

    def terminate_connection_snapshot(self, snapshot, connector, **kwargs):
        """Disallow connection from connector for a snapshot."""

    def create_consistencygroup(self, context, group):
        """Creates a consistencygroup.

        :param context: the context of the caller.
        :param group: the dictionary of the consistency group to be created.
        :returns: model_update

        model_update will be in this format: {'status': xxx, ......}.

        If the status in model_update is 'error', the manager will throw
        an exception and it will be caught in the try-except block in the
        manager. If the driver throws an exception, the manager will also
        catch it in the try-except block. The group status in the db will
        be changed to 'error'.

        For a successful operation, the driver can either build the
        model_update and return it or return None. The group status will
        be set to 'available'.
        """
        raise NotImplementedError()

    def create_consistencygroup_from_src(self, context, group, volumes,
                                         cgsnapshot=None, snapshots=None,
                                         source_cg=None, source_vols=None):
        """Creates a consistencygroup from source.

        :param context: the context of the caller.
        :param group: the dictionary of the consistency group to be created.
        :param volumes: a list of volume dictionaries in the group.
        :param cgsnapshot: the dictionary of the cgsnapshot as source.
        :param snapshots: a list of snapshot dictionaries in the cgsnapshot.
        :param source_cg: the dictionary of a consistency group as source.
        :param source_vols: a list of volume dictionaries in the source_cg.
        :returns: model_update, volumes_model_update

        The source can be cgsnapshot or a source cg.

        param volumes is retrieved directly from the db. It is a list of
        storage.db.sqlalchemy.models.Volume to be precise. It cannot be
        assigned to volumes_model_update. volumes_model_update is a list of
        dictionaries. It has to be built by the driver. An entry will be
        in this format: {'id': xxx, 'status': xxx, ......}. model_update
        will be in this format: {'status': xxx, ......}.

        To be consistent with other volume operations, the manager will
        assume the operation is successful if no exception is thrown by
        the driver. For a successful operation, the driver can either build
        the model_update and volumes_model_update and return them or
        return None, None.
        """
        raise NotImplementedError()

    def delete_consistencygroup(self, context, group, volumes):
        """Deletes a consistency group.

        :param context: the context of the caller.
        :param group: the dictionary of the consistency group to be deleted.
        :param volumes: a list of volume dictionaries in the group.
        :returns: model_update, volumes_model_update

        param volumes is retrieved directly from the db. It is a list of
        storage.db.sqlalchemy.models.Volume to be precise. It cannot be
        assigned to volumes_model_update. volumes_model_update is a list of
        dictionaries. It has to be built by the driver. An entry will be
        in this format: {'id': xxx, 'status': xxx, ......}. model_update
        will be in this format: {'status': xxx, ......}.

        The driver should populate volumes_model_update and model_update
        and return them.

        The manager will check volumes_model_update and update db accordingly
        for each volume. If the driver successfully deleted some volumes
        but failed to delete others, it should set statuses of the volumes
        accordingly so that the manager can update db correctly.

        If the status in any entry of volumes_model_update is 'error_deleting'
        or 'error', the status in model_update will be set to the same if it
        is not already 'error_deleting' or 'error'.

        If the status in model_update is 'error_deleting' or 'error', the
        manager will raise an exception and the status of the group will be
        set to 'error' in the db. If volumes_model_update is not returned by
        the driver, the manager will set the status of every volume in the
        group to 'error' in the except block.

        If the driver raises an exception during the operation, it will be
        caught by the try-except block in the manager. The statuses of the
        group and all volumes in it will be set to 'error'.

        For a successful operation, the driver can either build the
        model_update and volumes_model_update and return them or
        return None, None. The statuses of the group and all volumes
        will be set to 'deleted' after the manager deletes them from db.
        """
        raise NotImplementedError()

    def update_consistencygroup(self, context, group,
                                add_volumes=None, remove_volumes=None):
        """Updates a consistency group.

        :param context: the context of the caller.
        :param group: the dictionary of the consistency group to be updated.
        :param add_volumes: a list of volume dictionaries to be added.
        :param remove_volumes: a list of volume dictionaries to be removed.
        :returns: model_update, add_volumes_update, remove_volumes_update

        model_update is a dictionary that the driver wants the manager
        to update upon a successful return. If None is returned, the manager
        will set the status to 'available'.

        add_volumes_update and remove_volumes_update are lists of dictionaries
        that the driver wants the manager to update upon a successful return.
        Note that each entry requires a {'id': xxx} so that the correct
        volume entry can be updated. If None is returned, the volume will
        remain its original status. Also note that you cannot directly
        assign add_volumes to add_volumes_update as add_volumes is a list of
        storage.db.sqlalchemy.models.Volume storage and cannot be used for
        db update directly. Same with remove_volumes.

        If the driver throws an exception, the status of the group as well as
        those of the volumes to be added/removed will be set to 'error'.
        """
        raise NotImplementedError()

    def create_cgsnapshot(self, context, cgsnapshot, snapshots):
        """Creates a cgsnapshot.

        :param context: the context of the caller.
        :param cgsnapshot: the dictionary of the cgsnapshot to be created.
        :param snapshots: a list of snapshot dictionaries in the cgsnapshot.
        :returns: model_update, snapshots_model_update

        param snapshots is retrieved directly from the db. It is a list of
        storage.db.sqlalchemy.models.Snapshot to be precise. It cannot be
        assigned to snapshots_model_update. snapshots_model_update is a list
        of dictionaries. It has to be built by the driver. An entry will be
        in this format: {'id': xxx, 'status': xxx, ......}. model_update
        will be in this format: {'status': xxx, ......}.

        The driver should populate snapshots_model_update and model_update
        and return them.

        The manager will check snapshots_model_update and update db accordingly
        for each snapshot. If the driver successfully deleted some snapshots
        but failed to delete others, it should set statuses of the snapshots
        accordingly so that the manager can update db correctly.

        If the status in any entry of snapshots_model_update is 'error', the
        status in model_update will be set to the same if it is not already
        'error'.

        If the status in model_update is 'error', the manager will raise an
        exception and the status of cgsnapshot will be set to 'error' in the
        db. If snapshots_model_update is not returned by the driver, the
        manager will set the status of every snapshot to 'error' in the except
        block.

        If the driver raises an exception during the operation, it will be
        caught by the try-except block in the manager and the statuses of
        cgsnapshot and all snapshots will be set to 'error'.

        For a successful operation, the driver can either build the
        model_update and snapshots_model_update and return them or
        return None, None. The statuses of cgsnapshot and all snapshots
        will be set to 'available' at the end of the manager function.
        """
        raise NotImplementedError()

    def delete_cgsnapshot(self, context, cgsnapshot, snapshots):
        """Deletes a cgsnapshot.

        :param context: the context of the caller.
        :param cgsnapshot: the dictionary of the cgsnapshot to be deleted.
        :param snapshots: a list of snapshot dictionaries in the cgsnapshot.
        :returns: model_update, snapshots_model_update

        param snapshots is retrieved directly from the db. It is a list of
        storage.db.sqlalchemy.models.Snapshot to be precise. It cannot be
        assigned to snapshots_model_update. snapshots_model_update is a list
        of dictionaries. It has to be built by the driver. An entry will be
        in this format: {'id': xxx, 'status': xxx, ......}. model_update
        will be in this format: {'status': xxx, ......}.

        The driver should populate snapshots_model_update and model_update
        and return them.

        The manager will check snapshots_model_update and update db accordingly
        for each snapshot. If the driver successfully deleted some snapshots
        but failed to delete others, it should set statuses of the snapshots
        accordingly so that the manager can update db correctly.

        If the status in any entry of snapshots_model_update is
        'error_deleting' or 'error', the status in model_update will be set to
        the same if it is not already 'error_deleting' or 'error'.

        If the status in model_update is 'error_deleting' or 'error', the
        manager will raise an exception and the status of cgsnapshot will be
        set to 'error' in the db. If snapshots_model_update is not returned by
        the driver, the manager will set the status of every snapshot to
        'error' in the except block.

        If the driver raises an exception during the operation, it will be
        caught by the try-except block in the manager and the statuses of
        cgsnapshot and all snapshots will be set to 'error'.

        For a successful operation, the driver can either build the
        model_update and snapshots_model_update and return them or
        return None, None. The statuses of cgsnapshot and all snapshots
        will be set to 'deleted' after the manager deletes them from db.
        """
        raise NotImplementedError()

    def clone_image(self, volume, image_location, image_id, image_meta,
                    image_service):
        return None, False

    def get_pool(self, volume):
        """Return pool name where volume reside on.

        :param volume: The volume hosted by the driver.
        :returns: name of the pool where given volume is in.
        """
        return None

    def migrate_volume(self, context, volume, host):
        return (False, None)
