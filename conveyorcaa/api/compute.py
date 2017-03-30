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


from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import importutils

import webob


from conveyorcaa import exception
from conveyorcaa.i18n import _
from conveyorcaa import wsgi

computer_opts = [
    cfg.StrOpt('compute_driver',
               default='conveyorcaa.driver.aws.compute.'
                       'compute_driver.AwsComputeDriver',
               help='Driver to connect cloud'),
]


CONF = cfg.CONF
CONF.register_opts(computer_opts)


LOG = logging.getLogger(__name__)


class ContainerController(wsgi.Application):
    def __init__(self):
        compute_driver_class = importutils.import_class(CONF.compute_driver)
        self.compute_driver = compute_driver_class()

    def show(self, server_id):
        pass

    def list(self):
        '''Query all instances'''
        LOG.debug(_('Query all instance start'))
        self.compute_driver.list_instances()

    def get_flavor(self, flavor_id):
        pass

    def list_flavor(self):
        pass

    def get_keypair(self, keypair_id):
        pass

    def list_keypair(self):
        pass

    def attach_volume(self, req, id, body):
        volume_id = body.get('volumeId', None)
        mountpoint = body.get('device', None)

        if not id or not volume_id:
            msg = _("Invalid request to attach volume to an invalid target")
            LOG.error(msg)
            raise webob.exc.HTTPBadRequest(explanation=msg)

        try:
            self.compute_driver.attach_volume(volume_id, id,
                                              mountpoint=mountpoint)
        except Exception as e:
            msg = _('Driver attach volume failed: %s') % e
            LOG.error(msg)
            raise webob.exc.HTTPBadRequest(explanation=msg)

        return webob.Response(status_int=202)

    def detach_volume(self, req, id, body):
        context = None
        try:
            volume = self.compute_driver.get(context, id)
        except exception.VolumeNotFound as error:
            raise webob.exc.HTTPNotFound(explanation=error.msg)

        attachment_id = body.get('attachment_id', None)

        self.compute_driver.detach_volume(context, volume, attachment_id)
        return webob.Response(status_int=202)


def create_router(mapper):
    controller = ContainerController()
    mapper.connect('/server/list',
                   controller=controller,
                   action='list',
                   conditions=dict(method=['GET']))

    mapper.connect('/server/attach-volume',
                   controller=controller,
                   action='attach-volume',
                   conditions=dict(method=['POST']))

    mapper.connect('/server/detach_volume',
                   controller=controller,
                   action='detach_volume',
                   conditions=dict(method=['POST']))
