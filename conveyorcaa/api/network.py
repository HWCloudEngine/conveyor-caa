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
from conveyorcaa.i18n import _
from conveyorcaa import wsgi

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

volume_opts = [
    cfg.StrOpt('network_driver',
               default='',
               help='Driver to connect cloud'),
]

CONF.register_opts(volume_opts)


class NetWorkController(wsgi.Application):
    def __init__(self):
        network_driver_cls = importutils.import_class(CONF.network_driver)
        self.network_driver = network_driver_cls()
        super(NetWorkController, self).__init__()

    def list(self, request, scan=True):
        """ List all host devices. """
        LOG.debug(_('Query all volume start'))
        self.volume_driver.list_volumes()

    def show(self, request, volume):
        pass

    def show_subnet(self, request, subnet_id):
        pass

    def list_subnets(self, request, **kwargs):
        pass

    def show_security_group(self, request, secgroup_id):
        pass

    def list_security_groups(self, request, **kwargs):
        pass

    def show_port(self, request, port_id):
        pass

    def list_ports(self, request, **kwargs):
        pass

    def show_router(self, request, router_id):
        pass

    def list_routers(self, request, **kwargs):
        pass

    def show_floatingip(self, request, floatingip_id):
        pass

    def list_floatingips(self, request, **kwargs):
        pass


def create_router(mapper):
    controller = NetWorkController()

    mapper.connect('/network',
                   controller=controller,
                   action='list',
                   conditions=dict(method=['GET']))
    mapper.connect('/network/details',
                   controller=controller,
                   action='show',
                   conditions=dict(method=['GET']))
