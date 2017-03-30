from webob import exc

from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import importutils

from conveyorcaa.i18n import _
from conveyorcaa import wsgi
from conveyorcaa.driver import exception_ex

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

volume_opts = [
    cfg.StrOpt('volume_driver',
               default='conveyorcaa.driver.aws.volume.'
                       'volume_driver.AwsVolumeDriver',
               help='Driver to connect cloud'),
]

CONF.register_opts(volume_opts)


class VolumeController(wsgi.Application):
    def __init__(self):
        volume_driver_cls = importutils.import_class(CONF.volume_driver)
        self.volume_driver = volume_driver_cls()
        super(VolumeController, self).__init__()

    def list(self, request, scan=True):
        """ List all host devices. """
        LOG.debug(_('Query all volume start'))
        volumes = self.volume_driver.list_volumes()
        return volumes

    def show(self, request, volume_id):
        volumes = self.volume_driver.list_volumes()
        volume = None
        for vol in volumes:
            vol_id = vol.get('id', None)
            if volume_id == vol_id:
                volume = vol
                break
        if not volume:
            msg = _("Volume could not be found")
            raise exc.HTTPNotFound(explanation=msg)

        return volume

    def get_all_volume_types(self, request):

        types = self.volume_driver.get_all_volume_types()
        return types

    def get_volume_type(self, request, volume_type_id):

        try:
            volume_type = self.volume_driver.show_volume_type(volume_type_id)
        except exception_ex.VolumeTypeNotFoundError:
            msg = _("Volume type could not be found")
            raise exc.HTTPNotFound(explanation=msg)
        return volume_type


def create_router(mapper):
    controller = VolumeController()

    mapper.connect('/volumes',
                   controller=controller,
                   action='list',
                   conditions=dict(method=['GET']))
    mapper.connect('/volumes/details',
                   controller=controller,
                   action='show',
                   conditions=dict(method=['GET']))
    mapper.connect('/types',
                   controller=controller,
                   action='get_all_volume_types',
                   conditions=dict(method=['GET']))
