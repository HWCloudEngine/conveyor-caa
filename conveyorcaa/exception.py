import sys

from oslo_config import cfg
from oslo_log import log as logging

from conveyorcaa.i18n import _

LOG = logging.getLogger(__name__)

exc_log_opts = [
    cfg.BoolOpt('fatal_exception_format_errors',
                default=False,
                help='Make exception message format errors fatal'),
]

CONF = cfg.CONF
CONF.register_opts(exc_log_opts)


def _cleanse_dict(original):
    """Strip all admin_password, new_pass, rescue_pass keys from a dict."""
    return dict((k, v) for k, v in original.iteritems() if "_pass" not in k)


class ConveyorCaaException(Exception):
    """Base Wormhole Exception

    To correctly use this class, inherit from it and define
    a 'msg_fmt' property. That msg_fmt will get printf'd
    with the keyword arguments provided to the constructor.

    """
    msg_fmt = _("An unknown exception occurred.")
    code = 500
    headers = {}
    safe = False
    title = ''

    def __init__(self, message=None, title='', **kwargs):
        self.kwargs = kwargs
        self.title = title

        if 'code' not in self.kwargs:
            try:
                self.kwargs['code'] = self.code
            except AttributeError:
                pass

        if not message:
            try:
                message = self.msg_fmt % kwargs

            except Exception:
                exc_info = sys.exc_info()
                # kwargs doesn't match a variable in the message
                # log the issue and the kwargs
                LOG.exception(_('Exception in string format operation'))
                for name, value in kwargs.iteritems():
                    LOG.error("%s: %s" % (name, value))  # noqa

                if CONF.fatal_exception_format_errors:
                    raise exc_info[0], exc_info[1], exc_info[2]
                else:
                    # at least get the core message out if something happened
                    message = self.msg_fmt

        super(ConveyorCaaException, self).__init__(message)

    def format_message(self):
        # NOTE(mrodden): use the first argument to the python Exception object
        # which should be our full ConveyorCaaException message, (see __init__)
        return self.args[0]


class ValidationError(ConveyorCaaException):
    msg_fmt = _("Expecting to find %(attribute)s in %(target)s -"
                " the server could not comply with the request"
                " since it is either malformed or otherwise"
                " incorrect. The client is assumed to be in error.")
    code = 400
    title = 'Bad Request'


class Invalid(ConveyorCaaException):
    msg_fmt = _("Unacceptable parameters.")
    code = 400


class Forbidden(ConveyorCaaException):
    msg_fmt = _("Not authorized.")
    code = 403


class UnexpectedError(ConveyorCaaException):
    msg_fmt = _("Unexpected Error.")
    code = 500


class AdminRequired(Forbidden):
    msg_fmt = _("Container does not have admin privileges")


class InvalidInput(Invalid):
    msg_fmt = _("Invalid input received: %(reason)s")


class InvalidContentType(Invalid):
    msg_fmt = _("Invalid content type %(content_type)s.")


class InvalidID(Invalid):
    title = "Invalid Id"
    msg_fmt = _("Invalid ID received %(id)s.")


class NotFound(ConveyorCaaException):
    title = "Not Found"
    msg_fmt = _("Resource could not be found.")
    code = 404


class ConfigNotFound(ConveyorCaaException):
    msg_fmt = _("Could not find config at %(path)s")


class PasteAppNotFound(ConveyorCaaException):
    msg_fmt = _("Could not load paste app '%(name)s' from %(path)s")


class MalformedRequestBody(ConveyorCaaException):
    msg_fmt = _("Malformed message body: %(reason)s")


class VolumeNotFound(NotFound):
    title = "Volume Not Found"
    msg_fmt = _("Volume %(id)s Not Found.")


class InstanceNotFound(NotFound):
    title = "Instance Not Found"
    msg_fmt = _("Instance %(id)s Not Found.")


class DirNotFound(NotFound):
    title = "Dir Not Found"
    msg_fmt = _("Dir %(dir)s Not Found.")


class InjectFailed(ConveyorCaaException):
    msg_fmt = _("Inject file %(path)s failed: %(reason)s")


class ImageNotAuthorized(ConveyorCaaException):
    msg_fmt = _("Not authorized for image %(image_id)s.")


class ImageNotFound(ConveyorCaaException):
    msg_fmt = _("Image %(image_id)s could not be found.")


class ImageBadRequest(Invalid):
    msg_fmt = _("Request of image %(image_id)s got BadRequest response: "
                "%(response)s")


class SignatureVerificationError(ConveyorCaaException):
    msg_fmt = _("Signature verification for the image "
                "failed: %(reason)s.")


class NotEnoughSpace(ConveyorCaaException):
    msg_fmt = _("Can not download image %(image_id)s with size %(image_size).")


class MultipleDownload(ConveyorCaaException):
    msg_fmt = _("Can not download another image %(image_id)s.")


class DownloadError(ConveyorCaaException):
    msg_fmt = _("Execute get size error")


class ExtendError(ConveyorCaaException):
    msg_fmt = _("Extend image error image %(image)s.")


class MultipleExtend(ConveyorCaaException):
    msg_fmt = _("Can not extend another image %(image_id)s.")


class MountError(ConveyorCaaException):
    msg_fmt = _("Execute mount user device error")


class NicNotFoundByIpAddr(ConveyorCaaException):
    msg_fmt = _("HyperContainer Nic Not Found By %(ip_addr)s.")


class NicNotFoundByMacAddr(ConveyorCaaException):
    msg_fmt = _("HyperContainer Nic Not Found By %(mac_addr)s.")


class FgPortDoesNotExist(ConveyorCaaException):
    message = _("Fg Port does not exist.")


class SudoRequired(ConveyorCaaException):
    message = _("Sudo privilege is required to run this command.")


class NetworkVxlanPortRangeError(ConveyorCaaException):
    message = _("Invalid network VXLAN port range: '%(vxlan_range)s'")
