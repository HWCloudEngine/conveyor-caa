import eventlet
import sys

from oslo_config import cfg
from oslo_log import log as logging

from conveyorcaa import config
from conveyorcaa import service

CONF = cfg.CONF


def main(servername="conveyorcaa"):
    config.parse_args(sys.argv)
    eventlet.monkey_patch(os=False)
    logging.setup(CONF, servername)

    launcher = service.process_launcher()
    server = service.WSGIService(servername, use_ssl=False,
                                 max_url_len=16384)
    launcher.launch_service(server, workers=server.workers or 1)
    launcher.wait()
