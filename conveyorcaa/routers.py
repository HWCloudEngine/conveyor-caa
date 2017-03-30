from conveyorcaa.api import compute
from conveyorcaa.api import volumes
from conveyorcaa import wsgi


class Router(wsgi.ComposableRouter):
    def add_routes(self, mapper):
        for r in [compute, volumes]:
            r.create_router(mapper)
