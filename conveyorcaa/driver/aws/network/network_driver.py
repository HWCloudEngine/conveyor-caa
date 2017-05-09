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
Network Drivers for Amazon
"""

from conveyorcaa.driver.aws import client
from conveyorcaa import exception
from conveyorcaa.i18n import _LE


from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils
from oslo_utils import uuidutils

LOG = logging.getLogger(__name__)

aws_opts = [

]
CONF = cfg.CONF
CONF.register_opts(aws_opts)


class AwsNetworkDriver(object):
    CLOUD_DRIVER = True

    def __init__(self, *args, **kwargs):
        self._aws_client = client.AwsClient()
        self.network_id = uuidutils.generate_uuid()
        super(AwsNetworkDriver, self).__init__(*args, **kwargs)

    def _format_subnet(self, subnet):

        op_subnet = {}
        op_subnet['id'] = subnet.get('SubnetId', '')
        op_subnet['cidr'] = subnet.get('CidrBlock', '')
        op_subnet['gateway_ip'] = subnet.get('GatewayIp', '')
        op_subnet['enable_dhcp'] = subnet.get('EnableDhcp', False)
        op_subnet['ip_version'] = subnet.get('IpVersion', '4')
        op_subnet['dns_nameservers'] = None
        op_subnet['host_routes'] = None
        op_subnet['network_id'] = self.network_id

        # AWS AvailableIpAddressCount info
        # can caculate allocation pools of openstack
        op_subnet['allocation_pools'] = None

        tags = subnet.get('Tags', [])
        for tag in tags:
            key = tag.get('Key', '')
            value = tag.get('Value', '')
            if 'Name' == key:
                op_subnet['name'] = value
                break
        return op_subnet

    def _format_securitygroup(self, securitygroup):

        sec = {}
        sec['name'] = securitygroup.get('GroupName', '')
        sec['id'] = securitygroup.get('GroupId', '')
        sec['description'] = securitygroup.get('Description', '')
        sec['remote_group_id'] = None
        sec['security_group_id'] = None
        sec['tenant_id'] = None

        rules = []
        in_rules = securitygroup.get('IpPermissions', [])
        for in_rule in in_rules:
            rule = {}
            rule['direction'] = 'ingress'
            rule['protocol'] = in_rule.get('IpProtocol', '')
            rule['port_range_max'] = in_rule.get('ToPort', '')
            rule['port_range_min'] = in_rule.get('FromPort', '')
            rule['remote_group_id'] = None
            rule['security_group_id'] = None
            rule['tenant_id'] = None
            rules.append(rule)

        out_rules = securitygroup.get('IpPermissionsEgress', [])
        for out_rule in out_rules:
            rule = {}
            rule['direction'] = 'egress'
            rule['protocol'] = out_rule.get('IpProtocol', '')
            rule['port_range_max'] = out_rule.get('ToPort', '')
            rule['port_range_min'] = out_rule.get('FromPort', '')
            rule['remote_group_id'] = None
            rule['security_group_id'] = None
            rule['tenant_id'] = None
            rules.append(rule)

        sec['security_group_rules'] = rules
        return sec

    def _format_port(self, port):
        op_port = []
        op_port['mac_address'] = port.get('MacAddress', '')
        op_port['admin_state_up'] = True
        op_port['id'] = port.get('NetworkInterfaceId', '')
        op_port['allowed_address_pairs'] = None
        op_port['binding:profile'] = None
        op_port['binding:vnic_type'] = None

        # security group transformer to openstack
        secgroups = port.get('Groups ', [])
        group_ids = []
        for secgroup in secgroups:
            group_id = secgroup.get('GroupId', '')
            group_ids.append(group_id)
        op_port['security_groups'] = group_ids

        # fix ip info transformer to openstack
        subnet_id = port.get('SubnetId', '')
        fixed_ips = port.get('PrivateIpAddresses', [])
        op_fixed_ips = []
        for fixed_ip in fixed_ips:
            ip = {}
            ip['ip_address'] = fixed_ip.get('PrivateIpAddress', '')
            ip['subnet_id'] = subnet_id
            op_fixed_ips.append(ip)
        op_port['fixed_ips'] = op_fixed_ips

        tags = port.get('Tags', [])
        for tag in tags:
            key = tag.get('Key', '')
            value = tag.get('Value', '')
            if 'Name' == key:
                op_port['name'] = value
                break
        return op_port

    def _format_floatingIp(self, floatingIp):

        op_floatingip = {}

        # aws uses ip to query floating ip info,
        # so setting 'PublicIp' as openstack 'id'
        op_floatingip['id'] = floatingIp.get('PublicIp', '')
        op_floatingip['floating_network_id']
        op_floatingip['floating_ip_address'] = floatingIp.get('PublicIp', '')
        op_floatingip['router_id'] = None
        op_floatingip['port_id'] = floatingIp.get('NetworkInterfaceId', '')
        return op_floatingip

    def _format_router(self, router):

        op_router = {}
        op_router['id'] = router.get('InternetGatewayId', '')
        op_router['admin_state_up'] = True
        op_router['external_gateway_info'] = None
        tags = router.get('Tags', [])
        for tag in tags:
            key = tag.get('Key', '')
            value = tag.get('Value', '')
            if 'Name' == key:
                op_router['name'] = value
                break
        return op_router

    def get_network(self, network_id, ctxt=None):

        op_net = {}
        op_net['id'] = network_id
        op_net['name'] = 'aws-network'
        op_net['admin_state_up'] = True
        op_net['shared'] = True
        op_net['provider:physical_network'] = None
        op_net['provider:network_type'] = None
        op_net['provider:segmentation_id'] = None
        return op_net

    def list_networks(self, ctxt=None):
        op_nets = []
        op_net = {}
        op_net['id'] = self.network_id
        op_net['name'] = 'aws-network'
        op_net['admin_state_up'] = True
        op_net['shared'] = True
        op_net['provider:physical_network'] = None
        op_net['provider:network_type'] = None
        op_net['provider:segmentation_id'] = None
        op_nets.append(op_net)
        return op_nets

    def get_subnet(self, subnet_id, ctxt=None):

        kwargs = {}
        kwargs['SubnetIds'] = [subnet_id]
        subnet = []
        try:
            subnet = self._aws_client.get_aws_client(ctxt). \
                describe_subnets(**kwargs)
        except Exception as e:
            reason = e.response.get('Error', {}).get('Code', 'Unkown')
            if 'InvalidParameterValue' == reason:
                raise exception.NotFound
            else:
                with excutils.save_and_reraise_exception():
                    LOG.error(_LE('Error query subnet: %s', e))
        if subnet:
            subnet = self._format_subnet(subnet[0])
        return subnet

    def list_subnet(self, ctxt=None):

        subnets = []
        try:
            subnets = self._aws_client.get_aws_client(ctxt). \
                describe_subnets()
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE('Error query subnets: %s', e))

        dict_subnets = []
        for subnet in subnets:
            subnet = self._format_subnet(subnet)
            dict_subnets.append(subnet)
        return dict_subnets

    def get_security_group(self, securitygroup_id, ctxt=None):
        kwargs = {}
        kwargs['GroupIds'] = [securitygroup_id]

        securitygroup = []
        try:
            securitygroup = self._aws_client.get_aws_client(ctxt). \
                describe_security_groups(**kwargs)
        except Exception as e:
            reason = e.response.get('Error', {}).get('Code', 'Unkown')
            if 'InvalidParameterValue' == reason:
                raise exception.NotFound
            else:
                with excutils.save_and_reraise_exception():
                    LOG.error(_LE('Error query securitygroup: %s', e))
        if securitygroup:
            securitygroup = self._format_securitygroup(securitygroup[0])
        return securitygroup

    def list_security_group(self, ctxt=None):
        securitygroups = []
        try:
            securitygroups = self._aws_client.get_aws_client(ctxt). \
                describe_security_groups()
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE('Error query securitygroups: %s', e))

        dict_securitygroup = []
        for securitygroup in securitygroups:
            securitygroup = self._format_securitygroup(securitygroup)
            dict_securitygroup.append(securitygroup)
        return dict_securitygroup

    def get_port(self, port_id, ctxt=None):
        kwargs = {}
        kwargs['NetworkInterfaceIds'] = [port_id]
        port = []
        try:
            port = self._aws_client.get_aws_client(ctxt). \
                describe_network_interfaces(**kwargs)
        except Exception as e:
            reason = e.response.get('Error', {}).get('Code', 'Unkown')
            if 'InvalidParameterValue' == reason:
                raise exception.NotFound
            else:
                with excutils.save_and_reraise_exception():
                    LOG.error(_LE('Error query port: %s', e))
        if port:
            port = self._format_port(port[0])
        return port

    def list_ports(self, ctxt=None):
        ports = []
        try:
            ports = self._aws_client.get_aws_client(ctxt). \
                describe_network_interfaces()
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE('Error query ports: %s', e))

        dict_port = []
        for port in ports:
            port = self._format_port(port)
            dict_port.append(port)
        return dict_port

    def get_floatingip(self, floatingIp, ctxt=None):
        kwargs = {}
        kwargs['PublicIps'] = [floatingIp]
        floatingip = []
        try:
            floatingip = self._aws_client.get_aws_client(ctxt). \
                describe_addresses(**kwargs)
        except Exception as e:
            reason = e.response.get('Error', {}).get('Code', 'Unkown')
            if 'InvalidParameterValue' == reason:
                raise exception.NotFound
            else:
                with excutils.save_and_reraise_exception():
                    LOG.error(_LE('Error query floatingip: %s', e))
        if floatingip:
            floatingip = self._format_port(floatingip[0])
        return floatingip

    def list_floatingips(self, ctxt=None):
        floatingips = []
        try:
            floatingips = self._aws_client.get_aws_client(ctxt). \
                describe_addresses()
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE('Error query floatingips: %s', e))

        dict_floatingips = []
        for floatingip in floatingips:
            floatingip = self._format_port(floatingip)
            dict_floatingips.append(floatingip)
        return dict_floatingips

    def get_router(self, router_id, ctxt=None):
        kwargs = {}
        kwargs['InternetGatewayIds'] = [router_id]
        router = []
        try:
            router = self._aws_client.get_aws_client(ctxt). \
                describe_internet_gateways(**kwargs)
        except Exception as e:
            reason = e.response.get('Error', {}).get('Code', 'Unkown')
            if 'InvalidParameterValue' == reason:
                raise exception.NotFound
            else:
                with excutils.save_and_reraise_exception():
                    LOG.error(_LE('Error query router: %s', e))
        if router:
            router = self._format_router(router[0])
        return router

    def list_routers(self, router_id, ctxt=None):
        routers = []
        try:
            routers = self._aws_client.get_aws_client(ctxt). \
                describe_internet_gateways()
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE('Error query routers: %s', e))

        dict_routers = []
        for router in routers:
            router = self._format_router(router)
            dict_routers.append(router)
        return dict_routers
