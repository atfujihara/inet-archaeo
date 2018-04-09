#!/usr/bin/env python

import argparse
import re
import yaml
import json
import pysnmp.hlapi as SnmpApi


def get_args():
    parser = argparse.ArgumentParser(
        description='Python script to collect network topology data'
                    + ' from Routers/Switches via SNMP')

    parser.add_argument(
        '-d', '--debug',
        action='store_true',
        default=False,
        help='Run in debug mode(Output detailed info to STDOUT)'
             + ' [Default: False]')

    parser.add_argument(
        '-c', '--config',
        action='store',
        help='Configuration file in YAML format')

    args = parser.parse_args()

    return args


def load_config(config):
    f = open(config, 'r')
    conf_data = yaml.load(f)
    f.close()

    return conf_data


def snmp_init(agent):
    conn = {
        'snmpEng': SnmpApi.SnmpEngine(),
        'community': SnmpApi.CommunityData(agent['community']),
        'target':  SnmpApi.UdpTransportTarget((agent['host'], agent['port'])),
        'context': SnmpApi.ContextData()
    }
    return conn


def get_node(conn):
    node = {}
    name = SnmpApi.ObjectType(
        SnmpApi.ObjectIdentity('SNMPv2-MIB', 'sysName', 0))
    descr = SnmpApi.ObjectType(
        SnmpApi.ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0))

    errorIndication, errorStatus, errorIndex, varBinds = next(
        SnmpApi.getCmd(
            conn['snmpEng'],
            conn['community'],
            conn['target'],
            conn['context'],
            name, descr
        )
    )

    if errorIndication:
        print(errorIndication)
    elif errorStatus:
        print('%s at %s' % (errorStatus.prettyPrint(),
              errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
    else:
        for varBind in varBinds:
            (oid, value) = [x.prettyPrint() for x in varBind]
            if value is None:
                continue

            if re.search('sysName', oid):
                node['name'] = value
            elif re.search('sysDescr', oid):
                node['descr'] = value

    return node


def get_ifs(conn):
    ifs = {}

    iftype = SnmpApi.ObjectType(SnmpApi.ObjectIdentity('IF-MIB', 'ifType'))
    ifname = SnmpApi.ObjectType(SnmpApi.ObjectIdentity('IF-MIB', 'ifName'))
    ifdescr = SnmpApi.ObjectType(SnmpApi.ObjectIdentity('IF-MIB', 'ifDescr'))
    ifalias = SnmpApi.ObjectType(SnmpApi.ObjectIdentity('IF-MIB', 'ifAlias'))

    for (errorIndication,
         errorStatus,
         errorIndex,
         varBinds) in SnmpApi.nextCmd(conn['snmpEng'],
                                      conn['community'],
                                      conn['target'],
                                      conn['context'],
                                      iftype, ifname, ifdescr, ifalias,
                                      lexicographicMode=False):
        if errorIndication:
            print(errorIndication)
            continue
        elif errorStatus:
            print('%s at %s' % (
                errorStatus.prettyPrint(),
                errorIndex and varBinds[int(errorIndex) - 1][0] or '?')
            )
            continue

        for varBind in varBinds:
            (oid, value) = [x.prettyPrint() for x in varBind]
            if value is None:
                continue

            index = (oid.split('.'))[-1]
            if index not in ifs:
                ifs[index] = {}

            if re.search('ifType', oid):
                label = 'ifType'
            elif re.search('ifName', oid):
                label = 'ifName'
            elif re.search('ifDescr', oid):
                label = 'ifDescr'
            elif re.search('ifAlias', oid):
                label = 'ifAlias'
            else:
                continue

            ifs[index][label] = value

    return ifs


def get_peer_info(descr, separators=' '):
    buff = re.split('([' + separators + ']+)', descr)
    node = buff.pop(0)
    interface = ''

    while buff:
        separator = buff.pop(0)
        word = buff.pop(0)

        if word == '':
            break

        if node == '':
            node = word
            continue

        if re.match('^.*[a-zA-Z0-9]$', node) and \
                re.match('^[a-zA-Z0-9]', word):
            interface = word
            break
        else:
            node = separator.join([node, word])

    while buff:
        separator = buff.pop(0)
        word = buff.pop(0)

        if word == '':
            break

        interface = separator.join([interface, word])

    return {'node': node, 'interface': interface}


def get_data(agent):
    conn = snmp_init(agent)

    data = {
        'node': get_node(conn),
        'interfaces': get_ifs(conn)
    }

    return data


def get_target_if(if_str, ifs):
    for if_name in ifs:
        if if_str == if_name:
            return if_name

        if_num = re.search('\d.*$', if_str)
        if if_num is None:
            continue

        if re.search(if_num[0], if_name):
            return if_name

    return


def create_database(nodes, links):
    database = {
        'nodes': [],
        'links': []
    }

    for name, vars in nodes.items():
        item = {'name': name}
        icon = vars.get('icon', '')
        if icon != '':
            item['icon'] = icon
        database['nodes'].append(item)

    for src_host, target in links.items():
        for target_host, src_ifs in target.items():

            # check peer
            target_ifs = None
            if (target_host in links) and (src_host in links[target_host]):
                target_ifs = links[target_host][src_host]

            for src_if, peer_if in src_ifs.items():
                target_if = None
                if target_ifs is not None:
                    target_if = get_target_if(peer_if, target_ifs)

                if target_if is None:
                    target_if = peer_if
                elif src_host > target_host:
                    continue

                item = {
                    'source': src_host,
                    'target': target_host,
                    'meta': {
                        'interface': {'source': src_if, 'target': target_if}
                    }
                }
                database['links'].append(item)

    return database


def check_link_filter(link, filter):
    for item in filter:
        action = item.get('action', '')
        matched = False
        for key, pattern in item.items():
            if key == 'action':
                continue

            value = link.get(key, '')
            if re.match(pattern, value):
                matched = True
            else:
                break

        if matched:
            if action == 'exclude':
                return False
            if action == 'include':
                return True

    return True


def get_icon(node, vars, rules):
    for rule in rules:
        node_pattern = rule.get('node', '')
        model_pattern = rule.get('model', '')

        if node_pattern != '' and not re.match(node_pattern, node):
            continue

        if model_pattern != '' and \
                not re.match(model_pattern, vars.get('model', '')):
            continue

        return rule.get('icon', None)

    return


def main(args):
    config = load_config(args.config)
    agents = config['agents']

    nodes = {}
    links = {}
    for agent in agents:
        data = get_data(agent)

        src_host = data['node']['name']
        nodes[src_host] = {'model': data['node']['descr']}

        if src_host not in links:
            links[src_host] = {}

        for index, data in data['interfaces'].items():
            if data.get('ifType', '') != 'ethernetCsmacd':
                continue

            if data.get('ifAlias', '') == '':
                continue

            if data.get('ifName', '') != '':
                src_if = data['ifName']
            elif data.get('ifDesct', '') != '':
                src_if = data['ifDescr']
            else:
                continue

            peer = get_peer_info(
                        data['ifAlias'],
                        config.get('separators', ' ')
                    )
            target_host = peer['node']
            target_if = peer['interface']

            link = {
                'src_host':    src_host,
                'src_if':      src_if,
                'target_host': target_host,
                'target_if':   target_if,
            }
            if not check_link_filter(link, config.get('link_filter', [])):
                continue

            if target_host not in nodes:
                nodes[target_host] = {}

            if target_host not in links[src_host]:
                links[src_host][target_host] = {}

            links[src_host][target_host][src_if] = target_if

    icons = config.get('icons', {})
    for node, vars in nodes.items():
        icon = get_icon(node, vars, config.get('icon_rules', []))

        if icon is None:
            continue

        vars['icon'] = icons.get(icon, '')

    database = create_database(nodes, links)
    print(json.dumps(database))


if __name__ == "__main__":
    args = get_args()
    main(args)
