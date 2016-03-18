#!/usr/bin/python2.7

import re
import sys
import pprint
import json

pp = pprint.PrettyPrinter(indent=4)

from collections import defaultdict

SUPPORTED_TYPES = ['ESTABLISHED']

JAVA_GEN_IGNORE =  [ '^\-X','^\-Djava', '^-Dcom.sun',
                     '^-[dD][0-9]', '^-verbose', '^-Duser\.',
                     '[Pp]assword', '-server', '-Dsun',
                     'log4j', '[Uu]ser[Nn]ame' ]

JAVA_APP_HINTS = { '/opt/activemq/bin/run.jar':'amq',
                '-DAppiaInstance':'appia',
                }


DH_CONF = {
    '-D': ['-Djboss.partition.name',
           '-Djboss.partition.udpGroup',
           '-DhostGroup',
           '-Dcode_version',
           '-Dinstance_type'],
}

DPF_CONF = {
    '-D': [
        '-Dcode_version',
        '-DhostGroup',
        '-Denv',
        '-Dinstance_type',
        '-Dprovider',
    ],
    'nodash': {'config':'xml$'},
}
LIGHTSTREAM_CONF = {
    '-D': [ '-Dinstance_type', '-Dcode_version' ],
    'positional': { 'config': -1 },
}

AMQ_CONF = {
    '-D': [ '-Dactivemq.conf', '-Dactivemq.data' ],
    'nodash': { 'jar': 'run.jar' },
}

IGNORE = { 'ignore': True }

APPIA_CONF = {
    '-D': [ '-DAppiaConsolePort', '-DAppiaInstance' ],
    'nodash': { 'config': '.*ini' },
}

MYSQLD_CONF = { '--': [ '--port', '--socket', '--datadir', "--defaults-file" ] }
HTTPD_CONF = { '--': [ '--port', '--socket', '--datadir', "--defaults-file" ] }


MOBILE_CONF = {
    '-D': [ '-Dinstance_type',
            '-Dcode_version',
            '-Djboss.server.default.config',
            '-Dom.env',
            '-Dom.api.home' ]
}

CMDLINE_CONF = { 'java': {
        'gen_ignore': JAVA_GEN_IGNORE,
        'app_hints': JAVA_APP_HINTS,

        'app': {
            'amq': AMQ_CONF,
            'lightstreamer':  LIGHTSTREAM_CONF,
        },
        'lookahead': {  '-classpath': 'classpath',
                        '-b': 'jboss_node'},
     },
    'mysqld':{'app': {'mysqld': MYSQLD_CONF}},
    'httpd':{ 'app': {'httpd' :HTTPD_CONF}},
}

def type_by_host(hostname, field):
    host_vals = dd[hostname].items()
    ret = [ (iter_pid,vals[field]) if vals[field] else None for iter_pid,vals in host_vals ]
    ret = filter(None,ret)

    return dict(ret)

def type_by_all_hosts(field):
    hosts = dd.keys()
    ret = [ (host,type_by_host(host, field)) if field else None for host in hosts ]

    return dict(ret)

def get_sock(src_tup=None, dest_tup=None, host=None):
    if host:
        host_data = {host: type_by_host(host, 'tcp_conns')}
    else:
        host_data = type_by_all_hosts('tcp_conns')

    for iter_host,process in host_data.items():
        for iter_pid,conns in process.items():
            for iter_src, iter_dest, status in conns:
                if iter_src  == src_tup and iter_dest == dest_tup:
                    return iter_host, iter_pid

    return None,None

def parse_cmdline(line, conf=CMDLINE_CONF):
    if type(conf) != dict:
        print "conf must be a dict!"
        return

    cmdline = line.split('\0')
    full_cmd = cmdline.pop(0)
    exec_split = full_cmd.split('/')
    #ret_cmdline = { 'cmd':cmdline }

    new_ret = defaultdict(list)

    exec_base = exec_split[-1]
    exec_dir = exec_split[:-1]

    app_conf = []
    if exec_base in CMDLINE_CONF.keys():
        app_conf = CMDLINE_CONF[exec_base]
    else:
        if exec_base in CMDLINE_CONF.keys():
            app_conf = CMDLINE_CONF[exec_base]
            return {'exec_base':exec_base}

    app_name = exec_base
    if 'app_hints' in app_conf:
        app_hints = app_conf['app_hints']
        for param in cmdline:
            app_name_tmp = [ app if re.search(key, param) else None for key,app in app_hints.items() ]
            app_name_tmp = filter(None, app_name_tmp)
            if app_name_tmp:
                app_name = app_name_tmp[0]
                break

    ret_cmdline = parse_app_cmdline(exec_base, app_name, cmdline)

    return app_name, ret_cmdline

def parse_app_cmdline(exec_base, app_name, full_cmd):
    app_ret = {}

    if exec_base not in CMDLINE_CONF.keys():
        print "[WARN] `basename $file_location  is not in CMDLINE_CONF.keys(): %s" % (exec_base)
        return app_ret

    exec_base_conf = CMDLINE_CONF[exec_base]
    app_conf, lookahead, lookahead_param = None, None, None
    for param_c in range(len(full_cmd)):
        param = full_cmd[param_c]

        for key in exec_base_conf.keys():
            if key == 'lookahead':
                lookahead = exec_base_conf['lookahead']
                if param in lookahead.keys():
                    lookahead_key = lookahead[param]
                    lookahead_param = full_cmd[param_c+1]
                    app_ret[lookahead_key] = lookahead_param

                    param_c+=1

            if key == 'app':
                try:
                    app_conf = exec_base_conf['app'][app_name]
                    if 'ignore' in exec_base_conf['app'][app_name]:
                        return
                except:
                    print "[ERROR] app_conf was not able to set right! %s:%s" % (app_name,full_cmd)
                    return app_ret

                param_name, val = parse_app_params(app_conf, param)
                if not param_name and not val:
                    return

                app_ret[param_name] = val

    return app_ret

def parse_double_dash(param, d_confs):
    for d_param in d_confs:
        if re.search(d_param, param):
            param_split = param.split('=')

            d_name = param_split[0].replace('--','')
            d_val = param_split[1]

            return (d_name, d_val)

    return (None,None)

def parse_dash_dee(param, d_confs):
    for d_param in d_confs:
        if re.search(d_param, param):
            param_split = param.split('=')

            d_name = param_split[0].replace('-D','')
            d_val = param_split[1]

            if d_name == "instance_type":
                if ',' in  d_val:
                    d_val = d_val.split(',')[1]

            return (d_name, d_val)

    return (None,None)


def parse_app_params(app_conf, param):
    for app_key in app_conf.keys():
        if app_key == '--':
           dd_name, dd_val = parse_double_dash(param, app_conf['--'])
           return (dd_name, dd_val)

        elif app_key == '-D':
           d_name, d_val = parse_dash_dee(param, app_conf['-D'])
           return (d_name, d_val)

        elif app_key == 'nodash':
            for nd_name, nd_val in app_conf['nodash'].items():
                if re.search(nd_name, param):
                    return (nd_name, nd_val)

        else:
            return (None,None)

def is_useful(exec_base, param, conf=CMDLINE_CONF['java']):
    if not conf:
        return False

    is_ignorable = False
    for r in conf['gen_ignore']:
        ignore = re.search(r, param)

        if ignore:
            break

    if ignore:
        return False
    else:
        return True


def parse_conn(lsof_line, types=SUPPORTED_TYPES):
    is_valid_type = [ False if req_type not in SUPPORTED_TYPES
       else True for req_type in types ]

    if False in is_valid_type:
        sys.exit(1)

    lsof_line = lsof_line.strip()

    splitup = re.split('->|[ :\t\0\(\)]*', lsof_line)[:-1]

    tcp_conn_type = splitup[-1]
    if tcp_conn_type not in types:
        return None

    src_ip, src_port, dest_ip, dest_port, conn_type = splitup

    return (src_ip,src_port), (dest_ip,dest_port), conn_type


def sanitize_lines(lines):
    ret = [ re.split(':',line,3) if line else None for line in lines ]
    return ret

def parse_fds(fd_lines):
    ret_fds = [ re.split('\s', fd_line)[-1] for fd_line in fd_lines ]
    return ret_fds

input_file = open('/home/matt/output.txt', 'r')
lines = input_file.readlines()

dd = defaultdict(lambda : defaultdict(lambda : defaultdict(list)))
sanitized = sanitize_lines(lines)

for san in sanitized:
    if len(san) == 4:
        host = san[0]
        iter_pid = san[1]
        detail_type = san[2]
        output = san[3].strip()

    dd[host][iter_pid][detail_type].append(output)

host_src = defaultdict(set)
host_dest = defaultdict(set)

for host,process in dd.items():
    for iter_pid,vals in process.items():
        conns = [ parse_conn(conn) for conn in vals['tcp_conns'] ]
        conns = filter(None, conns)

        dd[host][iter_pid]['tcp_conns'] = conns
        dd[host][iter_pid]['command'] = conns

host_defs = defaultdict(lambda : defaultdict(lambda : defaultdict(list)))

results = { 'hosts':[] }
for src_host in dd.keys():
    host_details = {}
    host_details["hostname"] = src_host

    src_processes = []
    for src_pid, conns in type_by_host(src_host, 'tcp_conns').items():
        src_fds_raw = dd[src_host][src_pid]['writeable_fds']

        writeable_fds = parse_fds(src_fds_raw)

        src_cmdline = dd[src_host][src_pid]['cmdline'][0]
        src_app_name, src_app_details = parse_cmdline(src_cmdline)

        connections = []
        for conn in conns:
            conversation = {}

            src_socket, dest_socket, status = conn
            src_ip, src_port = src_socket

            dest_ip, dest_port = dest_socket

            external_conns = []
            for extern_host in dd.keys():
                if extern_host == src_host or extern_host:
                    continue

                dest_host, dest_pid = get_sock((dest_ip,dest_port), (src_ip, src_port),
                                          host=extern_host)

                if dest_host and dest_pid and src_pid and src_host:
                    dest_cmdline = dd[dest_host][dest_pid]['cmdline'][0]
                    dest_app_name,dest_app_details = parse_cmdline(dest_cmdline)

                    if not dest_app_name or not dest_app_details:
                        continue

                    app_conn = { 'dest_ip':dest_ip,
                                 'dest_host':dest_host,
                                 'dest_pid':dest_pid,
                                 'dest_app_name':dest_app_name ,
                                 'dest_app_details': dest_app_details}

                    connections.append(app_conn)

        src_process = { 'src_ip':dest_ip,
                        'src_pid':src_pid,
                        'src_app_name':src_app_name,
                        'src_app_details':src_app_details,
                        'writeable_fds':writeable_fds,
                        'external_conns':connections}

        src_processes.append(src_process)

    host_details['processes'] = src_processes
    results['hosts'].append(host_details)

print json.dumps(results, sort_keys=True, indent=2)
