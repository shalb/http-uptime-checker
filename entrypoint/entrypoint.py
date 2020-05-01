#!/usr/bin/env python

import urllib.request
import json
import traceback
import argparse
import sys
import time
import logging
import yaml
import os
import prometheus_client
import prometheus_client.core

# pip3 install prometheus_client docker pyaml

# parse arguments
parser = argparse.ArgumentParser()
parser.add_argument('--config', default=sys.argv[0] + '.yml', help='config file location')
parser.add_argument('--log_level', help='logging level')
args = parser.parse_args()

# add prometheus decorators
REQUEST_TIME = prometheus_client.core.Summary('request_processing_seconds', 'Time spent processing request')

def get_config(args):
    '''Parse configuration file and merge with cmd args'''
    for key in vars(args):
        conf[key] = vars(args)[key]
    with open(conf['config']) as conf_file:
        conf_yaml = yaml.load(conf_file, Loader=yaml.FullLoader)
    for key in conf_yaml:
        if not conf.get(key):
            conf[key] = conf_yaml[key]
    target_url = os.environ.get('TARGET_URL')
    if target_url:
        conf['target_url'] = target_url
    fails_to_downtime = os.environ.get('FAILS_TO_DOWNTIME')
    if fails_to_downtime:
        conf['fails_to_downtime'] = int(fails_to_downtime)
    target_url_check_interval = os.environ.get('TARGET_URL_CHECK_INTERVAL')
    if target_url_check_interval:
        conf['target_url_check_interval'] = int(target_url_check_interval)
    log_level = os.environ.get('LOG_LEVEL')
    if log_level:
        conf['log_level'] = log_level

def configure_logging():
    '''Configure logging module'''
    log = logging.getLogger(__name__)
    log.setLevel(conf['log_level'])
    FORMAT = '%(asctime)s %(levelname)s %(message)s'
    logging.basicConfig(format=FORMAT)
    return log

# Decorate function with metric.
@REQUEST_TIME.time()
def get_data():
    '''Get data from target service'''
    for task_name in conf['tasks']:
        get_data_function = globals()['get_data_'+ task_name]
        get_data_function()

def get_data_uptime():
    '''Get target url'''
    # prepare request
    time_1 = time.time()
    req = urllib.request.Request(conf['target_url'])
   #headers = conf.get('headers')
   #if headers:
   #    for key in headers:
   #        val = headers[key]
   #        req.add_header(key, val)
    try:
        responce = urllib.request.urlopen(req, timeout=conf['target_url_check_interval'])
        raw_data = responce.read().decode()
        time_2 = time.time()
        data_tmp['target_url_load_time'] = time_2 - time_1
    except:
        responce = False
        data_tmp['target_url_load_time'] = False
    parse_data_uptime(responce)

def parse_data_uptime(responce):
    '''Parse checks data received via API'''
    labels = dict()
    labels['target_url'] = label_clean(conf['target_url'])

    metric_name = '{0}_url_status'.format(conf['name'])
    description = 'Status of target url OK = 1'
    value = 0
    if responce:
        if responce.getcode() == 200:
            value = 1
            data_tmp['number_of_fails'] = 0
    if value == 0:
        data_tmp['number_of_fails'] += 1
    metric = {'metric_name': metric_name, 'labels': labels, 'description': description, 'value': value}
    data.append(metric)

    metric_name = '{0}_url_full_checks_total'.format(conf['name'])
    description = 'Number of full checks = fails_to_downtime * target_url_check_interval'
    value = int(data_tmp['number_of_checks'] / conf['fails_to_downtime'])
    metric = {'metric_name': metric_name, 'labels': labels, 'description': description, 'value': value}
    data.append(metric)
    data_tmp['number_of_checks'] += 1

    metric_name = '{0}_url_downtimes_total'.format(conf['name'])
    description = 'Number of downtimes'
    if data_tmp['number_of_fails'] >= conf['fails_to_downtime']:
        data_tmp['number_of_downtimes'] += 1
        data_tmp['number_of_fails'] = 0
    value = data_tmp['number_of_downtimes']
    metric = {'metric_name': metric_name, 'labels': labels, 'description': description, 'value': value}
    data.append(metric)

    if data_tmp['target_url_load_time']:
        metric_name = '{0}_url_load_time_seconds'.format(conf['name'])
        description = 'Target url load time'
        value = data_tmp['target_url_load_time']
        metric = {'metric_name': metric_name, 'labels': labels, 'description': description, 'value': value}
        data.append(metric)

def label_clean(label):
    replace_map = {
        '\\': '',
        '"': '',
        '\n': '',
        '\t': '',
        '\r': '',
        '-': '_',
        ' ': '_'
    }
    for r in replace_map:
        label = str(label).replace(r, replace_map[r])
    return label

# run
conf = dict()
get_config(args)
log = configure_logging()
data_tmp = {
    'number_of_fails': 0,
    'number_of_downtimes': 0,
    'number_of_checks': 0,
    'target_url_load_time': 0
}
data = list()

http_uptime_checker_up = prometheus_client.Gauge('http_uptime_checker_up', 'http uptime checker scrape status')
http_uptime_checker_errors_total = prometheus_client.Counter('http_uptime_checker_errors_total', 'http uptime checker scrape errors total counter')

class Collector(object):
    def collect(self):
        # add static metrics
        gauge = prometheus_client.core.GaugeMetricFamily
        counter = prometheus_client.core.CounterMetricFamily
        # get dinamic data
        try:
            get_data()
            http_uptime_checker_up.set(1)
        except:
            trace = traceback.format_exception(sys.exc_info()[0], sys.exc_info()[1], sys.exc_info()[2])
            for line in trace:
                log.error('{0}\n'.format(line[:-1]))
            http_uptime_checker_up.set(0)
            http_uptime_checker_errors_total.inc()
        # add dinamic metrics
        to_yield = set()
        for _ in range(len(data)):
            metric = data.pop()
            labels = list(metric['labels'].keys())
            labels_values = [ metric['labels'][k] for k in labels ]
            if metric['metric_name'] not in to_yield:
                setattr(self, metric['metric_name'], gauge(metric['metric_name'], metric['description'], labels=labels))
            if labels:
                getattr(self, metric['metric_name']).add_metric(labels_values, metric['value'])
                to_yield.add(metric['metric_name'])
        for metric in to_yield:
            yield getattr(self, metric)

registry = prometheus_client.core.REGISTRY
registry.register(Collector())

prometheus_client.start_http_server(conf['listen_port'])

# endless loop
while True:
    try:
        while True:
            time.sleep(conf['check_interval'])
    except KeyboardInterrupt:
        break
    except:
        trace = traceback.format_exception(sys.exc_info()[0], sys.exc_info()[1], sys.exc_info()[2])
        for line in trace:
            log.error(line[:-1])

