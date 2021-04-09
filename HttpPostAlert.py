import copy
import json
import os
import requests

from requests.exceptions import RequestException
from staticconf.loader import yaml_loader
from texttable import Texttable
from .util import EAException
from .util import elastalert_logger
from .util import lookup_es_key


class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if hasattr(obj, 'isoformat'):
            return obj.isoformat()
        else:
            return json.JSONEncoder.default(self, obj)

class HTTPPostAlerter(Alerter):
    """ Requested elasticsearch indices are sent by HTTP POST. Encoded with JSON. """

    def __init__(self, rule):
        super(HTTPPostAlerter, self).__init__(rule)
        post_url = self.rule.get('http_post_url')
        if isinstance(post_url, str):
            post_url = [post_url]
        self.post_url = post_url
        self.post_proxy = self.rule.get('http_post_proxy')
        self.post_payload = self.rule.get('http_post_payload', {})
        self.post_static_payload = self.rule.get('http_post_static_payload', {})
        self.post_all_values = self.rule.get('http_post_all_values', not self.post_payload)
        self.post_http_headers = self.rule.get('http_post_headers', {})
        self.timeout = self.rule.get('http_post_timeout', 10)

    def alert(self, matches):
        """ Each match will trigger a POST to the specified endpoint(s). """
        for match in matches:
            payload = match if self.post_all_values else {}
            payload.update(self.post_static_payload)
            for post_key, es_key in list(self.post_payload.items()):
                payload[post_key] = lookup_es_key(match, es_key)
            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json;charset=utf-8"
            }
            headers.update(self.post_http_headers)
            proxies = {'https': self.post_proxy} if self.post_proxy else None
            for url in self.post_url:
                try:
                    response = requests.post(url, data=json.dumps(payload, cls=DateTimeEncoder),
                                             headers=headers, proxies=proxies, timeout=self.timeout)
                    response.raise_for_status()
                except RequestException as e:
                    raise EAException("Error posting HTTP Post alert: %s" % e)
            elastalert_logger.info("HTTP Post alert sent.")

    def get_info(self):
        return {'type': 'http_post',
                'http_post_webhook_url': self.post_url}


    class Alerter(object):
        """ Base class for types of alerts.

        :param rule: The rule configuration.
        """
    required_options = frozenset([])

    def __init__(self, rule):
        self.rule = rule
        # pipeline object is created by ElastAlerter.send_alert()
        # and attached to each alerters used by a rule before calling alert()
        self.pipeline = None
        self.resolve_rule_references(self.rule)

    def resolve_rule_references(self, root):
        # Support referencing other top-level rule properties to avoid redundant copy/paste
        if type(root) == list:
            # Make a copy since we may be modifying the contents of the structure we're walking
            for i, item in enumerate(copy.copy(root)):
                if type(item) == dict or type(item) == list:
                    self.resolve_rule_references(root[i])
                else:
                    root[i] = self.resolve_rule_reference(item)
        elif type(root) == dict:
            # Make a copy since we may be modifying the contents of the structure we're walking
            for key, value in root.copy().items():
                if type(value) == dict or type(value) == list:
                    self.resolve_rule_references(root[key])
                else:
                    root[key] = self.resolve_rule_reference(value)

    def resolve_rule_reference(self, value):
        strValue = str(value)
        if strValue.startswith('$') and strValue.endswith('$') and strValue[1:-1] in self.rule:
            if type(value) == int:
                return int(self.rule[strValue[1:-1]])
            else:
                return self.rule[strValue[1:-1]]
        else:
            return value

    def alert(self, match):
        """ Send an alert. Match is a dictionary of information about the alert.

        :param match: A dictionary of relevant information to the alert.
        """
        raise NotImplementedError()

    def get_info(self):
        """ Returns a dictionary of data related to this alert. At minimum, this should contain
        a field type corresponding to the type of Alerter. """
        return {'type': 'Unknown'}

    def create_title(self, matches):
        """ Creates custom alert title to be used, e.g. as an e-mail subject or JIRA issue summary.

        :param matches: A list of dictionaries of relevant information to the alert.
        """
        if 'alert_subject' in self.rule:
            return self.create_custom_title(matches)

        return self.create_default_title(matches)

    def create_custom_title(self, matches):
        alert_subject = str(self.rule['alert_subject'])
        alert_subject_max_len = int(self.rule.get('alert_subject_max_len', 2048))

        if 'alert_subject_args' in self.rule:
            alert_subject_args = self.rule['alert_subject_args']
            alert_subject_values = [lookup_es_key(matches[0], arg) for arg in alert_subject_args]

            # Support referencing other top-level rule properties
            # This technically may not work if there is a top-level rule property with the same name
            # as an es result key, since it would have been matched in the lookup_es_key call above
            for i, subject_value in enumerate(alert_subject_values):
                if subject_value is None:
                    alert_value = self.rule.get(alert_subject_args[i])
                    if alert_value:
                        alert_subject_values[i] = alert_value

            missing = self.rule.get('alert_missing_value', '<MISSING VALUE>')
            alert_subject_values = [missing if val is None else val for val in alert_subject_values]
            alert_subject = alert_subject.format(*alert_subject_values)

        if len(alert_subject) > alert_subject_max_len:
            alert_subject = alert_subject[:alert_subject_max_len]

        return alert_subject

    def create_alert_body(self, matches):
        body = self.get_aggregation_summary_text(matches)
        if self.rule.get('alert_text_type') != 'aggregation_summary_only':
            for match in matches:
                body += str(BasicMatchString(self.rule, match))
                # Separate text of aggregated alerts with dashes
                if len(matches) > 1:
                    body += '\n----------------------------------------\n'
        return body

    def get_aggregation_summary_text__maximum_width(self):
        """Get maximum width allowed for summary text."""
        return 80

    def get_aggregation_summary_text(self, matches):
        text = ''
        if 'aggregation' in self.rule and 'summary_table_fields' in self.rule:
            text = self.rule.get('summary_prefix', '')
            summary_table_fields = self.rule['summary_table_fields']
            if not isinstance(summary_table_fields, list):
                summary_table_fields = [summary_table_fields]
            # Include a count aggregation so that we can see at a glance how many of each aggregation_key were encountered
            summary_table_fields_with_count = summary_table_fields + ['count']
            text += "Aggregation resulted in the following data for summary_table_fields ==> {0}:\n\n".format(
                summary_table_fields_with_count
            )
            text_table = Texttable(max_width=self.get_aggregation_summary_text__maximum_width())
            text_table.header(summary_table_fields_with_count)
            # Format all fields as 'text' to avoid long numbers being shown as scientific notation
            text_table.set_cols_dtype(['t' for i in summary_table_fields_with_count])
            match_aggregation = {}

            # Maintain an aggregate count for each unique key encountered in the aggregation period
            for match in matches:
                key_tuple = tuple([str(lookup_es_key(match, key)) for key in summary_table_fields])
                if key_tuple not in match_aggregation:
                    match_aggregation[key_tuple] = 1
                else:
                    match_aggregation[key_tuple] = match_aggregation[key_tuple] + 1
            for keys, count in match_aggregation.items():
                text_table.add_row([key for key in keys] + [count])
            text += text_table.draw() + '\n\n'
            text += self.rule.get('summary_prefix', '')
        return str(text)

    def create_default_title(self, matches):
        return self.rule['name']

    def get_account(self, account_file):
        """ Gets the username and password from an account file.

        :param account_file: Path to the file which contains user and password information.
        It can be either an absolute file path or one that is relative to the given rule.
        """
        if os.path.isabs(account_file):
            account_file_path = account_file
        else:
            account_file_path = os.path.join(os.path.dirname(self.rule['rule_file']), account_file)
        account_conf = yaml_loader(account_file_path)
        if 'user' not in account_conf or 'password' not in account_conf:
            raise EAException('Account file must have user and password fields')
        self.user = account_conf['user']
        self.password = account_conf['password']


