from .config import Config
from dataclasses import dataclass
from pathlib import Path
from pprint import pprint
from urllib.request import Request, urlopen, HTTPError
import json
import sys


known_policy_sets = [
    'accept',
    'avatar_removal',
    'banner_removal',
    'federated_timeline_removal',
    'followers_only',
    'media_nsfw',
    'media_removal',
    'reject',
    'reject_deletes',
    'report_removal',
]


class PleromaApi(object):
    instance_url: str
    auth_headers: dict[str, str]

    def __init__(self, config: Config) -> None:
        self.instance_url = config.instance_url
        self.auth_headers = {}

        if config.bearer_token:
            self.auth_headers['Authorization'] = f'Bearer {config.bearer_token}'
        elif config.admin_token:
            self.auth_headers['X-Admin-Token'] = config.admin_token
        else:
            raise RuntimeError('need either a bearer_token or admin_token')

    def fetch_simple_mrf_config(self) -> 'SimpleMrfConfig':
        req = Request(f'{self.instance_url}/api/v1/pleroma/admin/config', headers=self.auth_headers)

        with urlopen(req) as res:
            if res.status != 200:
                raise RuntimeError("couldn't fetch instance config")
            data = json.load(res)
        
        for config in data['configs']:
            if config['group'] == ':pleroma' and config['key'] == ':mrf_simple':
                return SimpleMrfConfig(config['value'])

        raise RuntimeError("no matching config found")

    def apply_simple_mrf_config(self, mrf_config: 'SimpleMrfConfig') -> None:
        data_dict = mrf_config.marshal()
        data_json = json.dumps(data_dict)
        data_bytes = data_json.encode()

        headers = self.auth_headers.copy()
        headers['Content-Type'] = 'application/json; charset=utf-8'
        req = Request(
            f'{self.instance_url}/api/v1/pleroma/admin/config',
            headers=headers,
            method='POST',
            data=data_bytes,
        )

        try:
            with urlopen(req) as res:
                if res.status != 200:
                    raise RuntimeError(f"couldn't write instance config: {res.status}")
        except HTTPError as e:
            print(e)
            raise e


class SimpleMrfConfig(object):
    policies: dict[str, list['SimpleMrfRule']]
    modified: bool = False

    def __init__(self, rows):
        self.policies = {}

        remaining_policy_sets = known_policy_sets

        for row in rows:
            [policy_set, tuples] = row['tuple']
            policy_set = policy_set.lstrip(':')

            if policy_set == 'handle_threads':
                continue

            try:
                i = remaining_policy_sets.index(policy_set)
                remaining_policy_sets.pop(i)
            except ValueError:
                print(f"warning: unknown policy set in server response: {policy_set}", file=sys.stderr)
                continue

            self.policies[policy_set] = [SimpleMrfRule.from_tuple(t) for t in tuples]

        if remaining_policy_sets:
            print("warning: not all policy sets were found:", remaining_policy_sets, file=sys.stderr)

    def add(self, policy_set: str, pattern: str, reason: str) -> None:
        rule = SimpleMrfRule(pattern, reason)
        self.policies[policy_set].append(rule)
        self.modified = True

    def remove(self, policy_set: str, rule: 'SimpleMrfRule') -> None:
        self.policies[policy_set].remove(rule)
        self.modified = True

    def sort(self, policy_set: str, reason: str) -> None:
        self.policies[policy_set].sort(key=lambda rule: rule.reason != reason)

    def marshal(self) -> dict:
        reject_tuples = [r.marshal() for r in self.policies['reject']]

        return {
            'configs': [
                {
                    'group': ':pleroma',
                    'key': ':mrf_simple',
                    'value': [
                        {
                            'tuple': [':reject', reject_tuples]
                        }
                    ]
                }
            ]
        }

@dataclass
class SimpleMrfRule(object):
    pattern: str
    reason: str

    @staticmethod
    def from_tuple(data: dict) -> 'SimpleMrfRule':
        return SimpleMrfRule(*data['tuple'])

    def matches(self, domain: str) -> bool:
        if self.pattern.startswith('*.'):
            # really crude subdomain check because i can't think of a less
            # cursed way to do this properly right now
            pattern_subdomain_suffix = self.pattern[1:]
            pattern_domain = self.pattern[2:]
            return domain.endswith(pattern_subdomain_suffix) or domain == pattern_domain
        else:
            return domain == self.pattern

    def marshal(self):
        return {'tuple': [self.pattern, self.reason]}

    def __repr__(self):
        return f"<SimpleMrfRule pattern={self.pattern} reason={self.reason}>"


@dataclass
class FbaResponse(object):
    blockers: dict[str, list['FbaRule']]

    @staticmethod
    def fetch(query_domain: str) -> 'FbaResponse':
        cache_file = Path('~/.cache/update-mutual-blocks.json').expanduser()

        try:
            with open(cache_file) as f:
                cache = json.load(f)
            print("Cache loaded", file=sys.stderr)
        except FileNotFoundError:
            print("Creating fresh cache", file=sys.stderr)
            cache = {}

        req_headers = {}

        if cache_etag := cache.get('http-etag'):
            req_headers['if-none-match'] = cache_etag

        if cache_last_modified := cache.get('http-last-modified'):
            req_headers['if-modified-since'] = cache_last_modified

        req = Request(f'https://fba.ryona.agency/api?domain={query_domain}', headers=req_headers)

        with urlopen(req) as res:
            if res.status == 304: # not modified
                body = cache['body']
                print("Using cached response")

            elif res.status == 200:
                body = res.read().decode()
                cache['http-etag'] = res.getheader('etag')
                cache['http-last-modified'] = res.getheader('last-modified')
                cache['body'] = body
                with open(cache_file, 'w') as f:
                    json.dump(cache, f)
                print("Cached fresh response")

            else:
                raise RuntimeError(res.status, res.msg)

        data = json.loads(body)
        return FbaResponse(data)

    def __init__(self, data):
        self.blockers = {}
        for (policy_set, rules) in data.items():
            self.blockers[policy_set] = [FbaRule(**r) for r in rules]


@dataclass
class FbaRule(object):
    blocker: str
    blocked: str
    reason: str
    first_added: int
    last_seen: int
