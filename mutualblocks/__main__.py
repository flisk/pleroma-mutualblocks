from . import PleromaApi, FbaResponse, FbaRule, SimpleMrfConfig, SimpleMrfRule
from .config import Config
from pprint import pprint
import time


def main() -> None:
    """
    needed for suspend delta:
    - set of domain rules currently auto-suspended
    - set of domain rules we should suspend

    to generate set of current auto-suspend patterns:
    - start with full set of suspend rules
    - filter out rules that aren't managed by this program

    to generate set of patterns we should suspend:
    - start with full set of known suspending instances
    - filter out suspends older than threshold
    - filter out suspends already matched by a manual suspend rule
    """
    config = Config.load('config.ini') 

    api = PleromaApi(config.instance_url, config.bearer_token)

    mrf_config = api.fetch_simple_mrf_config()
    fba_response = FbaResponse.fetch(config.query_domain)

    (current_auto_rules, current_manual_rules) = current_rules(mrf_config, config.autoblock_reason)
    current_auto_domains = [rule.pattern for rule in current_auto_rules]

    target_auto_domains = target_autosuspend_domains(current_manual_rules, fba_response, config.stale_threshold_days * 86400)

    for target_domain in target_auto_domains:
        if target_domain not in current_auto_domains:
            print(f"adding autoblock: {target_domain}")
            mrf_config.add('reject', target_domain, config.autoblock_reason)
    
    for current_rule in current_auto_rules:
        if current_rule.pattern not in target_auto_domains:
            print(f"removing autoblock: {current_rule.pattern}")
            mrf_config.remove('reject', current_rule)

    mrf_config.sort('reject', config.autoblock_reason)

    if mrf_config.modified:
        print("mrf_config modified, applying...")
        api.apply_simple_mrf_config(mrf_config)
    else:
        print("mrf_config not modified")


def current_rules(mrf_config: SimpleMrfConfig, auto_reason: str) -> tuple[list[SimpleMrfRule], list[SimpleMrfRule]]:
    auto_rules = []
    manual_rules = []

    for rule in mrf_config.policies['reject']:
        if rule.reason == auto_reason:
            auto_rules.append(rule)
        else:
            manual_rules.append(rule)

    return (auto_rules, manual_rules)


def target_autosuspend_domains(
    current_manual: list[SimpleMrfRule],
    fba_response: FbaResponse,
    stale_seconds: int,
) -> list[str]:
    unix_now = time.time()

    rejects = fba_response.blockers['reject']
    non_stale_rejects = filter(lambda rule: unix_now - rule.last_seen < stale_seconds, rejects)

    def not_manually_blocked(rule: FbaRule) -> bool:
        matches = map(lambda mrf_rule: mrf_rule.matches(rule.blocker), current_manual)
        return not any(matches)

    non_stale_automatic_rejects = filter(not_manually_blocked, non_stale_rejects)

    domains = map(lambda rule: rule.blocker, non_stale_automatic_rejects)
    return list(domains)


def pattern_for_domain(domain: str) -> str:
    parts = domain.split('.')
    second_level_domain = '.'.join(parts[-2:])
    return f'*.{second_level_domain}'


if __name__ == '__main__':
    main()
