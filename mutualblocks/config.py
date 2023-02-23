from dataclasses import dataclass
from pathlib import Path
import configparser
import sys


@dataclass
class Config(object):
    instance_url: str
    query_domain: str
    bearer_token: str
    autoblock_reason: str = '(automatic) mutual block'
    stale_threshold_days: int = 7

    @staticmethod
    def load(filename: str) -> 'Config':
        filepath = Path(filename)
        filemode = filepath.stat().st_mode
        if filemode & 0o077 != 0:
            print(f"fixing insecure config file permissions: {filemode:o}", file=sys.stderr)
            filepath.chmod(0o600)

        p = configparser.ConfigParser()
        p.read(filename)
        return Config(**p['mutualblocks']) 
