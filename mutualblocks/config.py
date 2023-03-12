from dataclasses import dataclass
from pathlib import Path
from typing import Optional
import configparser
import sys


@dataclass
class Config(object):
    instance_url: str
    query_domain: str
    bearer_token: Optional[str] = None
    admin_token: Optional[str] = None
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
