"""Bundle dashboard configuration metadata from the actual rules file, not flags."""
import hashlib
import json
from pathlib import Path
import yaml

root = Path(__file__).resolve().parents[2]
raw = (root / '.reviewer.yaml').read_bytes()
config = yaml.safe_load(raw)
out = root / 'dashboard/app/panel_policy.json'
out.write_text(json.dumps({'source': '.reviewer.yaml at dashboard build (not historical review policy)',
                           'sha256': hashlib.sha256(raw).hexdigest(),
                           'agents': config['agents'], 'rules': config['rules']}, indent=2) + '\n')
print(out)
