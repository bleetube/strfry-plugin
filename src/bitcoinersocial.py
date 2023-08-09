#!/var/lib/strfry/plugin/venv/bin/python

import json, logging, sys
import collector
import csv

plugin_path = "/var/lib/strfry/plugin"
log_file = f"{plugin_path}/plugin.log"
users_csv = f"{plugin_path}/users.csv"

logging.basicConfig(
    filename=log_file,
    format='%(asctime)s %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    level=logging.INFO
)

static_allow_list = [
    '0fce2f5f937e1087883f5359c8fe7258b272e7d987db9274697d8efb65ad3374', # noscl tests
]

def event_flow_control(req: dict, action = 'accept', message: str = "") -> None:
    """Return a JSON response string to the strfry daemon by printing to stdout."""

    # We must minify our json response string so to remove formatting whitespace.
    resp = json.dumps({
        'id': req['event']['id'],
        'action': action,
        'msg': message
    }, separators=(',', ':'))

    # We must ensure stdout is line buffered for strfry.
    print(resp, flush=True)
    logging.info(f"{action}ed event_kind: {req['event']['kind']} from {req['sourceInfo']} {req['event']['pubkey']}")

def import_user_pubkeys(filename) -> list:
    """Returns a list of user hexidecimal pubkeys from a CSV file."""

    pubkeys = []
    try:
        with open(filename, 'r') as file:
            reader = csv.DictReader(file)
            for row in reader:
                pubkeys.append(row['pubkey'])
    except Exception as e:
        logging.error(f"Error importing user pubkeys: {e}")
        sys.exit(1)

    return pubkeys

allow_list = import_user_pubkeys(users_csv) + static_allow_list

strfry_metrics = collector.strfryCollector()
collector.start_http_server(collector.METRICS_PORT, collector.METRICS_BIND)
collector.REGISTRY.register(strfry_metrics)
strfry_metrics_event_kinds = list(strfry_metrics.event_kinds.keys())

for line in sys.stdin:
    logging.debug(line)
    try:
        req = json.loads(line)
    except Exception as e:
        logging.error('invalid JSON')
        print('invalid JSON', file=sys.stderr)
        continue

    if req.get('type') == 'lookback':
        continue

    if req.get('type') != 'new':
        logging.error('unexpected request type')
        print('PLUGIN: unexpected request type', file=sys.stderr)
        continue

    # Allow all messages from registered users and static allow list
    if req['event']['pubkey'] not in allow_list:
        event_flow_control(req['event'], 'reject', 'Sorry, bitcoiner.social is temporarily private. We will open up access again later.')
        continue

    event_kind = req.get('event').get('kind')

    if event_kind in strfry_metrics_event_kinds:
        strfry_metrics.event_kinds[event_kind] += 1
    else:
        strfry_metrics.event_kinds['other'] += 1

    event_flow_control(req, 'accept')