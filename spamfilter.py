#!/opt/strfry/.venv/bin/python

import json, logging, re, sys
from os import getcwd
import collector
from pprint import pprint

log_file = f"{getcwd()}/plugin.log"

logging.basicConfig(
    filename=log_file,
    format='%(asctime)s %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    level=logging.INFO
)
ban_list = [
    None,
#   '83768054ef906ca493dcf703dd93b73fa71054ec80f83e71e2eb68eb5139e1d6',
]
#url_pattern = re.compile(r'http[s]?://')
url_pattern = r'http[s]?://'
vmess_pattern = r'vmess://'
# https://bitcoin.stackexchange.com/a/107962/101
bolt11_pattern = r'lnbc[A-Za-z0-9]{190}'
lnurl_pattern = r'lnurl[A-Za-z0-9]{100}'

def event_flow_control(req: dict, action = 'accept', message: str = None):
    response = {
        'id': req['event']['id'],
        'action': action
    }
    if message:
        response['msg'] = message

    # Dump the json to a string without whitespace.
    response = json.dumps(response, separators=(',', ':'))
    # Ensure stdout is line buffered for strfry.
    print(response, flush=True)
    logging.info(f"{action}ed event_kind: {req['event']['kind']} from {req['sourceInfo']} {req['event']['pubkey']}")

strfry_metrics = collector.strfryCollector()
collector.start_http_server(collector.METRICS_PORT, collector.METRICS_BIND)
collector.REGISTRY.register(strfry_metrics)

other_event_kinds = {'periodic_report': 0}
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
        # This will show up in systemd journal.
        print('PLUGIN: unexpected request type', file=sys.stderr)
        continue

    # Block banned pubkeys.
    if req['event']['pubkey'] in ban_list:
        event_flow_control(req['event'], 'reject', 'blocked: banned')
        continue

    event_kind = req.get('event').get('kind')  or ""
    # Block notes and channel messages with URLs and bolt11 invoices.
    if event_kind == 1 or event_kind == 42:
        event_content = req.get('event').get('content') or ""
        if re.search(url_pattern, event_content, re.IGNORECASE):
            event_flow_control(req, 'reject', 'Spam filter: URLs are not allowed in notes on this free relay.')
            strfry_metrics.spam_events['url'] += 1
        elif re.search(vmess_pattern, event_content, re.IGNORECASE):
            event_flow_control(req, 'reject', 'Spam filter: URLs are not allowed in notes on this free relay.')
            strfry_metrics.spam_events['url'] += 1
        elif re.search(bolt11_pattern, event_content, re.IGNORECASE):
            event_flow_control(req, 'reject', 'Spam filter: Bolt11 invoices are not allowed in notes on this free relay.')
            strfry_metrics.spam_events['bolt11'] += 1
        elif re.search(lnurl_pattern, event_content, re.IGNORECASE):
            event_flow_control(req, 'reject', 'Spam filter: LNURLs are not allowed in notes on this free relay.')
            strfry_metrics.spam_events['bolt11'] += 1
        else:
            event_flow_control(req, 'accept')
            strfry_metrics.event_kinds[1] += 1
    # Block chat and direct messages.
    elif event_kind == 4 or event_kind == 42:
        event_flow_control(req, 'reject', 'Spam filter: DMs and chat groups are not allowed on this free relay.')
        strfry_metrics.spam_events['chat'] += 1
    # Accept all other events.
    else:
        # Count metrics for accepted events.
        # Could do a for loop here but guessing that's slower.
        if event_kind == 7 or \
            event_kind == 6 or \
            event_kind == 9735 or \
            event_kind == 30000:
            strfry_metrics.event_kinds[event_kind] += 1
        else:
            strfry_metrics.event_kinds['other'] += 1
            # Count other event kinds for internal visibility.
            if other_event_kinds.get(event_kind):
                other_event_kinds[event_kind] += 1
            else:
                other_event_kinds[event_kind] = 1
#           # Periodically log a count of the other event kinds.
#           if other_event_kinds['periodic_report'] > 10:
#               other_events = dict(sorted(other_event_kinds.items(), key=lambda x: x[1], reverse=True))
#               logging.info(f"Top 5 other_event_kinds: {other_events[:5]}")
#               other_event_kinds['periodic_report'] = 1
#           else:
#               other_event_kinds['periodic_report'] += 1
#       other_events = dict(sorted(other_event_kinds.items(), key=lambda x: x[1], reverse=True))
#       logging.info(other_events[:5])
        event_flow_control(req, 'accept')
