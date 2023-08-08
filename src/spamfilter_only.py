#!/usr/bin/env python3

import json, logging, re, sys
from os import getcwd

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
url_pattern = re.compile(r'http[s]?://')
# https://bitcoin.stackexchange.com/a/107962/101
bolt11_pattern = re.compile(r'lnbc[A-Za-z0-9]{190}')

def event_flow_control(id: str, action = 'accept', message: str = None):
    response = {
        'id': id,
        'action': action
    }
    if message:
        response['msg'] = message

    # Dump the json to a string without whitespace.
    response = json.dumps(response, separators=(',', ':'))
    logging.info(response)
    # Ensure stdout is line buffered for strfry.
    print(response, flush=True)

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
        event_flow_control(req['event']['id'], 'reject', 'blocked: banned')
        continue

    event_kind = req.get('event').get('kind') 
    event_content = req.get('event').get('content')
    if event_kind == 1:
        # When printing messages, we will stop printing at the first line break.
        line_break_index = event_content.find("\n")
        # Events with kind 1 are short notes.
        if re.search(url_pattern, event_content):
            event_flow_control(req['event']['id'], 'reject', 'Spam filter: URLs are not allowed in notes on this free relay.')
            logging.debug(f"Rejected note content: {event_content[:line_break_index][:25]}")
        elif re.search(bolt11_pattern, event_content):
            event_flow_control(req['event']['id'], 'reject', 'Spam filter: Bolt11 invoices are not allowed in notes on this free relay.')
            logging.debug(f"Rejected note content: {event_content[:line_break_index][:25]}")
        else:
            event_flow_control(req['event']['id'])
            logging.debug(f"Accepted note content: {event_content[:line_break_index][:25]}")
    elif event_kind == 4:
        event_flow_control(req['event']['id'], 'reject', 'Spam filter: DMs and chat groups are not allowed on this free relay.')
        logging.debug(f"Rejected kind 4 (chat).")
    else:
        # Accept all other events.
        event_flow_control(req['event']['id'])