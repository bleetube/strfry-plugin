
# https://github.com/prometheus/client_python
from prometheus_client import start_http_server, Summary
from prometheus_client.core import GaugeMetricFamily, REGISTRY
from time import sleep
from os import getcwd
from dotenv import dotenv_values
config = dotenv_values(f"{getcwd()}/.env")

REQUEST_TIME = Summary('request_processing_seconds', 'Time spent processing request')
METRICS_PORT = int(config.get('STRFRY_METRICS_PORT', 9101))
METRICS_BIND = config.get('STRFRY_METRICS_BIND', '127.0.0.1')

class strfryCollector(object):
    def __init__(self) -> None:
        # We do not want metrics for all possible event types because it compounds our cardinality.
        # See: https://www.robustperception.io/cardinality-is-key/
        self.event_kinds = {
            1:0, # Short Text Note
            7:0, # Reaction (nip-25)
            6:0, # Reposts (nip-18)
            1984:0, # Reporting (nip-56)
            9735:0, # Zap (nip-57)
            'other':0,
        }
        self.spam_events = {'url':0, 'bolt11':0, 'chat':0}

    @REQUEST_TIME.time()
    def collect(self):
        try:
            yield GaugeMetricFamily('rejected_note_url_spam', 'Rejected event kind 1 notes with a url', value=self.spam_events['url'])
            yield GaugeMetricFamily('rejected_note_bolt11_spam', 'Rejected event kind 1 notes with a bolt11 invoice', value=self.spam_events['bolt11'])
            yield GaugeMetricFamily('rejected_chat_spam', 'Rejected event kind 4 chats and direct messages', value=self.spam_events['chat'])
#           # Labels and values are mutually exclusive.
            g = GaugeMetricFamily( "events", "Count of events by kind", labels=[ "kind" ])
            for event in self.event_kinds.keys():
                g.add_metric([str(event),], self.event_kinds[event])
            yield g

        except Exception as e:
            exit( f"Exception: \n{e}")
