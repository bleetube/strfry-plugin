# strfry-plugin

This is a basic Python plugin for strfry. It provides an exporter for Promtheus openmetrics, and a brutally simple spam filter.

Alternatives:
* [strfry-policies](https://gitlab.com/soapbox-pub/strfry-policies/-/tree/develop/src/policies) (typescript)
* [spamblaster](https://github.com/relaytools/spamblaster) (go)

## Spam policies

* All event kind 4 direct messages are rejected.
* URLs are not permitted in event kind 1 notes.
* Bolt11 lightning invoices in event kind 1 notes are rejected.
* NIP-95 (file hosting on relays) is rejected.

## usage

See the strfry [plugin documentation](https://github.com/hoytech/strfry/blob/master/docs/plugins.md).

## metrics

```bash
pip install --upgrade pip
pip install prometheus_client python-dotenv
```

### environment variables

Define these optional variables in `.env`:

```ini
STRFRY_METRICS_PORT=9101
STRFRY_METRICS_BIND=127.0.0.1
```

You can test its working after your start strfry with the filter configured with `curl localhost:9101`

```prometheus
# HELP rejected_note_url_spam Rejected event kind 1 notes with a url
# TYPE rejected_note_url_spam gauge
rejected_note_url_spam 877.0
# HELP rejected_note_bolt11_spam Rejected event kind 1 notes with a bolt11 invoice
# TYPE rejected_note_bolt11_spam gauge
rejected_note_bolt11_spam 23.0
# HELP rejected_chat_spam Rejected event kind 4 chats and direct messages
# TYPE rejected_chat_spam gauge
rejected_chat_spam 1.0
# HELP events Count of events by kind
# TYPE events gauge
events{kind="1"} 33.0
events{kind="7"} 83.0
events{kind="6"} 10.0
events{kind="1984"} 0.0
events{kind="9735"} 3.0
events{kind="other"} 198.0
```

### top talker

You can identify top talkers with:

```bash
tail -40000 plugin.log | awk '{print $8}' | cut -d, -f1 | sort | uniq -c | sort -nr | head
```
