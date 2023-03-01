# strfry-plugin

This is a spam filter that I am trying out. It is intended for use on a free relay where the spam is very, very bad.

I also slapped on some metric collection for a monitoring stack like Prometheus.

## Spam policies

* All event kind 4 direct messages are rejected.

* URLs are not permitted in event kind 1 notes.

* Bolt11 lightning invoices in event kind 1 notes are rejected.

## usage

See the strfry [plugin documentation](https://github.com/hoytech/strfry/blob/master/docs/plugins.md).

To start, you can try out the `spamfilter_basic.py` script. More advanced users may be interested in the devops metrics described below.

## optional metrics

`spamfilter.py`

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