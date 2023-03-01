# strfry-plugin

This is a spam filter that I am trying out. It is intended for use on a free relay where the spam is very, very bad.

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
