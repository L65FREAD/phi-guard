# phi-guard

A Claude Code plugin that checks every message you send for likely PHI. If it finds any, the message is blocked before it reaches the model, and a scrubbed copy (`Patient [NAME], DOB [DOB]`) is shown and put on your clipboard so you can paste and resend.

This is a convenience guard, not a compliance control. It uses pattern matching, it will miss things, and anyone can turn it off.

## Install

```
/plugin marketplace add L65FREAD/claude-phi-guard
/plugin install phi-guard@phi-guard
```

Restart Claude Code afterwards. Requires `python3` on your PATH.

## Turn it on or off

- Toggle it in `/plugin` (takes effect next session).
- Skip it for one session: `PHI_GUARD=off claude`

## What it catches

| Anywhere | Only next to a label |
|---|---|
| SSNs | Dates of birth (`DOB`, `born`) |
| Email addresses | MRNs and patient IDs |
| Formatted phone numbers, `+1XXXXXXXXXX` | Rx numbers |
| Slash dates (`03/14/1961`) and written dates (`March 3, 1975`) | Member, policy and group IDs |
| Street addresses (capitalised) and PO boxes | Bare 10-digit phone numbers |
| | Names (after `patient`, `pt`, `name:`, `Mr.`/`Mrs.`/`Ms.`) |

## What it does not catch

- Names with no label in front ("John Smith called about his refill").
- ISO dates and timestamps (`2026-11-11`) unless labelled as a DOB.
- Lowercase street addresses.
- Anything Claude reads from files, tools or connectors. Only typed or pasted prompts are scanned.

Always glance at the scrubbed copy before resending.

## False positives

Add one regex per line to `~/.claude/phi-guard-allowlist.txt`. Each is matched case-insensitively against the whole flagged text:

```
.*@yourcompany\.com
555-555-\d{4}
```

## If the guard itself breaks

It fails closed: an error in the script blocks the message. Disable the plugin in `/plugin` or start with `PHI_GUARD=off` to get unblocked.
