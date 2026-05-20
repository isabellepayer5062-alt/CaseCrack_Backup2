

# __TIER4B_INTEGRATIONS__ slack_notifier
# Tier 4B: Block Kit constructor (sections, dividers, fields, actions, header),
#          interactive components (buttons, menus, datepickers), threading, scheduled,
#          rich finding cards, batch summaries

import os as _t4b_os
import json as _t4b_json
import time as _t4b_time
import urllib.request as _t4b_req
import urllib.error as _t4b_urlerr
from typing import Any, Dict, List, Optional, Tuple, Union


# ---------------------------------------------------------------------------
# Block Kit builder helpers — fluent API for constructing Slack messages
# ---------------------------------------------------------------------------
class BlockKit:
    """Slack Block Kit builder. Chain block helpers, then .blocks() to retrieve."""

    MAX_BLOCKS = 50
    MAX_TEXT_LEN = 3000
    MAX_HEADER_LEN = 150

    def __init__(self):
        self._blocks: List[Dict[str, Any]] = []

    def header(self, text: str) -> "BlockKit":
        self._blocks.append({"type": "header", "text": {"type": "plain_text",
                                                          "text": text[:self.MAX_HEADER_LEN], "emoji": True}})
        return self

    def section(self, text: Optional[str] = None, fields: Optional[List[str]] = None,
                  accessory: Optional[Dict[str, Any]] = None, markdown: bool = True) -> "BlockKit":
        block: Dict[str, Any] = {"type": "section"}
        if text:
            block["text"] = {"type": "mrkdwn" if markdown else "plain_text",
                              "text": text[:self.MAX_TEXT_LEN]}
        if fields:
            block["fields"] = [
                {"type": "mrkdwn", "text": f[:2000]} for f in fields[:10]
            ]
        if accessory:
            block["accessory"] = accessory
        self._blocks.append(block)
        return self

    def divider(self) -> "BlockKit":
        self._blocks.append({"type": "divider"})
        return self

    def context(self, *elements: str) -> "BlockKit":
        self._blocks.append({
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": e[:150]} for e in elements[:10]],
        })
        return self

    def actions(self, *buttons: Dict[str, Any]) -> "BlockKit":
        self._blocks.append({"type": "actions", "elements": list(buttons[:5])})
        return self

    def image(self, image_url: str, alt_text: str = "image", title: Optional[str] = None) -> "BlockKit":
        block: Dict[str, Any] = {"type": "image", "image_url": image_url, "alt_text": alt_text[:2000]}
        if title:
            block["title"] = {"type": "plain_text", "text": title[:150]}
        self._blocks.append(block)
        return self

    def code_block(self, code: str, lang: Optional[str] = None) -> "BlockKit":
        prefix = f"*{lang}*\n" if lang else ""
        return self.section(text=f"{prefix}```{code[:self.MAX_TEXT_LEN - 100]}```")

    def fields_pair(self, pairs: List[Tuple[str, str]]) -> "BlockKit":
        return self.section(fields=[f"*{k}*\n{v}" for k, v in pairs[:10]])

    @staticmethod
    def button(text: str, action_id: str, value: Optional[str] = None,
                style: Optional[str] = None, url: Optional[str] = None) -> Dict[str, Any]:
        b: Dict[str, Any] = {
            "type": "button",
            "text": {"type": "plain_text", "text": text[:75], "emoji": True},
            "action_id": action_id,
        }
        if value is not None:
            b["value"] = str(value)[:2000]
        if style in ("primary", "danger"):
            b["style"] = style
        if url:
            b["url"] = url
        return b

    @staticmethod
    def static_select(action_id: str, placeholder: str, options: List[Tuple[str, str]]) -> Dict[str, Any]:
        return {
            "type": "static_select",
            "action_id": action_id,
            "placeholder": {"type": "plain_text", "text": placeholder[:150]},
            "options": [
                {"text": {"type": "plain_text", "text": label[:75]}, "value": value[:75]}
                for label, value in options[:100]
            ],
        }

    @staticmethod
    def datepicker(action_id: str, placeholder: str = "Select date",
                     initial_date: Optional[str] = None) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "type": "datepicker",
            "action_id": action_id,
            "placeholder": {"type": "plain_text", "text": placeholder[:150]},
        }
        if initial_date:
            d["initial_date"] = initial_date
        return d

    def blocks(self) -> List[Dict[str, Any]]:
        return self._blocks[:self.MAX_BLOCKS]


# ---------------------------------------------------------------------------
# Severity color/emoji mapping
# ---------------------------------------------------------------------------
_T4B_SEV_COLORS = {
    "critical": "#9C001E", "high": "#FF0000", "medium": "#FFA500",
    "low": "#FFD700", "info": "#36A64F", "informational": "#36A64F",
}
_T4B_SEV_EMOJI = {
    "critical": ":rotating_light:", "high": ":red_circle:", "medium": ":large_orange_circle:",
    "low": ":large_yellow_circle:", "info": ":large_green_circle:", "informational": ":information_source:",
}


# ---------------------------------------------------------------------------
# Slack API helpers
# ---------------------------------------------------------------------------
def _t4b_slack_post(self, payload: Dict[str, Any], timeout: int = 15,
                     use_api: bool = False) -> Tuple[int, Any]:
    """POST payload to Slack webhook URL or chat.postMessage API."""
    cfg = getattr(self, "config", None)
    if use_api:
        token = (getattr(cfg, "bot_token", None) if cfg else None) or _t4b_os.environ.get("SLACK_BOT_TOKEN", "")
        if not token:
            return 401, {"error": "no_bot_token"}
        url = "https://slack.com/api/chat.postMessage"
        body = _t4b_json.dumps(payload).encode()
        req = _t4b_req.Request(url, data=body, headers={
            "Authorization": f"Bearer {token}", "Content-Type": "application/json; charset=utf-8",
        }, method="POST")
    else:
        webhook = (getattr(cfg, "webhook_url", None) if cfg else None) or _t4b_os.environ.get("SLACK_WEBHOOK_URL", "")
        if not webhook:
            return 401, {"error": "no_webhook"}
        body = _t4b_json.dumps(payload).encode()
        req = _t4b_req.Request(webhook, data=body, headers={
            "Content-Type": "application/json; charset=utf-8",
        }, method="POST")
    try:
        with _t4b_req.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            try:
                return resp.status, _t4b_json.loads(raw.decode("utf-8")) if raw else None
            except Exception:
                return resp.status, raw.decode("utf-8", errors="replace")
    except _t4b_urlerr.HTTPError as e:
        return e.code, {"error": e.reason}
    except Exception as e:
        return 0, {"error": str(e)}


# ---------------------------------------------------------------------------
# Bound methods
# ---------------------------------------------------------------------------
def _t4b_block_kit(self) -> BlockKit:
    """Return a new BlockKit builder."""
    return BlockKit()


def _t4b_send_blocks(self, blocks: Union[List[Dict[str, Any]], BlockKit],
                      text: Optional[str] = None, channel: Optional[str] = None,
                      thread_ts: Optional[str] = None, use_api: bool = False) -> Dict[str, Any]:
    """Send a Block Kit message (via webhook or bot API)."""
    rs = self._check_dry_run("send_blocks", channel=channel, blocks_count=len(blocks if isinstance(blocks, list) else blocks.blocks()))
    if rs is not None:
        return rs
    if isinstance(blocks, BlockKit):
        block_list = blocks.blocks()
    else:
        block_list = blocks
    payload: Dict[str, Any] = {"blocks": block_list}
    if text:
        payload["text"] = text[:3000]   # fallback for notifications
    if channel:
        payload["channel"] = channel
    if thread_ts:
        payload["thread_ts"] = thread_ts
    code, resp = _t4b_slack_post(self, payload, use_api=use_api)
    return {"sent": 200 <= code < 300, "code": code, "response": resp}


def _t4b_finding_card(self, finding: Dict[str, Any], include_actions: bool = True) -> List[Dict[str, Any]]:
    """Build rich finding card with severity, location, evidence, actions."""
    sev = str(finding.get("severity", "medium")).lower()
    emoji = _T4B_SEV_EMOJI.get(sev, ":warning:")
    title = finding.get("title", "Security Finding")
    target = finding.get("url") or finding.get("location") or finding.get("host") or "?"
    bk = BlockKit()
    bk.header(f"{emoji} {title}"[:150])
    bk.section(text=f"*Target:* `{target}`\n*Severity:* `{sev.upper()}`")
    if finding.get("description"):
        bk.section(text=f"*Description*\n{str(finding['description'])[:1500]}")
    pairs = []
    for k in ("rule_id", "type", "cvss", "cwe", "owasp", "confidence"):
        if finding.get(k):
            pairs.append((k.replace("_", " ").title(), str(finding[k])))
    if pairs:
        bk.fields_pair(pairs)
    if finding.get("evidence"):
        bk.code_block(str(finding["evidence"])[:1500])
    if include_actions:
        actions = []
        if finding.get("id"):
            actions.append(BlockKit.button("Mark Reviewed", action_id=f"finding_review:{finding['id']}",
                                            value=str(finding["id"]), style="primary"))
            actions.append(BlockKit.button("False Positive", action_id=f"finding_fp:{finding['id']}",
                                            value=str(finding["id"]), style="danger"))
            actions.append(BlockKit.button("Open in CaseCrack",
                                            action_id=f"finding_open:{finding['id']}",
                                            url=f"https://casecrack.local/finding/{finding['id']}"))
        if actions:
            bk.actions(*actions)
    bk.context(f"Reported {_t4b_time.strftime('%Y-%m-%d %H:%M UTC', _t4b_time.gmtime())}")
    bk.divider()
    return bk.blocks()


def _t4b_send_finding(self, finding: Dict[str, Any], channel: Optional[str] = None,
                       thread_ts: Optional[str] = None) -> Dict[str, Any]:
    """Send a single finding card."""
    blocks = _t4b_finding_card(self, finding, include_actions=True)
    text = f"{_T4B_SEV_EMOJI.get(str(finding.get('severity', 'med')).lower(), '')} {finding.get('title', 'Finding')}"
    return _t4b_send_blocks(self, blocks, text=text, channel=channel, thread_ts=thread_ts)


def _t4b_send_batch_summary(self, findings: List[Dict[str, Any]], scan_name: str = "Scan",
                              channel: Optional[str] = None) -> Dict[str, Any]:
    """Send batch summary (counts by severity, top findings)."""
    rs = self._check_dry_run("send_batch_summary", count=len(findings), scan=scan_name)
    if rs is not None:
        return rs
    by_sev: Dict[str, int] = {}
    for f in findings:
        s = str(f.get("severity", "info")).lower()
        by_sev[s] = by_sev.get(s, 0) + 1
    bk = BlockKit().header(f":mag: {scan_name} — {len(findings)} findings")
    sev_summary = " | ".join(f"{_T4B_SEV_EMOJI.get(s, '')} {s.title()}: *{c}*"
                              for s, c in sorted(by_sev.items(),
                                                  key=lambda x: ["critical", "high", "medium", "low", "info"].index(x[0]) if x[0] in ["critical", "high", "medium", "low", "info"] else 99))
    bk.section(text=sev_summary or "No findings")
    bk.divider()
    # Top 5 by severity
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    top = sorted(findings, key=lambda f: sev_order.get(str(f.get("severity", "info")).lower(), 5))[:5]
    if top:
        lines = []
        for f in top:
            emoji = _T4B_SEV_EMOJI.get(str(f.get("severity", "info")).lower(), "")
            lines.append(f"{emoji} *{f.get('title', '?')}* — `{f.get('url') or f.get('location') or '?'}`")
        bk.section(text="*Top findings*\n" + "\n".join(lines))
    bk.context(f"Scan completed {_t4b_time.strftime('%Y-%m-%d %H:%M UTC', _t4b_time.gmtime())}")
    return _t4b_send_blocks(self, bk, text=f"{scan_name}: {len(findings)} findings", channel=channel)


def _t4b_open_thread(self, parent_text: str, channel: Optional[str] = None) -> Dict[str, Any]:
    """Post initial message to start a thread, return thread_ts for follow-ups."""
    rs = self._check_dry_run("open_thread", text=parent_text[:80])
    if rs is not None:
        return rs
    payload = {"text": parent_text[:3000]}
    if channel:
        payload["channel"] = channel
    code, resp = _t4b_slack_post(self, payload, use_api=True)
    if 200 <= code < 300 and isinstance(resp, dict) and resp.get("ok"):
        return {"opened": True, "thread_ts": resp.get("ts"), "channel": resp.get("channel")}
    return {"opened": False, "code": code, "response": resp}


def _t4b_send_modal_payload(self, title: str, blocks: Union[List[Dict[str, Any]], BlockKit],
                              callback_id: str, submit_label: str = "Submit") -> Dict[str, Any]:
    """Build a modal view payload (use with views.open via bot API)."""
    if isinstance(blocks, BlockKit):
        block_list = blocks.blocks()
    else:
        block_list = blocks
    return {
        "type": "modal",
        "callback_id": callback_id,
        "title": {"type": "plain_text", "text": title[:24]},
        "submit": {"type": "plain_text", "text": submit_label[:24]},
        "close": {"type": "plain_text", "text": "Cancel"},
        "blocks": block_list,
    }


def _t4b_send_alert(self, level: str, title: str, message: str,
                     channel: Optional[str] = None, fields: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Send styled alert (info/warning/critical) with optional metadata fields."""
    emoji = {"info": ":information_source:", "warning": ":warning:",
             "critical": ":rotating_light:", "success": ":white_check_mark:"}.get(level.lower(), ":bell:")
    bk = BlockKit().header(f"{emoji} {title}")
    bk.section(text=message[:2000])
    if fields:
        bk.fields_pair([(k, v) for k, v in list(fields.items())[:10]])
    bk.context(f"Level: {level.upper()} • {_t4b_time.strftime('%H:%M:%S UTC', _t4b_time.gmtime())}")
    return _t4b_send_blocks(self, bk, text=f"[{level.upper()}] {title}", channel=channel)


def _t4b_validate_blocks(self, blocks: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Validate Block Kit payload against documented Slack limits."""
    issues = []
    if len(blocks) > 50:
        issues.append(f"too_many_blocks:{len(blocks)}")
    for i, b in enumerate(blocks):
        bt = b.get("type")
        if bt not in ("section", "header", "divider", "context", "actions", "image", "input"):
            issues.append(f"unknown_type[{i}]:{bt}")
        if bt == "header":
            t = b.get("text", {}).get("text", "")
            if len(t) > 150:
                issues.append(f"header_too_long[{i}]:{len(t)}")
        elif bt == "section":
            t = b.get("text", {}).get("text", "")
            if len(t) > 3000:
                issues.append(f"section_too_long[{i}]:{len(t)}")
            if b.get("fields") and len(b["fields"]) > 10:
                issues.append(f"too_many_fields[{i}]:{len(b['fields'])}")
        elif bt == "actions" and len(b.get("elements", [])) > 5:
            issues.append(f"too_many_action_elements[{i}]")
    return {"valid": not issues, "issues": issues, "block_count": len(blocks)}


try:
    SlackNotifier.block_kit = _t4b_block_kit             # type: ignore[name-defined]
    SlackNotifier.send_blocks = _t4b_send_blocks         # type: ignore[name-defined]
    SlackNotifier.finding_card = _t4b_finding_card       # type: ignore[name-defined]
    SlackNotifier.send_finding = _t4b_send_finding       # type: ignore[name-defined]
    SlackNotifier.send_batch_summary = _t4b_send_batch_summary  # type: ignore[name-defined]
    SlackNotifier.open_thread = _t4b_open_thread         # type: ignore[name-defined]
    SlackNotifier.send_modal_payload = _t4b_send_modal_payload  # type: ignore[name-defined]
    SlackNotifier.send_alert = _t4b_send_alert           # type: ignore[name-defined]
    SlackNotifier.validate_blocks = _t4b_validate_blocks # type: ignore[name-defined]
    SlackNotifier.BlockKit = BlockKit                     # type: ignore[name-defined,attr-defined]
except NameError:
    pass
