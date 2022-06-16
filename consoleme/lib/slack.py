import sys
import uuid
import random

import tornado.escape
import ujson as json
from tornado.httpclient import AsyncHTTPClient, HTTPClientError, HTTPRequest
from tornado.httputil import HTTPHeaders

from consoleme.config import config
from consoleme.lib.plugins import get_plugin_by_name
from consoleme.lib.policies import get_policy_request_uri_v2
from consoleme.models import ExtendedRequestModel

from slack import WebClient

log = config.get_logger()
stats = get_plugin_by_name(config.get("plugins.metrics", "default_metrics"))()


def slack_preflight_check(func):
    async def shortcircuit():
        return None

    def wrapper(*args, **kwargs):
        if not config.get("slack.notifications_enabled", False):
            return shortcircuit()
        return func(*args, **kwargs)

    return wrapper


@slack_preflight_check
async def send_slack_notification_new_policy_request(
    extended_request: ExtendedRequestModel, admin_approved, approval_probe_approved
):
    """
    Sends a notification using specified webhook URL about a new request created
    """

    if admin_approved and config.get("slack.ignore_auto_admin_policies", False):
        # Don't send slack notifications for policies that were auto approved due to admin status
        return None

    slack_api_token = config.get("slack.api_token", False)
    if not slack_api_token:
        log.error(
            f"Missing slack api token for slack notification."
        )
        return

    client = WebClient(token=slack_api_token)
    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    requester = extended_request.requester_email
    requester_info = client.users_lookupByEmail(email=requester)
    requester_id = requester_info["user"]["id"]

    assignee_id = None
    if not admin_approved and not approval_probe_approved:
        groups_request_assignee = config.get("groups.request_assignee")
        if not groups_request_assignee:
            log.error(
                f"Missing request assignee group for slack notification."
                )
            return
        assignee = random.choice(groups_request_assignee)
        assignee_info = client.users_lookupByEmail(email=assignee)
        assignee_id = assignee_info["user"]["id"]

    arn = extended_request.principal.principal_arn
    stats.count(function, tags={"user": requester, "arn": arn})

    payload_id = uuid.uuid4()

    log_data: dict = {
        "function": f"{__name__}.{sys._getframe().f_code.co_name}",
        "user": requester,
        "arn": arn,
        "message": "Incoming request for slack notification",
        "request": extended_request.dict(),
        "admin_approved": admin_approved,
        "approval_probe_approved": approval_probe_approved,
        "payload_id": payload_id,
    }
    log.debug(log_data)

    payload = await _build_policy_payload(
        extended_request, requester_id, arn, admin_approved, approval_probe_approved,
        assignee_id
        )

    return await send_slack_notification(payload, payload_id)


@slack_preflight_check
async def send_slack_notification(payload, payload_id):
    """
    Sends a notification using specified webhook URL about a new request created
    """

    slack_webhook_url = config.get("slack.webhook_url")
    if not slack_webhook_url:
        log.error(
            f"Missing webhook URL for slack notification. Not sending payload: {payload_id}"
        )
        return

    http_headers = HTTPHeaders({"Content-Type": "application/json"})
    http_req = HTTPRequest(
        url=slack_webhook_url,
        method="POST",
        headers=http_headers,
        body=json.dumps(payload),
    )

    http_client = AsyncHTTPClient(force_instance=True)
    try:
        await http_client.fetch(request=http_req)
        log.debug(f"Slack notifications sent for payload: {payload_id}")
    except (ConnectionError, HTTPClientError) as e:
        log.error(
            f"Slack notifications could not be sent for payload: {payload_id} due to {str(e)}"
        )


async def _build_policy_payload(
    extended_request: ExtendedRequestModel,
    requester: str,
    arn: str,
    admin_approved: bool,
    approval_probe_approved: bool,
    assignee: str = None
):
    request_uri = await get_policy_request_uri_v2(extended_request)
    pre_text = ""
    request_text = f"<@{requester}>"
    if admin_approved:
        pre_text += "관리자에 의해 자동 승인되었습니다."
    elif approval_probe_approved:
        pre_text += "auto-approved by auto-approval probe"
    elif assignee:
        pre_text += f"*담당자* :arrow_forward: <@{assignee}>"
        request_text += " 님, \n 요청 사항은 확인 후 스레드에 업데이트됩니다."

    payload = {
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*<{request_uri}|ConsoleMe 권한 요청>*",
                },
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*신청자* \n {request_text}"},
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*적용 대상* \n `{arn}`"},
            },
            {
                "type": "section",
                "fields": [
                    {"text": "*요청 내용*", "type": "mrkdwn"},
                    {"type": "plain_text", "text": "\n"},
                    {
                        "type": "plain_text",
                        "text": f"{tornado.escape.xhtml_escape(extended_request.justification)}",
                    },
                ],
            },
            {"type": "divider"},
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"{pre_text}",
                },
            },
        ]
    }
    return payload
