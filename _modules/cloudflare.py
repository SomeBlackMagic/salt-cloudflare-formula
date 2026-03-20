# -*- coding: utf-8 -*-
"""Cloudflare execution module for DNS API calls."""

import logging

import requests
import salt.exceptions

__virtualname__ = "cloudflare"

ZONES_URI_TEMPLATE = "https://api.cloudflare.com/client/v4/zones/{zone_id}"
RECORDS_URI_TEMPLATE = (
    "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?page={page}&per_page={per_page}"
)
ADD_RECORD_URI_TEMPLATE = "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
RECORD_URI_TEMPLATE = "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}"
REQUEST_TIMEOUT = 30

logger = logging.getLogger(__name__)


def __virtual__():
    return __virtualname__


def _get_zone_id(zone):
    zone_id = zone.get("zone_id")
    if not zone_id:
        raise salt.exceptions.SaltInvocationError("'zone_id' is required")
    return zone_id


def _get_headers(zone):
    api_token = zone.get("api_token")
    auth_email = zone.get("auth_email")
    auth_key = zone.get("auth_key")

    if api_token:
        return {"Authorization": "Bearer {0}".format(api_token)}

    if auth_email and auth_key:
        return {"X-Auth-Email": auth_email, "X-Auth-Key": auth_key}

    raise salt.exceptions.SaltInvocationError(
        "Either api_token or auth_email and auth_key must be provided"
    )


def _request(zone, uri, method="GET", payload=None):
    headers = _get_headers(zone)
    logger.info("Cloudflare request: %s %s", method, uri)

    try:
        response = requests.request(
            method=method,
            url=uri,
            headers=headers,
            json=payload,
            timeout=REQUEST_TIMEOUT,
        )
    except requests.RequestException as err:
        raise salt.exceptions.CommandExecutionError(
            "Cloudflare request failed: {0}".format(err)
        )

    if not response.ok:
        raise salt.exceptions.CommandExecutionError(
            "Cloudflare returned HTTP {0}: {1}".format(
                response.status_code, response.text
            )
        )

    try:
        result = response.json()
    except ValueError:
        raise salt.exceptions.CommandExecutionError(
            "Cloudflare returned non-JSON response: {0}".format(response.text)
        )

    if isinstance(result, dict) and result.get("success") is False:
        raise salt.exceptions.CommandExecutionError(
            "Cloudflare API error: {0}".format(result.get("errors", []))
        )

    return result


def get_zone(zone):
    """Return zone details from Cloudflare API."""
    zone_id = _get_zone_id(zone)
    uri = ZONES_URI_TEMPLATE.format(zone_id=zone_id)
    return _request(zone, uri, method="GET")


def list_zone_records(zone, page=1, per_page=50):
    """Return one page of DNS records for a zone."""
    zone_id = _get_zone_id(zone)
    uri = RECORDS_URI_TEMPLATE.format(zone_id=zone_id, page=page, per_page=per_page)
    return _request(zone, uri, method="GET")


def list_all_zone_records(zone, per_page=50):
    """Return all DNS records for a zone by walking paginated API."""
    records = []
    page = 1

    while True:
        response = list_zone_records(zone, page=page, per_page=per_page)
        records.extend(response.get("result", []))

        result_info = response.get("result_info", {})
        current_page = result_info.get("page", page)
        total_pages = result_info.get("total_pages", 0)

        if total_pages == 0 or current_page >= total_pages:
            break

        page += 1

    return records


def add_dns_record(zone, record):
    """Create DNS record in Cloudflare zone."""
    zone_id = _get_zone_id(zone)
    uri = ADD_RECORD_URI_TEMPLATE.format(zone_id=zone_id)
    return _request(zone, uri, method="POST", payload=record)


def update_dns_record(zone, record_id, record):
    """Update DNS record in Cloudflare zone."""
    zone_id = _get_zone_id(zone)
    uri = RECORD_URI_TEMPLATE.format(zone_id=zone_id, record_id=record_id)
    return _request(zone, uri, method="PUT", payload=record)


def remove_dns_record(zone, record_id):
    """Delete DNS record from Cloudflare zone."""
    zone_id = _get_zone_id(zone)
    uri = RECORD_URI_TEMPLATE.format(zone_id=zone_id, record_id=record_id)
    return _request(zone, uri, method="DELETE")
