# -*- coding: utf-8 -*-
"""State module for Cloudflare DNS records management."""

from collections import namedtuple
import re

import salt.exceptions


__virtualname__ = "cloudflare"


class Record(
    namedtuple(
        "Record",
        ("id", "type", "name", "content", "priority", "proxied", "ttl", "salt_managed"),
    )
):
    def pure(self):
        return Record(
            None,
            self.type,
            self.name,
            self.content,
            self.priority,
            self.proxied,
            self.ttl,
            self.salt_managed,
        )

    def data(self):
        if self.type == "SRV":
            service, proto, name = self.name.split(".", 2)
            parts = self.content.split("\t")
            if len(parts) == 3:
                priority = 10
                weight, port, target = parts
            else:
                priority, weight, port, target = parts
            return {
                "service": service,
                "proto": proto,
                "name": name,
                "priority": int(priority),
                "weight": int(weight),
                "port": int(port),
                "target": target,
            }

        if self.type == "CAA":
            flags, tag, value = self.content.split(" ")
            return {
                "name": self.name,
                "flags": int(flags),
                "tag": tag,
                "value": value[1:-1],
            }

        return None

    def __str__(self):
        ttl_str = "auto" if self.ttl == 1 else "{0}s".format(self.ttl)
        priority_str = "priority: {0}, ".format(self.priority) if self.type == "MX" else ""
        return "{0} {1} -> '{2}' ({3}proxied: {4}, ttl: {5})".format(
            self.type,
            self.name,
            self.content,
            priority_str,
            str(self.proxied).lower(),
            ttl_str,
        )

    def json(self):
        payload = {
            "type": self.type,
            "name": self.name,
            "content": self.content,
            "proxied": self.proxied,
            "ttl": self.ttl,
        }

        data = self.data()
        if data is not None:
            payload["data"] = data

        if self.type == "MX":
            payload["priority"] = self.priority

        return payload


def __virtual__():
    required = (
        "cloudflare.get_zone",
        "cloudflare.list_all_zone_records",
        "cloudflare.add_dns_record",
        "cloudflare.update_dns_record",
        "cloudflare.remove_dns_record",
    )

    missing = [name for name in required if name not in __salt__]
    if missing:
        return False, "cloudflare execution module is not available: missing {0}".format(
            ", ".join(missing)
        )

    return __virtualname__


def manage_zone_records(name, zone):
    managed = Zone(name, zone)

    try:
        managed.sanity_check()
    except salt.exceptions.SaltInvocationError as err:
        return {
            "name": name,
            "changes": {},
            "result": False,
            "comment": "{0}".format(err),
        }

    diff = managed.diff()
    result = {"name": name, "changes": _changes(diff), "result": None}

    if len(diff) == 0:
        result["comment"] = "The state of {0} ({1}) is up to date.".format(
            name, zone["zone_id"]
        )
        result["changes"] = {}
        result["result"] = True
        return result

    if __opts__.get("test") is True:
        result["comment"] = "The state of {0} ({1}) will be changed ({2} changes).".format(
            name, zone["zone_id"], len(diff)
        )
        result["pchanges"] = result["changes"]
        return result

    managed.apply(diff)

    result["comment"] = "The state of {0} ({1}) was changed ({2} changes).".format(
        name, zone["zone_id"], len(diff)
    )
    result["result"] = True

    return result


def _changes(diff):
    changes = {}
    actions = ["{0} {1}".format(op["action"], str(op["record"])) for op in diff]
    if actions:
        changes["diff"] = "\n".join(actions)
    return changes


def validate_record(record):
    if "name" not in record:
        raise salt.exceptions.SaltInvocationError("'name' is required")

    if "content" not in record:
        raise salt.exceptions.SaltInvocationError(
            "Required field 'content' is missing for entry <{0}>".format(
                record.get("name", "unknown")
            )
        )

    if record.get("type") == "MX" and "priority" not in record:
        raise salt.exceptions.SaltInvocationError(
            "Required field 'priority' is missing for MX entry <{0}>".format(
                record["name"]
            )
        )


def record_from_dict(record):
    record.setdefault("type", "A")
    record.setdefault("proxied", False)
    record.setdefault("id", None)
    record.setdefault("ttl", 1)
    record.setdefault("salt_managed", True)

    priority = record["priority"] if record["type"] == "MX" else None

    return Record(
        record["id"],
        record["type"],
        record["name"],
        record["content"],
        priority,
        record["proxied"],
        record["ttl"],
        record["salt_managed"],
    )


class Zone(object):
    ACTION_ADD = "add"
    ACTION_REMOVE = "remove"
    ACTION_UPDATE = "update"

    SPECIAL_APPLY_ORDER = {ACTION_REMOVE: 0, ACTION_ADD: 1, ACTION_UPDATE: 2}
    REGULAR_APPLY_ORDER = {ACTION_ADD: 0, ACTION_UPDATE: 1, ACTION_REMOVE: 2}

    def __init__(self, name, zone):
        self.name = name
        self.zone = zone
        self.zone_id = zone["zone_id"]
        self.records = zone["records"]
        self.exclude = zone.get("exclude", [])

        if not zone.get("api_token") and not (
            zone.get("auth_email") and zone.get("auth_key")
        ):
            raise salt.exceptions.SaltInvocationError(
                "Either api_token or auth_email and auth_key must be provided"
            )

    def sanity_check(self):
        found = __salt__["cloudflare.get_zone"](self.zone)
        found_name = found["result"]["name"]

        if self.name != found_name:
            raise salt.exceptions.SaltInvocationError(
                "Zone name does not match: {0} != {1}".format(self.name, found_name)
            )

        a_records = set()
        cname_records = set()

        for record in self.desired():
            if not record.name.endswith("." + self.name) and record.name != self.name:
                raise salt.exceptions.SaltInvocationError(
                    "Record {0} does not belong to zone {1}".format(
                        record.name, self.name
                    )
                )

            if record.ttl != 1 and record.ttl < 120:
                raise salt.exceptions.SaltInvocationError(
                    "Record {0} has invalid TTL: {1}".format(record.name, record.ttl)
                )

            if record.ttl != 1 and record.proxied:
                raise salt.exceptions.SaltInvocationError(
                    "Record {0} has TTL set, but TTL for proxied records is managed by Cloudflare".format(
                        record.name
                    )
                )

            try:
                record.data()
            except Exception as err:
                raise salt.exceptions.SaltInvocationError(
                    "Record {0} cannot synthesize data from content: {1}".format(
                        str(record), err
                    )
                )

            if record.type in ("A", "AAAA"):
                a_records.add(record.name)
                if record.name in cname_records:
                    raise salt.exceptions.SaltInvocationError(
                        "Record {0} has both A/AAAA and CNAME records".format(
                            record.name
                        )
                    )

            if record.type == "CNAME":
                if record.name in cname_records:
                    raise salt.exceptions.SaltInvocationError(
                        "Record {0} has serveral CNAME records".format(record.name)
                    )
                cname_records.add(record.name)
                if record.name in a_records:
                    raise salt.exceptions.SaltInvocationError(
                        "Record {0} has both A/AAAA and CNAME records".format(
                            record.name
                        )
                    )

    def existing(self):
        records = {}
        found_records = __salt__["cloudflare.list_all_zone_records"](self.zone)

        for record_dict in found_records:
            record = record_from_dict(record_dict)
            excluded = False
            for pattern in self.exclude:
                if re.match(pattern, record.name):
                    excluded = True
                    break
            if not excluded:
                records[record_dict["id"]] = record

        return records.values()

    def desired(self):
        for record in self.records:
            validate_record(record)
        return map(lambda record: record_from_dict(record.copy()), self.records)

    def diff(self):
        existing_tuples = {
            (record.type, record.name, record.content, record.salt_managed): record
            for record in self.existing()
        }
        desired_tuples = {
            (record.type, record.name, record.content, record.salt_managed): record
            for record in self.desired()
        }
        desired_salt_managed = {
            record.name: record.salt_managed for record in self.desired()
        }

        changes = []

        for key in set(desired_tuples).difference(existing_tuples):
            if not desired_tuples[key].salt_managed:
                continue
            changes.append({"action": self.ACTION_ADD, "record": desired_tuples[key]})

        for key in set(existing_tuples).difference(desired_tuples):
            if key[1] in desired_salt_managed and desired_salt_managed[key[1]] is False:
                continue
            changes.append({"action": self.ACTION_REMOVE, "record": existing_tuples[key]})

        for key in set(existing_tuples).intersection(desired_tuples):
            if (
                existing_tuples[key].pure() == desired_tuples[key]
                or not desired_tuples[key].salt_managed
            ):
                continue

            changes.append(
                {
                    "action": self.ACTION_UPDATE,
                    "record": Record(
                        existing_tuples[key].id,
                        desired_tuples[key].type,
                        desired_tuples[key].name,
                        desired_tuples[key].content,
                        priority=desired_tuples[key].priority,
                        proxied=desired_tuples[key].proxied,
                        ttl=desired_tuples[key].ttl,
                        salt_managed=True,
                    ),
                }
            )

        return self._order(changes)

    def _order(self, diff):
        groups = {"primary": {}, "rest": {}}

        for op in diff:
            group = "primary" if op["record"].type in ("A", "AAAA", "CNAME") else "rest"
            if op["record"].name not in groups[group]:
                groups[group][op["record"].name] = []
            groups[group][op["record"].name].append(op)

        result = []

        def append_in_order(ops, order):
            for op in sorted(ops, key=lambda op: order[op["action"]]):
                result.append(op)

        for ops in groups["primary"].values():
            if any(op["record"].type == "CNAME" for op in ops):
                append_in_order(ops, self.SPECIAL_APPLY_ORDER)
            else:
                append_in_order(ops, self.REGULAR_APPLY_ORDER)

        for ops in groups["rest"].values():
            append_in_order(ops, self.REGULAR_APPLY_ORDER)

        return result

    def apply(self, diff):
        for op in diff:
            if op["action"] == self.ACTION_ADD:
                __salt__["cloudflare.add_dns_record"](self.zone, op["record"].json())
            elif op["action"] == self.ACTION_REMOVE:
                __salt__["cloudflare.remove_dns_record"](self.zone, op["record"].id)
            elif op["action"] == self.ACTION_UPDATE:
                __salt__["cloudflare.update_dns_record"](
                    self.zone,
                    op["record"].id,
                    op["record"].json(),
                )
            else:
                raise salt.exceptions.CommandExecutionError(
                    "Unknown action {0} for record {1}".format(
                        op["action"], str(op["record"])
                    )
                )
