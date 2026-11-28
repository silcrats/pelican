"""
The Access page: what one person can see in search.

Builds the same roles Frogmouth gives that person at sign-in, then asks
OpenSearch, per source, how many documents carry at least one of them and
which of those roles let them in. Frogmouth's own rule (see its
computeRoles and config.yaml security block):

    <role prefix><each default role>        e.g. Rguest
    <user prefix><username, lower-cased>    e.g. 1alice
    <group prefix><each group>              e.g. 2Finance

The prefixes and default roles here must match Frogmouth's security block
and Pelican's roles: block in config/pelican.yaml; the defaults match both.
"""

import os
from dataclasses import dataclass, field


def _env_list(name: str, default: str) -> list[str]:
    return [v.strip() for v in os.environ.get(name, default).split(",") if v.strip()]


@dataclass
class RoleRules:
    user_prefix: str = "1"
    group_prefix: str = "2"
    role_prefix: str = "R"
    default_roles: list[str] = field(default_factory=lambda: ["guest"])
    lowercase_username: bool = True

    @classmethod
    def from_env(cls) -> "RoleRules":
        return cls(os.environ.get("ROLE_PREFIX_USER", "1"), os.environ.get("ROLE_PREFIX_GROUP", "2"),
                   os.environ.get("ROLE_PREFIX_ROLE", "R"), _env_list("DEFAULT_ROLES", "guest"),
                   os.environ.get("ROLE_LOWERCASE_USERNAME", "true").lower() in ("1", "true", "yes"))

    def roles(self, username: str, groups: list[str]) -> list[dict]:
        """Each role with where it comes from, in Frogmouth's order."""
        user = username.lower() if self.lowercase_username else username
        out = [{"role": f"{self.role_prefix}{r}", "from": "default", "name": r} for r in self.default_roles]
        out.append({"role": f"{self.user_prefix}{user}", "from": "user", "name": user})
        out += [{"role": f"{self.group_prefix}{g}", "from": "group", "name": g} for g in groups]
        seen, unique = set(), []
        for r in out:
            if r["role"] not in seen:
                seen.add(r["role"])
                unique.append(r)
        return unique


def visible_counts(os_search, index: str, roles: list[str]) -> dict:
    """{(share, host): {"total": n, "visible": n, "by_role": {role: n}}} over
    the whole index, from two aggregations. os_search(path, body) returns
    OpenSearch's parsed reply."""
    def by_source(query, with_roles):
        sub = {"host": {"terms": {"field": "host", "size": 10}}}
        if with_roles:
            # How many of the source's documents each of the person's roles opens.
            sub["host"]["aggs"] = {"granted": {"terms": {"field": "role", "include": roles,
                                                         "size": max(len(roles), 1)}}}
        body = {"size": 0, "track_total_hits": False, "query": query,
                "aggs": {"by_share": {"terms": {"field": "share", "size": 1000}, "aggs": sub}}}
        return os_search(f"/{index}/_search", body)["aggregations"]["by_share"]["buckets"]

    out: dict = {}
    for b in by_source({"match_all": {}}, False):
        for hb in b["host"]["buckets"]:
            out[(b["key"], hb["key"])] = {"total": hb["doc_count"], "visible": 0, "by_role": {}}
    if roles:
        for b in by_source({"bool": {"filter": [{"terms": {"role": roles}}]}}, True):
            for hb in b["host"]["buckets"]:
                row = out.setdefault((b["key"], hb["key"]), {"total": hb["doc_count"], "visible": 0, "by_role": {}})
                row["visible"] = hb["doc_count"]
                row["by_role"] = {g["key"]: g["doc_count"] for g in hb["granted"]["buckets"]}
    return out
