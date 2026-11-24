"""
Sign-in against Active Directory (or any LDAP directory): bind as the user,
then read their own group memberships over that same connection, so no
service account is needed. The same approach as Frogmouth's sign-in,
including AD's primary group, which memberOf never lists.
"""

import re
import ssl
import struct

import ldap3
from ldap3.core.exceptions import LDAPBindError, LDAPException
from ldap3.utils.conv import escape_filter_chars


class SignInFailed(Exception):
    pass


def cn_from_dn(dn: str) -> str:
    """'CN=Domain Admins,CN=Users,DC=...' -> 'Domain Admins'."""
    match = re.match(r"CN=((?:\\,|[^,])+)", dn or "", re.IGNORECASE)
    return match.group(1).replace("\\,", ",") if match else dn


def primary_group_sid(user_sid: bytes, rid: int) -> str | None:
    """The SID of an AD user's primary group: the user's own SID with its
    last sub-authority replaced by primaryGroupID, as S-1-5-21-...-513."""
    if not isinstance(user_sid, (bytes, bytearray)) or len(user_sid) < 8:
        return None
    count = user_sid[1]
    if count < 1 or len(user_sid) != 8 + 4 * count:
        return None
    authority = int.from_bytes(user_sid[2:8], "big")
    subs = list(struct.unpack(f"<{count}I", user_sid[8:]))[:-1]
    return f"S-{user_sid[0]}-{authority}-" + "-".join(str(s) for s in [*subs, rid])


class LdapAuth:
    def __init__(self, url: str, bind_template: str, base_dn: str, username_attr: str = "sAMAccountName",
                 start_tls: bool = False, ca_file: str = "", timeout: int = 5):
        self.url = url
        self.bind_template = bind_template
        self.base_dn = base_dn
        self.username_attr = username_attr
        self.start_tls = start_tls
        self.timeout = timeout
        tls = None
        if url.lower().startswith("ldaps://") or start_tls:
            tls = ldap3.Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=ca_file or None)
        self.server = ldap3.Server(url, tls=tls, connect_timeout=timeout, get_info=ldap3.NONE)

    def describe(self) -> str:
        return f"LDAP at {self.url}"

    def authenticate(self, username: str, password: str) -> tuple[str, list[str], str]:
        """(username, group CNs, display name), or SignInFailed."""
        if not username or not password or len(username) > 256 or re.search(r"[\x00-\x1f]", username):
            raise SignInFailed("invalid credentials")
        bind_dn = self.bind_template.replace("{username}", username)
        conn = ldap3.Connection(self.server, user=bind_dn, password=password, receive_timeout=self.timeout,
                                raise_exceptions=True, auto_bind=ldap3.AUTO_BIND_NONE)
        try:
            conn.open()
            if self.start_tls:
                conn.start_tls()
            conn.bind()
        except LDAPBindError:
            raise SignInFailed("invalid credentials")
        except LDAPException as exc:
            raise SignInFailed(f"directory unavailable: {exc}")
        try:
            conn.search(self.base_dn, f"({self.username_attr}={escape_filter_chars(username)})",
                        attributes=["memberOf", "displayName", "primaryGroupID", "objectSid", self.username_attr])
            if not conn.entries:
                raise SignInFailed("account not found under the base DN")
            entry = conn.entries[0]
            attrs = entry.entry_attributes_as_dict
            groups = [cn_from_dn(dn) for dn in attrs.get("memberOf", [])]
            primary = self._primary_group(conn, entry)
            if primary and primary not in groups:
                groups.append(primary)
            display = (attrs.get("displayName") or [username])[0] or username
            return username, groups, str(display)
        except LDAPException as exc:
            raise SignInFailed(f"directory lookup failed: {exc}")
        finally:
            try:
                conn.unbind()
            except LDAPException:
                pass

    def _primary_group(self, conn, entry) -> str | None:
        """A failure only leaves the group out, never adds one."""
        try:
            rid = int((entry.entry_attributes_as_dict.get("primaryGroupID") or [0])[0])
            raw = entry["objectSid"].raw_values[0] if "objectSid" in entry.entry_attributes else None
            sid = rid and raw and primary_group_sid(raw, rid)
            if not sid:
                return None
            conn.search(self.base_dn, f"(objectSid={sid})", attributes=["cn"])
            if conn.entries:
                return str(conn.entries[0]["cn"].value)
        except (LDAPException, ValueError, KeyError, IndexError) as exc:
            print(f"LDAP: primary group lookup failed: {exc}")
        return None
