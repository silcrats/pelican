"""
Sign-in against Active Directory (or any LDAP directory): bind as the user,
then read their own group memberships over that same connection, so no
service account is needed. The same approach as Frogmouth's sign-in,
including AD's primary group, which memberOf never lists.

The Access page reads someone else's groups, so it needs a directory
account of its own (LDAP_LOOKUP_USER / LDAP_LOOKUP_PASSWORD): any ordinary
domain account can read group memberships. Without one the page says so.
"""

import re
import ssl
import struct

import ldap3
from ldap3.core.exceptions import LDAPBindError, LDAPException, LDAPInvalidCredentialsResult

# A wrong password: ldap3 raises the second with raise_exceptions=True.
_REFUSED = (LDAPBindError, LDAPInvalidCredentialsResult)
from ldap3.utils.conv import escape_filter_chars


class SignInFailed(Exception):
    pass


class LookupFailed(Exception):
    pass


# AD's "matching rule in chain": every group the account is in, through
# nested groups too. Frogmouth only counts direct ones (memberOf) and the
# primary group, so the rest are shown as not counted.
_IN_CHAIN = "1.2.840.113556.1.4.1941"
_ACCOUNTDISABLE = 0x2


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
                 start_tls: bool = False, ca_file: str = "", timeout: int = 5,
                 lookup_user: str = "", lookup_password: str = ""):
        self.url = url
        self.lookup_user = lookup_user
        self.lookup_password = lookup_password
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

    def _bind_dn(self, username: str) -> str:
        return self.bind_template.replace("{username}", username)

    def _connect(self, bind_dn: str, password: str):
        """An open, bound connection. Raises LDAPBindError for a wrong
        password and LDAPException when the directory can't be reached."""
        conn = ldap3.Connection(self.server, user=bind_dn, password=password, receive_timeout=self.timeout,
                                raise_exceptions=True, auto_bind=ldap3.AUTO_BIND_NONE)
        conn.open()
        if self.start_tls:
            conn.start_tls()
        conn.bind()
        return conn

    @staticmethod
    def _valid_name(username: str) -> bool:
        return bool(username) and len(username) <= 256 and not re.search(r"[\x00-\x1f]", username)

    def _read_account(self, conn, username: str, extra=()):
        conn.search(self.base_dn, f"({self.username_attr}={escape_filter_chars(username)})",
                    attributes=["memberOf", "displayName", "primaryGroupID", "objectSid", self.username_attr, *extra])
        if not conn.entries:
            return None, None, None
        entry = conn.entries[0]
        attrs = entry.entry_attributes_as_dict
        groups = [cn_from_dn(dn) for dn in attrs.get("memberOf", [])]
        primary = self._primary_group(conn, entry)
        if primary and primary not in groups:
            groups.append(primary)
        return entry, attrs, groups

    def authenticate(self, username: str, password: str) -> tuple[str, list[str], str]:
        """(username, group CNs, display name), or SignInFailed."""
        if not self._valid_name(username) or not password:
            raise SignInFailed("invalid credentials")
        try:
            conn = self._connect(self._bind_dn(username), password)
        except _REFUSED:
            raise SignInFailed("invalid credentials")
        except LDAPException as exc:
            raise SignInFailed(f"directory unavailable: {exc}")
        try:
            entry, attrs, groups = self._read_account(conn, username)
            if entry is None:
                raise SignInFailed("account not found under the base DN")
            display = (attrs.get("displayName") or [username])[0] or username
            return username, groups, str(display)
        except LDAPException as exc:
            raise SignInFailed(f"directory lookup failed: {exc}")
        finally:
            try:
                conn.unbind()
            except LDAPException:
                pass

    def can_look_up(self) -> bool:
        return bool(self.lookup_user and self.lookup_password)

    def lookup(self, username: str) -> dict | None:
        """Someone else's account, read with the lookup account: the groups
        Frogmouth would give them at sign-in (memberOf plus the primary
        group), the nested groups it wouldn't, and whether the account is
        disabled. None if there's no such account. LookupFailed if the
        directory can't be asked."""
        if not self.can_look_up():
            raise LookupFailed("no lookup account is set (LDAP_LOOKUP_USER, LDAP_LOOKUP_PASSWORD)")
        if not self._valid_name(username):
            return None
        bind_dn = self.lookup_user if re.search(r"[=@\\]", self.lookup_user) else self._bind_dn(self.lookup_user)
        try:
            conn = self._connect(bind_dn, self.lookup_password)
        except _REFUSED:
            raise LookupFailed("the lookup account's sign-in was refused")
        except LDAPException as exc:
            raise LookupFailed(f"directory unavailable: {exc}")
        try:
            entry, attrs, groups = self._read_account(conn, username, extra=("userAccountControl",))
            if entry is None:
                return None
            name = str((attrs.get(self.username_attr) or [username])[0] or username)
            uac = attrs.get("userAccountControl") or [0]
            try:
                disabled = bool(int(uac[0]) & _ACCOUNTDISABLE)
            except (TypeError, ValueError):
                disabled = False
            return {
                "username": name,
                "display_name": str((attrs.get("displayName") or [name])[0] or name),
                "groups": groups,
                "nested_groups": self._nested_groups(conn, entry.entry_dn, groups),
                "disabled": disabled,
            }
        except LDAPException as exc:
            raise LookupFailed(f"directory lookup failed: {exc}")
        finally:
            try:
                conn.unbind()
            except LDAPException:
                pass

    def _nested_groups(self, conn, user_dn: str, direct: list[str]) -> list[str] | None:
        """Groups reached only through other groups, or None where the
        directory can't say (not AD)."""
        try:
            conn.search(self.base_dn, f"(member:{_IN_CHAIN}:={escape_filter_chars(user_dn)})", attributes=["cn"])
            all_groups = {str(e["cn"].value) for e in conn.entries if "cn" in e.entry_attributes}
        except LDAPException as exc:
            print(f"LDAP: nested group lookup failed: {exc}")
            return None
        known = {g.lower() for g in direct}
        return sorted((g for g in all_groups if g.lower() not in known), key=str.lower)

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
