# -*- coding: utf-8 -*-
# Copyright 2022 Johannes H.
# Modifications 2024 IRT Jules Verne
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import ssl
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

import ldap3
import ldap3.core.exceptions
import synapse
from pkg_resources import parse_version
from synapse.api.errors import SynapseError, ShadowBanError
from synapse.module_api import ModuleApi
from synapse.types import RoomAlias
from twisted.internet import threads

__version__ = "0.0.3"

logger = logging.getLogger(__name__)

@dataclass
class _Config:
    enabled: bool
    uri: Union[str, List[str]]
    start_tls: bool
    bind_dn: str
    bind_password: str
    inviter: str
    room_mapping: Dict[str, Dict[str, Any]]
    base: str

class LdapRules:
    _ldap_tls = ldap3.Tls(validate=ssl.CERT_NONE)

    def __init__(self, config: _Config, api: ModuleApi):
        self.api_handler = api
        synapse_min_version = "1.46.0" # Introduces ModuleApi.update_room_membership

        if parse_version(synapse.__version__) < parse_version(synapse_min_version):
            raise Exception(f"Running Synapse version {synapse.__version__}, {synapse_min_version} required.")

        self.ldap_uris = [config.uri] if isinstance(config.uri, str) else config.uri
        self.ldap_start_tls = config.start_tls
        self.ldap_bind_dn = config.bind_dn
        self.ldap_bind_password = config.bind_password
        self.ldap_base = config.base
        self.inviter = config.inviter
        self.room_mapping = config.room_mapping

        # Ensure 'invite' key is present in room mappings, making invite key optional
        for group, mapping in self.room_mapping.items():
            # TODO: Check this per room, not per group?
            mapping.setdefault("invite", False)

        # Module callback for Synapse
        api.register_account_validity_callbacks(on_user_login=self.on_register)

    @staticmethod
    def parse_config(config) -> _Config:
        # verify config sanity
        _require_keys(config, ["uri", "bind_dn", "bind_password", "base", "inviter", "room_mapping"])
        return _Config(
            enabled=config.get("enabled", False),
            uri=config["uri"],
            start_tls=config.get("start_tls", False),
            bind_dn=config["bind_dn"],
            bind_password=config["bind_password"],
            base=config["base"],
            inviter=config["inviter"],
            room_mapping=config["room_mapping"],
        )

    def _get_server(self, get_info: Optional[str] = None) -> ldap3.ServerPool:
        """Constructs ServerPool from configured LDAP URIs

        Args:
            get_info: specifies if the server schema and server
            specific info must be read. Defaults to None.

        Returns:
            Servers grouped in a ServerPool
        """
        return ldap3.ServerPool([ldap3.Server(uri, get_info=get_info, tls=self._ldap_tls) for uri in self.ldap_uris])

    async def _ldap_simple_bind(self, server: ldap3.ServerPool, bind_dn: str, password: str) -> Tuple[bool, Optional[ldap3.Connection]]:
        """Attempt a simple bind with the credentials given against
        the LDAP server.

        Returns True, LDAP3Connection
            if the bind was successful
        Returns False, None
            if an error occured
        """

        try:
            conn = await threads.deferToThread(ldap3.Connection, server, bind_dn, password, authentication=ldap3.SIMPLE, read_only=True)
            logger.debug("Established LDAP connection in simple bind mode: %s", conn)

            if self.ldap_start_tls:
                await threads.deferToThread(conn.open)
                await threads.deferToThread(conn.start_tls)
                logger.debug("Upgraded LDAP connection in simple bind mode through StartTLS: %s", conn)

            if await threads.deferToThread(conn.bind):
                logger.debug("LDAP Bind successful in simple bind mode.")
                return True, conn

            logger.info("Binding against LDAP failed for '%s': %s", bind_dn, conn.result["description"])
            await threads.deferToThread(conn.unbind)
            return False, None

        except ldap3.core.exceptions.LDAPException as e:
            logger.warning("Error during LDAP authentication: %s", e)
            return False, None

    async def _check_membership(self, conn: ldap3.Connection, username: str, ldap_group: str, ldap_filter: str) -> bool:
        """Checks whether a group contains a user. This could technically be
        any property of the group. We provide group properties that resolve to
        users, because OpenLDAP does not support LDAP_MATCHING_RULE_IN_CHAIN.
        You will most likely have to modify this for your installation.

        Args:
            username: The users login.
            ldap_group: LDAP group to check for username.
            ldap_base: LDAP base of group

        Returns True
            if username was found in group
        Returns False
            if username was not found in group or bind failed
        """

        query = ldap_filter.format(username=username, group=ldap_group)

        await threads.deferToThread(conn.search, search_base=self.ldap_base, search_filter=query)
        responses = [response for response in conn.response if response["type"] == "searchResEntry"]

        return len(responses) == 1

    async def _join_to_room(self, sender: str, target: str, roomid: str, invite: Optional[bool] = False) -> bool:
        """Tries to force-join a user into a room.

        Args:
            sender: Inviters mxid, must be local
            target: Invitees mxid, must be local
            roomid: The roomid to join
            invite: If True, only invite

        Returns True
            if join or invite was successful
        Returns False
            if join or invite failed
        """

        try:
            await self.api_handler.update_room_membership(sender, target, roomid, "invite")
            if not invite:
                await self.api_handler.update_room_membership(target, target, roomid, "join")
            logger.info("Joined user '%s' into room '%s'", target, roomid)
            return True
        except (RuntimeError, ShadowBanError, SynapseError) as e:
            logger.exception("Error occurred when trying to join '%s' into '%s': %s", target, roomid, e)
            return False

    async def _check_room_exist(self, room_name: str) -> Optional[str]:
        """Check if a room exists using the alias."""
        try:
            if "!" not in room_name:
                room_alias_obj = RoomAlias(room_name, self.api_handler.server_name)
                room_id = await self.api_handler.lookup_room_alias(room_alias_obj.to_string())
                if room_id:
                    logger.info("Found room '%s'", room_name)
                    return room_id[0]
            else:
                raise Exception(f"Invalid room alias: '{room_name}'")
        except SynapseError:
            logger.info("Room '%s' not found, we must create it", room_name)
            return None
        except Exception as e:
            logger.exception("Failed to check room '%s': '%s'", room_name, e)
            return None

    async def _create_the_room(self, room_name: str) -> Optional[str]:
        """Create a room using the alias."""
        room_creation_params = {
            "preset": "private_chat",
            "room_alias_name": room_name,
            "name": room_name,
            "visibility": "private"
        }
        try:
            room_id = await self.api_handler.create_room(self.inviter, room_creation_params)
            logger.info("Room '%s' created successfully: %s", room_name, room_id[0])
            return room_id[0]
        except Exception as e:
            logger.exception("Failed to create room '%s': %s", room_name, e)
            return None

    async def on_register(self, username: str, auth_provider_type: str, auth_provider_id: str):
        # username from callback will be fully qualified        
        localpart = username.split(":", 1)[0][1:]
        logger.debug("'%s' just got registered, localpart '%s'", username, localpart)

        server = self._get_server()
        result, conn = await self._ldap_simple_bind(server, self.ldap_bind_dn, self.ldap_bind_password)

        if not result:
            logger.warning("LDAP bind failed for user '%s'", username)
            return

        for group, mapping in self.room_mapping.items():
            invite = mapping["invite"]
            filter = mapping["filter"]
            room_names = mapping["room_names"]
            # Check whether user is in group ...
            if await self._check_membership(conn, localpart, group, filter):
                # ... on success we can iterate through rooms to join                
                for room_name in room_names:
                    room_id = await self._check_room_exist(room_name)
                    if room_id is None:
                        room_id = await self._create_the_room(room_name)
                    if room_id:
                        await self._join_to_room(self.inviter, username, room_id, invite)

        await threads.deferToThread(conn.unbind)

def _require_keys(config: Dict[str, Any], required: Iterable[str]) -> None:
    missing = [key for key in required if key not in config]
    if missing:
        raise Exception("Module enabled but missing required config values: {}".format(", ".join(missing)))
