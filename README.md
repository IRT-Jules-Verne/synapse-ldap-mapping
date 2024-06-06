# Synapse Ldap Mapping

**You will most likely have to rework the LDAP queries to fit your environment. See Configuration section below.**

Synapse module for various rules depending on LDAP attributes. Currently only for joining rooms based on group membership on registration.

This is intended to be used with an auth module which uses the same LDAP backend as this module, but will work just as well with any other registration method that triggers Synapses `on_user_registration` callback.
Note that if you allow normal registration alongside this, normal registration users with names found in LDAP/OpenID will be matched too.

The module should be easily extendable to provide [matrix-corporal](https://github.com/devture/matrix-corporal) with policies.

## Installation

### Manual
**This module requires at least Synapse 1.46.0.**
Install the module somewhere your Synapse can find it. For the Debian package you will probably want this:
```bash
source /opt/venvs/matrix-synapse/bin/activate
pip install git+https://github.com/IRT-Jules-Verne/synapse-ldap-mapping.git
deactivate
```

### Matrix-Docker

You can install/configure this using https://github.com/spantaleev/matrix-docker-ansible-deploy by dropping the subdirectory `synapse-ldap-mapping` inside `matrix-docker-ansible-deploy/roles/custom/matrix-synapse/tasks/ext/`.

Add at the end of `matrix-docker-ansible-deploy/roles/custom/matrix-synapse/tasks/ext/setup_install.yml`:

```
# synapse-ldap-mapping
- tags:
    - setup-all
    - setup-synapse
    - install-all
    - install-synapse
  block:
    - when: matrix_synapse_ext_synapse_ldap_mapping_enabled | bool
      ansible.builtin.include_tasks: "{{ role_path }}/tasks/ext/synapse-ldap-mapping/setup_install.yml"
```
and at the end of `matrix-docker-ansible-deploy/roles/custom/matrix-synapse/tasks/ext/setup_uninstall.yml`:

```
# synapse-ldap-mapping
- tags:
    - setup-all
    - setup-synapse
  block:
    - when: not matrix_synapse_ext_synapse_ldap_mapping_enabled | bool
      ansible.builtin.include_tasks: "{{ role_path }}/tasks/ext/synapse-ldap-mapping/setup_uninstall.yml"
```


You can now configure this module inside the vars.yml of matrix-docker-ansible-deploy file with: 

```
matrix_synapse_ext_synapse_ldap_mapping_enabled: true
matrix_synapse_ext_synapse_ldap_mapping_download_uri: "https://raw.githubusercontent.com/IRT-Jules-Verne/synapse-ldap-mapping/master/ldap_rules.py"
matrix_synapse_ext_synapse_ldap_mapping_uri: [ "ldap://X.X.X.X:389" ]
matrix_synapse_ext_synapse_ldap_mapping_start_tls: false
matrix_synapse_ext_synapse_ldap_mapping_bind_dn: "CN=my_bind,OU=sync,DC=example,DC=com"
matrix_synapse_ext_synapse_ldap_mapping_bind_password: "SuperPassword"
matrix_synapse_ext_synapse_ldap_mapping_base: "DC=example,DC=com"
matrix_synapse_ext_synapse_ldap_mapping_inviter: "@inviter:example.com"
matrix_synapse_ext_synapse_ldap_mapping_room_mapping: "{{ matrix_synapse_ext_synapse_ldap_mapping_room_mapping_yaml | from_yaml }}"
matrix_synapse_ext_synapse_ldap_mapping_room_mapping_yaml: |
    room_mapping:
      my_group:
        filter: (&(objectClass=user)(sAMAccountName={username})(memberof=CN={group},{base}))
        room_names:
        - my_room

```



## Configuration
`config.inviter` will try to join the newly registered user into the room by default.
If you only want to have the user invited instead, set `config.room_mapping.<group>.invite: true`.
Both inviter and invite settings might be changed to be configurable per room, instead of per group in the future.

`config.inviter` **must** be based on your homeserver and be able to invite people into the configured room.

`config.base` is the LDAP base.

If the query yields one result, the user is considered to be in the group.
The default would be the equivalent of `ldapsearch -b "<config.base>" "(room_mapping.<group>.filters)"`
You will likely have to change this for your setup. See `_check_membership` in source for specifics.


```yaml
modules:
  - module: "ldap_rules.LdapRules"
    config:
      uri:
        - "ldaps://ldap.example.com:636"
      start_tls: false
      bind_dn: "uid=matrix,ou=local,dc=example,dc=com"
      bind_password: "bind_pw"
      base: "DC=example,DC=com"
      inviter: "@admin:example.com"
      room_mapping:
        bigboss:
          filter: "(&(objectClass=user)(sAMAccountName={username})(memberof=CN={group},OU=biggroup,{base}"
          room_names:
            - "BossRoom"
        engineer:
          filter: "(&(sAMAccountName={username})(memberof=CN={group},OU=biggroup,{base})"
          invite: true
          room_names:
            - "Robotic"
            - "Solar"
        ancientgroup:
          filter: "(&(sAMAccountName={username})(memberof=CN={group},{base})"
          room_names:
            - "Retired"
```

## Credits

Originaly from https://git.uni-jena.de/ko27per/synapse-ldap-rules

Borrowed code and/or took inspiration from:

https://github.com/almightybob/matrix-synapse-rest-password-provider

https://github.com/matrix-org/matrix-synapse-ldap3/tree/rei/sma_wrapper

