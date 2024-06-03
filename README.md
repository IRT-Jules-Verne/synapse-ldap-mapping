# Synapse Ldap Mapping

**You will most likely have to rework the LDAP queries to fit your environment. See Configuration section below.**

Synapse module for various rules depending on LDAP attributes. Currently only for joining rooms based on group membership on registration.

This is intended to be used with an auth module which uses the same LDAP backend as this module, but will work just as well with any other registration method that triggers Synapses `on_user_registration` callback.
Note that if you allow normal registration alongside this, normal registration users with names found in LDAP will be matched too.

The module should be easily extendable to provide [matrix-corporal](https://github.com/devture/matrix-corporal) with policies.

## Installation
**This module requires at least Synapse 1.46.0.**
Install the module somewhere your Synapse can find it. For the Debian package you will probably want this:
```bash
source /opt/venvs/matrix-synapse/bin/activate
pip install git+https://github.com/subjugum/matrix-synapse-ldap-rules.git
deactivate
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
        big-boss:
          filters: "(&(objectClass=user)(sAMAccountName={username})(memberof=CN={group},OU=biggroup,{base}"
          roomids:
            - "!HQXHtWbrXbkldqluli:example.com"
        admin:
          base: "ou=local,ou=groups,dc=example,dc=com"
          invite: true
          roomids:
            - "!tniBCoYJDryqxNzudS:example.com"
        ancient-group:
          base: "ou=ads-old,ou=groups,dc=example,dc=com"
          roomids:
            - "!MShKAzDGwDFdyApLIR:example.com"
            - "!ApLIRzDGMShKAywDFd:example.com"
```

## Credits

Originaly from https://git.uni-jena.de/ko27per/synapse-ldap-rules

I borrowed code and/or took inspiration from:

https://github.com/almightybob/matrix-synapse-rest-password-provider

https://github.com/matrix-org/matrix-synapse-ldap3/tree/rei/sma_wrapper

