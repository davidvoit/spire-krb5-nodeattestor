# Agent plugin: NodeAttestor "krb5"

*Must be used in conjunction with the [server-side krb5 plugin](plugin_server_nodeattestor_krb5.md)*

The `krb5` plugin provides attestation data for a node by performing a Kerberos GSSAPI/SSPI exchange.
As the agent is an KRB5 acceptor, it needs access to HOST@<hostname> SPN.
For unix based system this means it must have access to /etc/krb5.keytab.
For Windows based systems it must be running as a service with LocalService Account permissions,
Administrator rights alone are **not** enough!

The SPIFFE ID produced by the [server-side `krb5` plugin](plugin_server_nodeattestor_krb5.md) is based on the hostname provided by the agent. The SPIFFE ID has the form:

```xml
spiffe://<trust_domain>/spire/agent/krb5/<hostname>
```

This plugin does not require any configuration.
