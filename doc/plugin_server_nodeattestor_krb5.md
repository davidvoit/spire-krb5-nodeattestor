# Server plugin: NodeAttestor "krb5"

*Must be used in conjunction with the [agent-side krb5 plugin](plugin_agent_nodeattestor_krb5.md)*

The `krb5` plugin attests nodes by performing a Kerberos GSSAPI/SSPI exchange. The server acts as a GSS Initiator
and targets a service principal based on the agent's hostname (`HOST@<hostname>`).
The trust algorithm works as follows: The agent sends it's fqdn to us, we establish a krb5 context, as mentioned above.
We create a Nonce and wrap it using the krb5 HOST@agenthostname kerberos session keys.
If the agent can unwrap and re-wrap it using the established GSS context, we know the agent is really the hostname it said it is.

The SPIFFE ID produced by the plugin is based on the hostname provided by the agent. The SPIFFE ID has the form:

```xml
spiffe://<trust_domain>/spire/agent/krb5/<hostname>
```

| Configuration | Description                                                   | Default |
| ------------- |---------------------------------------------------------------| ------- |
| `keytab_path` | Optional path to a Kerberos keytab file. (ignored on windows) | |

*Note: The krb5 plugin requires credentials for the server to initiate the Kerberos exchange. Only a valid principal to establish the GSS context is needed; it does not require any specific roles or permissions or SPNs.*

A sample configuration:

```hcl
    NodeAttestor "krb5" {
        plugin_data {
            keytab_path = "/etc/spire/server.keytab"
        }
    }
```

## Selectors

| Selector | Example | Description |
| -------- | ------- | ----------- |
| Hostname | `krb5:hostname:host.example.org` | The verified hostname of the agent. |
