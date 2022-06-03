# X509 Metrics

This script pings a server and asks for the certificate or allows the certificate to be passed in on the command line.
It then reports some expiration data in json form.  Useful for monitoring certificate expiration and when a certificate
needs to be rotated.

## Inputs

| Name     | Value                                                                                                   |
|----------|---------------------------------------------------------------------------------------------------------|
| Stdin    | A certificate is expected to follow and the other options are ignored                                   |
| b64      | A base64 encoded certificate is expected to follow and the other options are ignored                    |
| Host     | The Host of the server that is to be inspected.                                                         |
| Port     | The Port of the server that is to be inspected. Default is `443`.                                       |
| Protocol | The protocol to use to connect to the server.  Valid options are `tcp` or `postgres`. Default is `tcp`. |

## Output

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://jmoney.dev/x509-metrics/x509metrics.schema.json",
  "title": "X509Metrics",
  "description": "Certificate expiration metrics of a x509 certificate.",
  "type": "object",
  "properties": {
    "error": {
      "description": "Error message is gathering metrics failed with the reason why",
      "type": "string"
    },
    "tags": {
      "description": "Metadata about the certificate.",
      "type": "array",
      "items": {
        "type": "string"
      }
    },
    "x509": {
      "description": "Metric data is hosted under.",
      "type": "object",
      "properties": {
        "days_left": {
          "description": "The number of days left until this certificate expires.",
          "type": "number"
        },
        "issued_days": {
          "description": "The number of days this certificate has been issued for.",
          "type": "number"
        },
        "issued_seconds": {
          "description": "The number of seconds this certificate has been issued for.",
          "type": "number"
        },
        "seconds_left": {
          "description": "The number of seconds left until this certificate expires.",
          "type": "number"
        }
      },
      "required": [ "days_left", "issued_days", "issued_seconds", "seconds_left" ]
    }
  }
}
```

## Help

```bash
x509-metrics -host example.com
```