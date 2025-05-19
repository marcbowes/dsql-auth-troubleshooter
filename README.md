# DSQL auth troubleshooter

This utility will walk you through diagnosing authentication and authorization
issues to your DSQL cluster.

To install from source:

``` sh
cargo install --git https://github.com/marcbowes/dsql-auth-troubleshooter.git --branch main
```

Usage:

``` sh
dsql-auth-troubleshooter \
    --cluster-endpoint $YOUR_CLUSTER_ID.dsql.$AWS_REGION.on.aws \
    --user $YOUR_POSTGRES_USER \
    --region $AWS_REGION
```

This tool initializes the AWS SDK with defaults. This means you can provide
credentials or configuration (like the region) via the standard AWS SDK
environment variables or ~/.aws/config.

If the tool's configuration does not match what you expect, check your
environment:

``` sh
env | grep AWS_
```

Otherwise, check your config:

``` sh
less ~/.aws/config
```
