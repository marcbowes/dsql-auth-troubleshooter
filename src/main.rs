use std::time::SystemTime;

use ansi_term::{Colour::*, Style};
use anyhow::{Context, Result};
use aws_config::Region;
use aws_sdk_dsql::auth_token::{self, AuthTokenGenerator};
use aws_sdk_iam::operation::simulate_principal_policy::SimulatePrincipalPolicyOutput;
use aws_sdk_sts::Client as StsClient;
use aws_sdk_sts::{config::ProvideCredentials, error::BoxError};
use aws_types::SdkConfig;
use chrono::{DateTime, Utc};
use clap::Parser;
use dsql_auth_troubleshooter::{AwsIdentity, ClusterEndpoint};
use native_tls::TlsConnector;
use postgres_native_tls::MakeTlsConnector;

/// A utility for troubleshooting authentication and authorization issues with
/// DSQL clusters
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The DSQL cluster endpoint URL.
    #[arg(long)]
    cluster_endpoint: String,

    /// AWS region where the DSQL cluster is located. If left blank, the AWS SDK
    /// will pick a default region based off your environment or AWS profile.
    #[arg(long, env = "AWS_REGION")]
    region: Option<String>,

    /// AWS profile to use. If left blank, the AWS SDK will pick a default
    /// profile. Profiles affect which credentials are used, as well as what the
    /// default region is.
    #[arg(long, env = "AWS_PROFILE")]
    profile: Option<String>,

    /// Postgres user (role)
    #[arg(long)]
    user: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let cluster_endpoint = ClusterEndpoint::try_from(&args.cluster_endpoint[..])
        .map_err(|err| anyhow::anyhow!("Unable to parse endpoint: {err}"))?;
    let sdk_config = load_sdk_config(&args).await;
    let Some(aws_region) = sdk_config.region() else {
        println!("Unable to determine AWS region. Please configure one by:");
        println!("    - Passing in the region with --region");
        println!("    - Exporting $AWS_REGION");
        anyhow::bail!("SDK region not configured")
    };
    if aws_region.as_ref() != cluster_endpoint.aws_region {
        anyhow::bail!(
            "The endpoint of the cluster is in AWS region {}, but the SDK was configured to use {aws_region}.",
            cluster_endpoint.aws_region
        );
    }

    println!("\n1. Checking connectivity to DSQL cluster...");
    match test_cluster_connectivity(&sdk_config, &args).await {
        Ok(_) => {
            println!(
                "{}",
                Green
                    .bold()
                    .paint("\u{2713} Successfully connected to the cluster endpoint")
            );

            return Ok(());
        }
        Err(err) => {
            println!(
                "{}",
                Red.bold().paint(format!(
                    "\u{2717} Failed to connect to the cluster endpoint: {err}"
                ))
            );
            println!("   Possible solutions:");
            println!("   - Check if the cluster endpoint is correct");
            println!("   - Verify your network connectivity");
            println!("   - Ensure your VPC security groups allow connections from your IP");
            println!("   - Ensure your Postgres user (role) is correct");
            println!(
                "   - Ensure your Postgres user (role) has permission to connect (see `AWS IAM GRANT` in the DSQL documentation)"
            );
        }
    }

    println!("\n2. Checking AWS credentials...");
    match validate_aws_creds_locally(&sdk_config).await {
        Ok(()) => {
            println!(
                "{}",
                Green
                    .bold()
                    .paint("\u{2713} AWS credentials loaded successfully")
            );
        }
        Err(err) => {
            println!(
                "{}",
                Red.bold()
                    .paint(format!("\u{2717} AWS credentials check failed: {err}"))
            );
            println!("   Possible solutions:");
            println!("   - Check if your AWS credentials are correctly configured");
            if let Some(p) = &args.profile {
                println!("   - Verify that the AWS profile '{p}' exists",);
            }
            println!("   - Ensure your credentials have not expired");
            return Err(err);
        }
    }

    println!("\n3. Testing AWS credentials...");
    let identity = match test_aws_credentials(&sdk_config).await {
        Ok(identity) => {
            println!(
                "{}",
                Green
                    .bold()
                    .paint("\u{2713} AWS credentials verified successfully")
            );
            println!("   Account ID: {}", identity.account_id);
            println!("   ARN:        {}", identity.arn);
            println!("   User ID:    {}", identity.user_id);
            identity
        }
        Err(err) => {
            println!(
                "{}",
                Red.bold()
                    .paint(format!("\u{2717} AWS credentials check failed: {err}"))
            );
            println!("   Possible solutions:");
            println!("   - Check if your AWS credentials are correctly configured");
            if let Some(p) = &args.profile {
                println!("   - Verify that the AWS profile '{p}' exists",);
            }
            println!("   - Ensure your credentials have not expired");
            return Err(err);
        }
    };

    println!("\n4. Checking policy...");
    let (is_admin, sim) = match do_policy_sim(
        &sdk_config,
        &cluster_endpoint.cluster_arn(&identity)?,
        &args.user,
        &identity,
    )
    .await
    {
        Ok(it) => it,
        Err(err) => {
            println!(
                "{}",
                Red.bold()
                    .paint(format!("\u{2717} AWS policy simulation failed: {err}"))
            );
            println!("   Possible solutions:");
            println!(
                "   - Check if your AWS user has permission to call {}",
                Style::new().bold().paint("iam:SimulatePrincipalPolicy")
            );

            suggest_policy_update(
                &identity,
                "iam.SimulatePrincipalPolicy",
                "iam:SimulatePrincipalPolicy",
            );
            anyhow::bail!("Unable to simulate permissions");
        }
    };

    if sim.is_truncated() {
        anyhow::bail!("Too many results");
    }

    for result in sim.evaluation_results() {
        match result.eval_decision() {
            aws_sdk_iam::types::PolicyEvaluationDecisionType::Allowed => {}
            aws_sdk_iam::types::PolicyEvaluationDecisionType::ExplicitDeny => {
                println!(
                    "{}",
                    Red.bold().paint(format!(
                        "Not authorized to call {} due to explicit deny",
                        result.eval_action_name()
                    ))
                );
                println!("You will need to remove the explicit deny from your policy");
                anyhow::bail!("Explicit deny");
            }
            aws_sdk_iam::types::PolicyEvaluationDecisionType::ImplicitDeny => {
                println!(
                    "{}",
                    Red.bold().paint(format!(
                        "Not authorized to call {} due to implicit deny",
                        result.eval_action_name()
                    ))
                );
                println!("You will need to explicitly authorize this action");

                suggest_policy_update(
                    &identity,
                    &result.eval_action_name().replace(":", "."),
                    result.eval_action_name(),
                );

                anyhow::bail!("Implicit deny");
            }
            not => anyhow::bail!(
                "Not authorized to call {}: {not}",
                result.eval_action_name()
            ),
        }
    }

    println!(
        "{}",
        Green.bold().paint(format!(
            "AWS policy allows connecting as {}",
            if is_admin { "admin" } else { "non-admin user" }
        ))
    );

    if is_admin {
        println!(
            r#"
Given we were not able to connect to the cluster, but your policies allow admin
access, you should diagnose the actual connection between your client and {}.
"#,
            args.cluster_endpoint
        );
    } else {
        println!(
            r#"
Given we were not able to connect to the cluster, but your policies did allow
access, you should ensure your IAM entity has permission to the role {user}.

If you have access to the cluster as admin, the following may help:

1. You can look at existing grants by running:

       SELECT * FROM sys.iam_pg_role_mappings;

   Make sure the output contains the tuple:
       - arn = {iam_entity}
       - pg_role_name = {user}

2. You can grant access by running:

       AWS IAM GRANT {user} TO '{iam_entity}';
"#,
            user = args.user,
            iam_entity = identity.arn,
        );
    }

    Ok(())
}

async fn load_sdk_config(args: &Args) -> SdkConfig {
    // Create a config with the specified profile
    let mut config_builder = aws_config::defaults(aws_config::BehaviorVersion::latest());
    if let Some(r) = &args.region {
        config_builder = config_builder.region(Region::new(r.clone()));
    }
    if let Some(p) = &args.profile {
        config_builder = config_builder.profile_name(p);
    }

    config_builder.load().await
}

async fn validate_aws_creds_locally(sdk_config: &SdkConfig) -> Result<()> {
    let Some(provider) = sdk_config.credentials_provider() else {
        anyhow::bail!("no credentials provider")
    };

    let now = SystemTime::now();

    let credentials = provider
        .provide_credentials()
        .await
        .context("No AWS credentials found")?;

    if let Some(expiry) = credentials.expiry() {
        if expiry < now {
            let now: DateTime<Utc> = now.into();
            let iso = now.to_rfc3339();
            anyhow::bail!("Your AWS credentials have already expired. They expired at: {iso}");
        }
    }

    Ok(())
}

/// Test AWS credentials and return identity information
async fn test_aws_credentials(sdk_config: &SdkConfig) -> Result<AwsIdentity> {
    // Create an STS client
    let sts_client = StsClient::new(sdk_config);

    // Call GetCallerIdentity to verify credentials
    let identity = sts_client
        .get_caller_identity()
        .send()
        .await
        .context("Failed to get AWS identity. Check your AWS credentials and permissions.")?;

    Ok(AwsIdentity {
        account_id: identity.account().unwrap_or("unknown").to_string(),
        arn: identity.arn().unwrap_or("unknown").to_string(),
        user_id: identity.user_id().unwrap_or("unknown").to_string(),
    })
}

/// Test connectivity to the DSQL cluster endpoint
async fn test_cluster_connectivity(sdk_config: &SdkConfig, args: &Args) -> Result<(), BoxError> {
    let signer = AuthTokenGenerator::new(
        auth_token::Config::builder()
            .hostname(&args.cluster_endpoint)
            .build()?,
    );

    let token = match &args.user[..] {
        "admin" => signer.db_connect_admin_auth_token(&sdk_config).await?,
        _ => signer.db_connect_auth_token(&sdk_config).await?,
    };

    let config = format!(
        "host={} user={} password={} dbname=postgres sslmode=require",
        args.cluster_endpoint, args.user, token
    );
    let connector = TlsConnector::builder().build()?;
    let tls = MakeTlsConnector::new(connector);
    _ = tokio_postgres::connect(&config, tls).await?;

    Ok(())
}

async fn do_policy_sim(
    sdk_config: &SdkConfig,
    cluster_arn: &str,
    user: &str,
    identity: &AwsIdentity,
) -> Result<(bool, SimulatePrincipalPolicyOutput)> {
    let is_admin = if user == "admin" { true } else { false };
    let action = if is_admin {
        "dsql:DbConnectAdmin"
    } else {
        "dsql:DbConnect"
    };

    let client = aws_sdk_iam::Client::new(&sdk_config);
    let sim = client
        .simulate_principal_policy()
        .action_names(action)
        .policy_source_arn(identity.arn.clone())
        .resource_arns(cluster_arn)
        .send()
        .await
        .context(format!(
            "Failed to simulate {action}. Check your permissions."
        ))?;

    Ok((is_admin, sim))
}

fn suggest_policy_update(identity: &AwsIdentity, policy_name: &str, action: &str) {
    let (action_part, entity_name) = if identity.arn.contains(":user/") {
        let n = identity.arn.split(":user/").nth(1);
        ("user", n.unwrap_or("IAM_USER_NAME"))
    } else if identity.arn.contains(":role/") {
        let n = identity.arn.split(":role/").nth(1);
        ("role", n.unwrap_or("IAM_ROLE_NAME"))
    } else {
        return;
    };

    println!(
        r#"You can add this policy by running:

aws {profile_arg} iam put-{action_part}-policy --{action_part}-name {entity_name} --policy-name '{policy_name}' --policy-document '{{
    "Version": "2012-10-17",
    "Statement": [{{
        "Effect": "Allow",
        "Action": "{action}",
        "Resource": "*"
    }}]
}}'

If you don't have access to modify profiles, please ask your administrator for help.
"#,
        profile_arg = Style::new().bold().paint("--profile YOUR_ADMIN_PROFILE")
    );
}
