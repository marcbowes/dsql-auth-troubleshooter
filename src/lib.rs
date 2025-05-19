use anyhow::Result;
use s2n_codec::{DecoderBuffer, DecoderBufferResult, DecoderError, DecoderValue};

/// AWS identity information
pub struct AwsIdentity {
    pub account_id: String,
    pub arn: String,
    pub user_id: String,
}

struct PeriodDelim(String);

impl<'a> DecoderValue<'a> for PeriodDelim {
    fn decode(mut buffer: DecoderBuffer<'a>) -> DecoderBufferResult<'a, Self> {
        let mut r = PeriodDelim(String::new());

        while !buffer.is_empty() {
            let (b, n) = buffer.decode::<u8>()?;
            let ch = b as char;
            buffer = n;

            if ch == '.' {
                return Ok((r, buffer));
            } else {
                r.0.push(ch);
            }
        }

        if r.0.is_ascii() {
            return Err(DecoderError::InvariantViolation("nothing to decode"));
        }

        Ok((r, buffer))
    }
}

impl From<PeriodDelim> for String {
    fn from(value: PeriodDelim) -> Self {
        value.0
    }
}

pub struct ClusterEndpoint {
    pub cluster_id: String,
    pub aws_region: String,
}

impl TryFrom<&str> for ClusterEndpoint {
    type Error = DecoderError;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        let decoder = DecoderBuffer::new(&value.as_bytes());
        let (it, _) = ClusterEndpoint::decode(decoder)?;
        Ok(it)
    }
}

impl<'a> DecoderValue<'a> for ClusterEndpoint {
    fn decode(buffer: DecoderBuffer<'a>) -> DecoderBufferResult<'a, Self> {
        let (cluster_id, buffer) = buffer.decode::<PeriodDelim>()?;
        let (_dsql, buffer) = buffer.decode::<PeriodDelim>()?;
        let (aws_region, buffer) = buffer.decode::<PeriodDelim>()?;

        Ok((
            ClusterEndpoint {
                cluster_id: cluster_id.into(),
                aws_region: aws_region.into(),
            },
            buffer,
        ))
    }
}

impl ClusterEndpoint {
    /// Builds an Amazon Resource Name from a cluster endpoint. Assumes the cluster
    /// is owned by the given [`AwsIdentity`].
    pub fn cluster_arn(&self, identity: &AwsIdentity) -> Result<String> {
        let arn = format!(
            "arn:aws:dsql:{aws_region}:{account_id}:cluster/{cluster_id}",
            aws_region = &self.aws_region,
            cluster_id = &self.cluster_id,
            account_id = identity.account_id,
        );

        Ok(arn)
    }
}
