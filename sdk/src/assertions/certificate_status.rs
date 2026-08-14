// Copyright 2025 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::{
    assertion::{Assertion, AssertionBase, AssertionCbor},
    assertions::labels,
    crypto::base64,
    error::Result,
};

/// Helper class to create Certificate Status assertions
#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Eq)]
pub struct CertificateStatus {
    #[serde(
        rename = "ocspVals",
        serialize_with = "serialize_bytes_vec",
        deserialize_with = "deserialize_bytes_vec"
    )]
    pub ocsp_vals: Vec<ByteBuf>,
}

impl CertificateStatus {
    /// Label prefix for a [`CertificateStatus`] assertion.
    ///
    /// See [certificate status assertion - C2PA Technical Specification](https://spec.c2pa.org/specifications/specifications/2.3/specs/C2PA_Specification.html#certificate_status_assertion)
    pub const LABEL: &'static str = labels::CERTIFICATE_STATUS;

    pub fn new(ocsp_vals: Vec<Vec<u8>>) -> Self {
        let mut cs = CertificateStatus {
            ocsp_vals: Vec::new(),
        };
        for oscp_val in ocsp_vals {
            cs.ocsp_vals.push(ByteBuf::from(oscp_val));
        }
        cs
    }

    pub fn add_ocsp_vals(mut self, ocsp_vals: Vec<Vec<u8>>) -> Self {
        for ocsp_val in ocsp_vals {
            self.ocsp_vals.push(ByteBuf::from(ocsp_val));
        }
        self
    }
}

impl AsRef<Vec<ByteBuf>> for CertificateStatus {
    fn as_ref(&self) -> &Vec<ByteBuf> {
        &self.ocsp_vals
    }
}

impl AssertionCbor for CertificateStatus {
    fn to_cbor_assertion(&self) -> Result<Assertion> {
        CertificateStatusCbor {
            ocsp_vals: self.ocsp_vals.clone(),
        }
        .to_cbor_assertion()
    }

    fn from_cbor_assertion(assertion: &Assertion) -> Result<Self> {
        CertificateStatusCbor::from_cbor_assertion(assertion).map(|status| Self {
            ocsp_vals: status.ocsp_vals,
        })
    }
}

// c2pa_cbor currently reports itself as human-readable to Serde. A distinct
// CBOR wire type prevents that incorrect signal from applying JSON's Base64
// encoding to OCSP responses, which the C2PA schema requires to be byte strings.
#[derive(Deserialize, Serialize)]
struct CertificateStatusCbor {
    #[serde(rename = "ocspVals", deserialize_with = "deserialize_cbor_bytes_vec")]
    ocsp_vals: Vec<ByteBuf>,
}

impl AssertionCbor for CertificateStatusCbor {}

impl AssertionBase for CertificateStatusCbor {
    const LABEL: &'static str = CertificateStatus::LABEL;

    fn to_assertion(&self) -> Result<Assertion> {
        self.to_cbor_assertion()
    }

    fn from_assertion(assertion: &Assertion) -> Result<Self> {
        Self::from_cbor_assertion(assertion)
    }
}

impl AssertionBase for CertificateStatus {
    const LABEL: &'static str = Self::LABEL;

    fn to_assertion(&self) -> Result<Assertion> {
        Self::to_cbor_assertion(self)
    }

    fn from_assertion(assertion: &Assertion) -> Result<Self> {
        Self::from_cbor_assertion(assertion)
    }
}

// Custom serialization functions
fn serialize_bytes_vec<S>(
    bytes_vec: &Vec<ByteBuf>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    if serializer.is_human_readable() {
        // For JSON (human readable), convert to base64 strings
        let base64_vec: Vec<String> = bytes_vec.iter().map(|buf| base64::encode(buf)).collect();
        base64_vec.serialize(serializer)
    } else {
        // For CBOR (non-human readable), use default serialization
        bytes_vec.serialize(serializer)
    }
}

fn deserialize_bytes_vec<'de, D>(deserializer: D) -> std::result::Result<Vec<ByteBuf>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    if deserializer.is_human_readable() {
        // For JSON (human readable), convert from base64 strings
        let base64_vec: Vec<String> = Vec::deserialize(deserializer)?;
        base64_vec
            .into_iter()
            .map(|s| {
                base64::decode(&s)
                    .map(ByteBuf::from)
                    .map_err(serde::de::Error::custom)
            })
            .collect()
    } else {
        // For CBOR (non-human readable), use default deserialization
        Vec::<ByteBuf>::deserialize(deserializer)
    }
}

fn deserialize_cbor_bytes_vec<'de, D>(
    deserializer: D,
) -> std::result::Result<Vec<ByteBuf>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Vec::<c2pa_cbor::Value>::deserialize(deserializer)?
        .into_iter()
        .map(|value| match value {
            c2pa_cbor::Value::Bytes(bytes) => Ok(ByteBuf::from(bytes)),
            _ => Err(serde::de::Error::custom(
                "certificate-status OCSP responses must be CBOR byte strings",
            )),
        })
        .collect()
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]

    use crate::{
        assertion::{Assertion, AssertionBase, AssertionData},
        assertions::CertificateStatus,
    };

    #[test]
    fn assertions_certificate_status() {
        let original = CertificateStatus::new(vec!["ocsp_val".into()]);

        assert_eq!(original.ocsp_vals.len(), 1);

        let assertion = original.to_assertion().unwrap();
        assert_eq!(assertion.mime_type(), "application/cbor");
        assert_eq!(assertion.label(), CertificateStatus::LABEL);

        let c2pa_cbor::Value::Map(values) = c2pa_cbor::from_slice(assertion.data()).unwrap() else {
            panic!("certificate status assertion must contain a CBOR map");
        };
        assert_eq!(
            values.get(&c2pa_cbor::Value::Text("ocspVals".to_owned())),
            Some(&c2pa_cbor::Value::Array(vec![c2pa_cbor::Value::Bytes(
                b"ocsp_val".to_vec(),
            )])),
        );

        let result = CertificateStatus::from_assertion(&assertion).unwrap();
        assert_eq!(result, original)
    }

    #[test]
    fn certificate_status_rejects_base64_text_in_cbor() {
        let malformed = serde_json::json!({ "ocspVals": ["b2NzcF92YWw="] });
        let assertion = Assertion::new(
            CertificateStatus::LABEL,
            None,
            AssertionData::Cbor(c2pa_cbor::to_vec(&malformed).unwrap()),
        );

        assert!(CertificateStatus::from_assertion(&assertion).is_err());
    }

    #[test]
    fn test_json_round_trip() {
        let json = serde_json::json!({
          "ocspVals" : [
            "b2NzcF92YWw=",
            ""
          ]
        });

        let original: CertificateStatus = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(serde_json::to_value(&original).unwrap(), json);
        let assertion = original.to_assertion().unwrap();
        let result = CertificateStatus::from_assertion(&assertion).unwrap();

        assert_eq!(result, original);
    }
}
