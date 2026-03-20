use opaque_ke::argon2::{Algorithm, Argon2, Params, Version};
use opaque_ke::errors::ProtocolError;
use opaque_ke::rand::rngs::OsRng;
use opaque_ke::{
    ClientLogin, ClientRegistration, Identifiers as OpaqueIdentifiers, ServerLogin,
    ServerRegistration as OpaqueServerRegistration, ServerSetup as OpaqueServerSetup,
};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyModule};

use crate::errors::{invalid_state_err, serialization_err, to_py_err};
use crate::py_utils;
use crate::suite::{
    MlKem768Ristretto255Sha512, P256Sha256, P384Sha384, P521Sha512, Ristretto255Sha512, SuiteId,
    parse_suite,
};

#[pyclass(unsendable, from_py_object)]
#[derive(Clone)]
pub struct Identifiers {
    #[pyo3(get)]
    client: Option<Vec<u8>>,
    #[pyo3(get)]
    server: Option<Vec<u8>>,
}

impl Identifiers {
    pub(crate) fn as_opaque(&self) -> OpaqueIdentifiers<'_> {
        OpaqueIdentifiers {
            client: self.client.as_deref(),
            server: self.server.as_deref(),
        }
    }
}

#[pymethods]
impl Identifiers {
    #[new]
    fn new(client: Option<Vec<u8>>, server: Option<Vec<u8>>) -> Self {
        Self { client, server }
    }
}

#[pyclass(unsendable, from_py_object)]
#[derive(Clone)]
pub struct Argon2Params {
    #[pyo3(get)]
    memory_cost_kib: u32,
    #[pyo3(get)]
    time_cost: u32,
    #[pyo3(get)]
    parallelism: u32,
    #[pyo3(get)]
    output_length: Option<usize>,
}

impl Argon2Params {
    pub(crate) fn to_params(&self) -> PyResult<Params> {
        Params::new(
            self.memory_cost_kib,
            self.time_cost,
            self.parallelism,
            self.output_length,
        )
        .map_err(|err| PyErr::new::<PyValueError, _>(err.to_string()))
    }
}

#[pymethods]
impl Argon2Params {
    #[new]
    fn new(
        memory_cost_kib: u32,
        time_cost: u32,
        parallelism: u32,
        output_length: Option<usize>,
    ) -> Self {
        Self {
            memory_cost_kib,
            time_cost,
            parallelism,
            output_length,
        }
    }
}

#[pyclass(unsendable, from_py_object)]
#[derive(Clone)]
pub struct KeyStretching {
    #[pyo3(get)]
    variant: String,
    params: Option<Argon2Params>,
}

impl KeyStretching {
    const MEMORY_CONSTRAINED: &'static str = "memory_constrained";
    const RFC_RECOMMENDED: &'static str = "rfc_recommended";

    fn normalize_variant(variant: &str) -> Option<&'static str> {
        match variant.to_ascii_lowercase().as_str() {
            "memory_constrained" | "memory-constrained" => Some(Self::MEMORY_CONSTRAINED),
            "rfc_recommended" | "rfc-draft-recommended" => Some(Self::RFC_RECOMMENDED),
            _ => None,
        }
    }

    pub(crate) fn default_js_compatible() -> Self {
        Self {
            variant: Self::MEMORY_CONSTRAINED.to_string(),
            params: None,
        }
    }

    pub(crate) fn build_ksf(&self) -> PyResult<Argon2<'static>> {
        let params = if let Some(params) = self.params.as_ref() {
            params.to_params()?
        } else {
            match self.variant.as_str() {
                Self::MEMORY_CONSTRAINED => Params::new(1 << 16, 3, 4, None)
                    .map_err(|err| PyErr::new::<PyValueError, _>(err.to_string()))?,
                Self::RFC_RECOMMENDED => Params::new((1 << 21) - 1, 1, 4, None)
                    .map_err(|err| PyErr::new::<PyValueError, _>(err.to_string()))?,
                _ => Params::DEFAULT,
            }
        };
        let algorithm = Algorithm::Argon2id;
        let version = Version::V0x13;
        Ok(Argon2::new(algorithm, version, params))
    }
}

#[pymethods]
impl KeyStretching {
    #[new]
    fn new(variant: &str, params: Option<PyRef<'_, Argon2Params>>) -> PyResult<Self> {
        let normalized = Self::normalize_variant(variant).ok_or_else(|| {
            PyErr::new::<PyValueError, _>(format!("unsupported key stretching variant '{variant}'"))
        })?;
        Ok(Self {
            variant: normalized.to_string(),
            params: params.map(|value| value.clone()),
        })
    }
}

#[pyclass(unsendable, from_py_object)]
#[derive(Clone)]
pub struct ClientRegistrationFinishParameters {
    identifiers: Option<Identifiers>,
    key_stretching: Option<KeyStretching>,
}

impl ClientRegistrationFinishParameters {
    pub(crate) fn identifiers(&self) -> Option<&Identifiers> {
        self.identifiers.as_ref()
    }

    pub(crate) fn key_stretching(&self) -> Option<&KeyStretching> {
        self.key_stretching.as_ref()
    }
}

#[pymethods]
impl ClientRegistrationFinishParameters {
    #[new]
    fn new(
        identifiers: Option<PyRef<'_, Identifiers>>,
        key_stretching: Option<PyRef<'_, KeyStretching>>,
    ) -> Self {
        Self {
            identifiers: identifiers.map(|value| value.clone()),
            key_stretching: key_stretching.map(|value| value.clone()),
        }
    }
}

#[pyclass(unsendable, from_py_object)]
#[derive(Clone)]
pub struct ServerLoginParameters {
    context: Option<Vec<u8>>,
    identifiers: Option<Identifiers>,
}

impl ServerLoginParameters {
    pub(crate) fn context(&self) -> Option<&[u8]> {
        self.context.as_deref()
    }

    pub(crate) fn identifiers(&self) -> Option<&Identifiers> {
        self.identifiers.as_ref()
    }
}

#[pymethods]
impl ServerLoginParameters {
    #[new]
    fn new(context: Option<Vec<u8>>, identifiers: Option<PyRef<'_, Identifiers>>) -> Self {
        Self {
            context,
            identifiers: identifiers.map(|value| value.clone()),
        }
    }
}

#[pyclass(unsendable, from_py_object)]
#[derive(Clone)]
pub struct ClientLoginFinishParameters {
    context: Option<Vec<u8>>,
    identifiers: Option<Identifiers>,
    key_stretching: Option<KeyStretching>,
    server_s_pk: Option<Vec<u8>>,
}

impl ClientLoginFinishParameters {
    pub(crate) fn context(&self) -> Option<&[u8]> {
        self.context.as_deref()
    }

    pub(crate) fn identifiers(&self) -> Option<&Identifiers> {
        self.identifiers.as_ref()
    }

    pub(crate) fn key_stretching(&self) -> Option<&KeyStretching> {
        self.key_stretching.as_ref()
    }

    pub(crate) fn server_s_pk(&self) -> Option<&[u8]> {
        self.server_s_pk.as_deref()
    }
}

#[pymethods]
impl ClientLoginFinishParameters {
    #[new]
    fn new(
        context: Option<Vec<u8>>,
        identifiers: Option<PyRef<'_, Identifiers>>,
        key_stretching: Option<PyRef<'_, KeyStretching>>,
        server_s_pk: Option<Vec<u8>>,
    ) -> Self {
        Self {
            context,
            identifiers: identifiers.map(|value| value.clone()),
            key_stretching: key_stretching.map(|value| value.clone()),
            server_s_pk,
        }
    }
}

fn deserialize_py_err<T: std::fmt::Display>(err: ProtocolError<T>) -> PyErr {
    match err {
        ProtocolError::SizeError { .. } => to_py_err(err),
        _ => serialization_err(&err.to_string()),
    }
}

fn deserialize_with_suite<T, F>(suite: Option<String>, label: &str, mut parse: F) -> PyResult<T>
where
    F: FnMut(SuiteId) -> PyResult<T>,
{
    if let Some(suite) = suite {
        return parse(parse_suite(Some(suite.as_str()))?);
    }

    let mut matched = Vec::new();
    let mut value = None;
    for candidate in SuiteId::all() {
        if let Ok(parsed) = parse(candidate) {
            matched.push(candidate.as_str());
            if value.is_none() {
                value = Some(parsed);
            }
        }
    }

    match matched.len() {
        0 => Err(serialization_err(&format!(
            "failed to deserialize {label} under any supported cipher suite"
        ))),
        1 => match value {
            Some(value) => Ok(value),
            None => Err(serialization_err(&format!(
                "failed to deserialize {label} under any supported cipher suite"
            ))),
        },
        _ => Err(PyErr::new::<PyValueError, _>(format!(
            "ambiguous {label} deserialization; pass suite explicitly (matches: {})",
            matched.join(", ")
        ))),
    }
}

pub(crate) enum ServerSetupInner {
    Ristretto255Sha512(OpaqueServerSetup<Ristretto255Sha512>),
    P256Sha256(OpaqueServerSetup<P256Sha256>),
    P384Sha384(OpaqueServerSetup<P384Sha384>),
    P521Sha512(OpaqueServerSetup<P521Sha512>),
    MlKem768Ristretto255Sha512(OpaqueServerSetup<MlKem768Ristretto255Sha512>),
}

impl ServerSetupInner {
    fn suite_id(&self) -> SuiteId {
        match self {
            ServerSetupInner::Ristretto255Sha512(_) => SuiteId::Ristretto255Sha512,
            ServerSetupInner::P256Sha256(_) => SuiteId::P256Sha256,
            ServerSetupInner::P384Sha384(_) => SuiteId::P384Sha384,
            ServerSetupInner::P521Sha512(_) => SuiteId::P521Sha512,
            ServerSetupInner::MlKem768Ristretto255Sha512(_) => SuiteId::MlKem768Ristretto255Sha512,
        }
    }
}

#[pyclass(unsendable)]
pub struct ServerSetup {
    pub(crate) inner: ServerSetupInner,
}

#[pymethods]
impl ServerSetup {
    #[pyo3(signature = (suite=None))]
    #[new]
    fn new(suite: Option<String>) -> PyResult<Self> {
        let suite = parse_suite(suite.as_deref())?;
        let mut rng = OsRng;
        let inner = match suite {
            SuiteId::Ristretto255Sha512 => ServerSetupInner::Ristretto255Sha512(
                OpaqueServerSetup::<Ristretto255Sha512>::new(&mut rng),
            ),
            SuiteId::P256Sha256 => {
                ServerSetupInner::P256Sha256(OpaqueServerSetup::<P256Sha256>::new(&mut rng))
            }
            SuiteId::P384Sha384 => {
                ServerSetupInner::P384Sha384(OpaqueServerSetup::<P384Sha384>::new(&mut rng))
            }
            SuiteId::P521Sha512 => {
                ServerSetupInner::P521Sha512(OpaqueServerSetup::<P521Sha512>::new(&mut rng))
            }
            SuiteId::MlKem768Ristretto255Sha512 => {
                ServerSetupInner::MlKem768Ristretto255Sha512(OpaqueServerSetup::<
                    MlKem768Ristretto255Sha512,
                >::new(&mut rng))
            }
        };
        Ok(Self { inner })
    }

    #[staticmethod]
    #[pyo3(signature = (data, suite=None))]
    fn deserialize(data: Vec<u8>, suite: Option<String>) -> PyResult<Self> {
        let inner = deserialize_with_suite(suite, "ServerSetup", |suite| {
            Ok(match suite {
                SuiteId::Ristretto255Sha512 => ServerSetupInner::Ristretto255Sha512(
                    OpaqueServerSetup::<Ristretto255Sha512>::deserialize(&data)
                        .map_err(deserialize_py_err)?,
                ),
                SuiteId::P256Sha256 => ServerSetupInner::P256Sha256(
                    OpaqueServerSetup::<P256Sha256>::deserialize(&data)
                        .map_err(deserialize_py_err)?,
                ),
                SuiteId::P384Sha384 => ServerSetupInner::P384Sha384(
                    OpaqueServerSetup::<P384Sha384>::deserialize(&data)
                        .map_err(deserialize_py_err)?,
                ),
                SuiteId::P521Sha512 => ServerSetupInner::P521Sha512(
                    OpaqueServerSetup::<P521Sha512>::deserialize(&data)
                        .map_err(deserialize_py_err)?,
                ),
                SuiteId::MlKem768Ristretto255Sha512 => {
                    ServerSetupInner::MlKem768Ristretto255Sha512(
                        OpaqueServerSetup::<MlKem768Ristretto255Sha512>::deserialize(&data)
                            .map_err(deserialize_py_err)?,
                    )
                }
            })
        })?;
        Ok(Self { inner })
    }

    fn serialize(&self, py: Python<'_>) -> Py<PyBytes> {
        let serialized = match &self.inner {
            ServerSetupInner::Ristretto255Sha512(inner) => inner.serialize().to_vec(),
            ServerSetupInner::P256Sha256(inner) => inner.serialize().to_vec(),
            ServerSetupInner::P384Sha384(inner) => inner.serialize().to_vec(),
            ServerSetupInner::P521Sha512(inner) => inner.serialize().to_vec(),
            ServerSetupInner::MlKem768Ristretto255Sha512(inner) => inner.serialize().to_vec(),
        };
        py_utils::to_pybytes(py, &serialized)
    }
}

impl ServerSetup {
    pub(crate) fn suite_id(&self) -> SuiteId {
        self.inner.suite_id()
    }
}

pub(crate) enum ServerRegistrationInner {
    Ristretto255Sha512(OpaqueServerRegistration<Ristretto255Sha512>),
    P256Sha256(OpaqueServerRegistration<P256Sha256>),
    P384Sha384(OpaqueServerRegistration<P384Sha384>),
    P521Sha512(OpaqueServerRegistration<P521Sha512>),
    MlKem768Ristretto255Sha512(OpaqueServerRegistration<MlKem768Ristretto255Sha512>),
}

impl ServerRegistrationInner {
    fn suite_id(&self) -> SuiteId {
        match self {
            ServerRegistrationInner::Ristretto255Sha512(_) => SuiteId::Ristretto255Sha512,
            ServerRegistrationInner::P256Sha256(_) => SuiteId::P256Sha256,
            ServerRegistrationInner::P384Sha384(_) => SuiteId::P384Sha384,
            ServerRegistrationInner::P521Sha512(_) => SuiteId::P521Sha512,
            ServerRegistrationInner::MlKem768Ristretto255Sha512(_) => {
                SuiteId::MlKem768Ristretto255Sha512
            }
        }
    }
}

#[pyclass(unsendable)]
pub struct ServerRegistration {
    pub(crate) inner: ServerRegistrationInner,
}

#[pymethods]
impl ServerRegistration {
    #[staticmethod]
    #[pyo3(signature = (data, suite=None))]
    fn deserialize(data: Vec<u8>, suite: Option<String>) -> PyResult<Self> {
        let inner = deserialize_with_suite(suite, "ServerRegistration", |suite| {
            Ok(match suite {
                SuiteId::Ristretto255Sha512 => ServerRegistrationInner::Ristretto255Sha512(
                    OpaqueServerRegistration::<Ristretto255Sha512>::deserialize(&data)
                        .map_err(deserialize_py_err)?,
                ),
                SuiteId::P256Sha256 => ServerRegistrationInner::P256Sha256(
                    OpaqueServerRegistration::<P256Sha256>::deserialize(&data)
                        .map_err(deserialize_py_err)?,
                ),
                SuiteId::P384Sha384 => ServerRegistrationInner::P384Sha384(
                    OpaqueServerRegistration::<P384Sha384>::deserialize(&data)
                        .map_err(deserialize_py_err)?,
                ),
                SuiteId::P521Sha512 => ServerRegistrationInner::P521Sha512(
                    OpaqueServerRegistration::<P521Sha512>::deserialize(&data)
                        .map_err(deserialize_py_err)?,
                ),
                SuiteId::MlKem768Ristretto255Sha512 => {
                    ServerRegistrationInner::MlKem768Ristretto255Sha512(
                        OpaqueServerRegistration::<MlKem768Ristretto255Sha512>::deserialize(&data)
                            .map_err(deserialize_py_err)?,
                    )
                }
            })
        })?;
        Ok(Self { inner })
    }

    fn serialize(&self, py: Python<'_>) -> PyResult<Py<PyBytes>> {
        let serialized = match &self.inner {
            ServerRegistrationInner::Ristretto255Sha512(inner) => inner.serialize().to_vec(),
            ServerRegistrationInner::P256Sha256(inner) => inner.serialize().to_vec(),
            ServerRegistrationInner::P384Sha384(inner) => inner.serialize().to_vec(),
            ServerRegistrationInner::P521Sha512(inner) => inner.serialize().to_vec(),
            ServerRegistrationInner::MlKem768Ristretto255Sha512(inner) => {
                inner.serialize().to_vec()
            }
        };
        Ok(py_utils::to_pybytes(py, &serialized))
    }
}

impl ServerRegistration {
    pub(crate) fn suite_id(&self) -> SuiteId {
        self.inner.suite_id()
    }
}

pub(crate) enum ClientRegistrationStateInner {
    Ristretto255Sha512(Option<ClientRegistration<Ristretto255Sha512>>),
    P256Sha256(Option<ClientRegistration<P256Sha256>>),
    P384Sha384(Option<ClientRegistration<P384Sha384>>),
    P521Sha512(Option<ClientRegistration<P521Sha512>>),
    MlKem768Ristretto255Sha512(Option<ClientRegistration<MlKem768Ristretto255Sha512>>),
}

impl ClientRegistrationStateInner {
    fn suite_id(&self) -> SuiteId {
        match self {
            ClientRegistrationStateInner::Ristretto255Sha512(_) => SuiteId::Ristretto255Sha512,
            ClientRegistrationStateInner::P256Sha256(_) => SuiteId::P256Sha256,
            ClientRegistrationStateInner::P384Sha384(_) => SuiteId::P384Sha384,
            ClientRegistrationStateInner::P521Sha512(_) => SuiteId::P521Sha512,
            ClientRegistrationStateInner::MlKem768Ristretto255Sha512(_) => {
                SuiteId::MlKem768Ristretto255Sha512
            }
        }
    }
}

#[pyclass(unsendable)]
pub struct ClientRegistrationState {
    pub(crate) inner: ClientRegistrationStateInner,
}

#[pymethods]
impl ClientRegistrationState {
    #[staticmethod]
    #[pyo3(signature = (data, suite=None))]
    fn deserialize(data: Vec<u8>, suite: Option<String>) -> PyResult<Self> {
        let inner = deserialize_with_suite(suite, "ClientRegistrationState", |suite| {
            Ok(match suite {
                SuiteId::Ristretto255Sha512 => {
                    ClientRegistrationStateInner::Ristretto255Sha512(Some(
                        ClientRegistration::<Ristretto255Sha512>::deserialize(&data)
                            .map_err(deserialize_py_err)?,
                    ))
                }
                SuiteId::P256Sha256 => ClientRegistrationStateInner::P256Sha256(Some(
                    ClientRegistration::<P256Sha256>::deserialize(&data)
                        .map_err(deserialize_py_err)?,
                )),
                SuiteId::P384Sha384 => ClientRegistrationStateInner::P384Sha384(Some(
                    ClientRegistration::<P384Sha384>::deserialize(&data)
                        .map_err(deserialize_py_err)?,
                )),
                SuiteId::P521Sha512 => ClientRegistrationStateInner::P521Sha512(Some(
                    ClientRegistration::<P521Sha512>::deserialize(&data)
                        .map_err(deserialize_py_err)?,
                )),
                SuiteId::MlKem768Ristretto255Sha512 => {
                    ClientRegistrationStateInner::MlKem768Ristretto255Sha512(Some(
                        ClientRegistration::<MlKem768Ristretto255Sha512>::deserialize(&data)
                            .map_err(deserialize_py_err)?,
                    ))
                }
            })
        })?;
        Ok(Self { inner })
    }

    fn serialize(&self, py: Python<'_>) -> PyResult<Py<PyBytes>> {
        let serialized = match &self.inner {
            ClientRegistrationStateInner::Ristretto255Sha512(inner) => inner
                .as_ref()
                .ok_or_else(|| invalid_state_err("ClientRegistrationState has already been used"))?
                .serialize()
                .to_vec(),
            ClientRegistrationStateInner::P256Sha256(inner) => inner
                .as_ref()
                .ok_or_else(|| invalid_state_err("ClientRegistrationState has already been used"))?
                .serialize()
                .to_vec(),
            ClientRegistrationStateInner::P384Sha384(inner) => inner
                .as_ref()
                .ok_or_else(|| invalid_state_err("ClientRegistrationState has already been used"))?
                .serialize()
                .to_vec(),
            ClientRegistrationStateInner::P521Sha512(inner) => inner
                .as_ref()
                .ok_or_else(|| invalid_state_err("ClientRegistrationState has already been used"))?
                .serialize()
                .to_vec(),
            ClientRegistrationStateInner::MlKem768Ristretto255Sha512(inner) => inner
                .as_ref()
                .ok_or_else(|| invalid_state_err("ClientRegistrationState has already been used"))?
                .serialize()
                .to_vec(),
        };
        Ok(py_utils::to_pybytes(py, &serialized))
    }
}

impl ClientRegistrationState {
    pub(crate) fn suite_id(&self) -> SuiteId {
        self.inner.suite_id()
    }

    pub(crate) fn take_ristretto(&mut self) -> PyResult<ClientRegistration<Ristretto255Sha512>> {
        match &mut self.inner {
            ClientRegistrationStateInner::Ristretto255Sha512(inner) => inner
                .take()
                .ok_or_else(|| invalid_state_err("ClientRegistrationState has already been used")),
            _ => Err(invalid_state_err(
                "ClientRegistrationState does not match requested cipher suite",
            )),
        }
    }

    pub(crate) fn take_p256(&mut self) -> PyResult<ClientRegistration<P256Sha256>> {
        match &mut self.inner {
            ClientRegistrationStateInner::P256Sha256(inner) => inner
                .take()
                .ok_or_else(|| invalid_state_err("ClientRegistrationState has already been used")),
            _ => Err(invalid_state_err(
                "ClientRegistrationState does not match requested cipher suite",
            )),
        }
    }

    pub(crate) fn take_p384(&mut self) -> PyResult<ClientRegistration<P384Sha384>> {
        match &mut self.inner {
            ClientRegistrationStateInner::P384Sha384(inner) => inner
                .take()
                .ok_or_else(|| invalid_state_err("ClientRegistrationState has already been used")),
            _ => Err(invalid_state_err(
                "ClientRegistrationState does not match requested cipher suite",
            )),
        }
    }

    pub(crate) fn take_p521(&mut self) -> PyResult<ClientRegistration<P521Sha512>> {
        match &mut self.inner {
            ClientRegistrationStateInner::P521Sha512(inner) => inner
                .take()
                .ok_or_else(|| invalid_state_err("ClientRegistrationState has already been used")),
            _ => Err(invalid_state_err(
                "ClientRegistrationState does not match requested cipher suite",
            )),
        }
    }

    pub(crate) fn take_kem(&mut self) -> PyResult<ClientRegistration<MlKem768Ristretto255Sha512>> {
        match &mut self.inner {
            ClientRegistrationStateInner::MlKem768Ristretto255Sha512(inner) => inner
                .take()
                .ok_or_else(|| invalid_state_err("ClientRegistrationState has already been used")),
            _ => Err(invalid_state_err(
                "ClientRegistrationState does not match requested cipher suite",
            )),
        }
    }
}

pub(crate) enum ClientLoginStateInner {
    Ristretto255Sha512(Option<ClientLogin<Ristretto255Sha512>>),
    P256Sha256(Option<ClientLogin<P256Sha256>>),
    P384Sha384(Option<ClientLogin<P384Sha384>>),
    P521Sha512(Option<ClientLogin<P521Sha512>>),
    MlKem768Ristretto255Sha512(Option<ClientLogin<MlKem768Ristretto255Sha512>>),
}

impl ClientLoginStateInner {
    fn suite_id(&self) -> SuiteId {
        match self {
            ClientLoginStateInner::Ristretto255Sha512(_) => SuiteId::Ristretto255Sha512,
            ClientLoginStateInner::P256Sha256(_) => SuiteId::P256Sha256,
            ClientLoginStateInner::P384Sha384(_) => SuiteId::P384Sha384,
            ClientLoginStateInner::P521Sha512(_) => SuiteId::P521Sha512,
            ClientLoginStateInner::MlKem768Ristretto255Sha512(_) => {
                SuiteId::MlKem768Ristretto255Sha512
            }
        }
    }
}

#[pyclass(unsendable)]
pub struct ClientLoginState {
    pub(crate) inner: ClientLoginStateInner,
}

#[pymethods]
impl ClientLoginState {
    #[staticmethod]
    #[pyo3(signature = (data, suite=None))]
    fn deserialize(data: Vec<u8>, suite: Option<String>) -> PyResult<Self> {
        let inner = deserialize_with_suite(suite, "ClientLoginState", |suite| {
            Ok(match suite {
                SuiteId::Ristretto255Sha512 => ClientLoginStateInner::Ristretto255Sha512(Some(
                    ClientLogin::<Ristretto255Sha512>::deserialize(&data)
                        .map_err(deserialize_py_err)?,
                )),
                SuiteId::P256Sha256 => ClientLoginStateInner::P256Sha256(Some(
                    ClientLogin::<P256Sha256>::deserialize(&data).map_err(deserialize_py_err)?,
                )),
                SuiteId::P384Sha384 => ClientLoginStateInner::P384Sha384(Some(
                    ClientLogin::<P384Sha384>::deserialize(&data).map_err(deserialize_py_err)?,
                )),
                SuiteId::P521Sha512 => ClientLoginStateInner::P521Sha512(Some(
                    ClientLogin::<P521Sha512>::deserialize(&data).map_err(deserialize_py_err)?,
                )),
                SuiteId::MlKem768Ristretto255Sha512 => {
                    ClientLoginStateInner::MlKem768Ristretto255Sha512(Some(
                        ClientLogin::<MlKem768Ristretto255Sha512>::deserialize(&data)
                            .map_err(deserialize_py_err)?,
                    ))
                }
            })
        })?;
        Ok(Self { inner })
    }

    fn serialize(&self, py: Python<'_>) -> PyResult<Py<PyBytes>> {
        let serialized = match &self.inner {
            ClientLoginStateInner::Ristretto255Sha512(inner) => inner
                .as_ref()
                .ok_or_else(|| invalid_state_err("ClientLoginState has already been used"))?
                .serialize()
                .to_vec(),
            ClientLoginStateInner::P256Sha256(inner) => inner
                .as_ref()
                .ok_or_else(|| invalid_state_err("ClientLoginState has already been used"))?
                .serialize()
                .to_vec(),
            ClientLoginStateInner::P384Sha384(inner) => inner
                .as_ref()
                .ok_or_else(|| invalid_state_err("ClientLoginState has already been used"))?
                .serialize()
                .to_vec(),
            ClientLoginStateInner::P521Sha512(inner) => inner
                .as_ref()
                .ok_or_else(|| invalid_state_err("ClientLoginState has already been used"))?
                .serialize()
                .to_vec(),
            ClientLoginStateInner::MlKem768Ristretto255Sha512(inner) => inner
                .as_ref()
                .ok_or_else(|| invalid_state_err("ClientLoginState has already been used"))?
                .serialize()
                .to_vec(),
        };
        Ok(py_utils::to_pybytes(py, &serialized))
    }
}

impl ClientLoginState {
    pub(crate) fn suite_id(&self) -> SuiteId {
        self.inner.suite_id()
    }

    pub(crate) fn take_ristretto(&mut self) -> PyResult<ClientLogin<Ristretto255Sha512>> {
        match &mut self.inner {
            ClientLoginStateInner::Ristretto255Sha512(inner) => inner
                .take()
                .ok_or_else(|| invalid_state_err("ClientLoginState has already been used")),
            _ => Err(invalid_state_err(
                "ClientLoginState does not match requested cipher suite",
            )),
        }
    }

    pub(crate) fn take_p256(&mut self) -> PyResult<ClientLogin<P256Sha256>> {
        match &mut self.inner {
            ClientLoginStateInner::P256Sha256(inner) => inner
                .take()
                .ok_or_else(|| invalid_state_err("ClientLoginState has already been used")),
            _ => Err(invalid_state_err(
                "ClientLoginState does not match requested cipher suite",
            )),
        }
    }

    pub(crate) fn take_p384(&mut self) -> PyResult<ClientLogin<P384Sha384>> {
        match &mut self.inner {
            ClientLoginStateInner::P384Sha384(inner) => inner
                .take()
                .ok_or_else(|| invalid_state_err("ClientLoginState has already been used")),
            _ => Err(invalid_state_err(
                "ClientLoginState does not match requested cipher suite",
            )),
        }
    }

    pub(crate) fn take_p521(&mut self) -> PyResult<ClientLogin<P521Sha512>> {
        match &mut self.inner {
            ClientLoginStateInner::P521Sha512(inner) => inner
                .take()
                .ok_or_else(|| invalid_state_err("ClientLoginState has already been used")),
            _ => Err(invalid_state_err(
                "ClientLoginState does not match requested cipher suite",
            )),
        }
    }

    pub(crate) fn take_kem(&mut self) -> PyResult<ClientLogin<MlKem768Ristretto255Sha512>> {
        match &mut self.inner {
            ClientLoginStateInner::MlKem768Ristretto255Sha512(inner) => inner
                .take()
                .ok_or_else(|| invalid_state_err("ClientLoginState has already been used")),
            _ => Err(invalid_state_err(
                "ClientLoginState does not match requested cipher suite",
            )),
        }
    }
}

pub(crate) enum ServerLoginStateInner {
    Ristretto255Sha512(Option<ServerLogin<Ristretto255Sha512>>),
    P256Sha256(Option<ServerLogin<P256Sha256>>),
    P384Sha384(Option<ServerLogin<P384Sha384>>),
    P521Sha512(Option<ServerLogin<P521Sha512>>),
    MlKem768Ristretto255Sha512(Option<ServerLogin<MlKem768Ristretto255Sha512>>),
}

impl ServerLoginStateInner {
    fn suite_id(&self) -> SuiteId {
        match self {
            ServerLoginStateInner::Ristretto255Sha512(_) => SuiteId::Ristretto255Sha512,
            ServerLoginStateInner::P256Sha256(_) => SuiteId::P256Sha256,
            ServerLoginStateInner::P384Sha384(_) => SuiteId::P384Sha384,
            ServerLoginStateInner::P521Sha512(_) => SuiteId::P521Sha512,
            ServerLoginStateInner::MlKem768Ristretto255Sha512(_) => {
                SuiteId::MlKem768Ristretto255Sha512
            }
        }
    }
}

#[pyclass(unsendable)]
pub struct ServerLoginState {
    pub(crate) inner: ServerLoginStateInner,
}

#[pymethods]
impl ServerLoginState {
    #[staticmethod]
    #[pyo3(signature = (data, suite=None))]
    fn deserialize(data: Vec<u8>, suite: Option<String>) -> PyResult<Self> {
        let inner = deserialize_with_suite(suite, "ServerLoginState", |suite| {
            Ok(match suite {
                SuiteId::Ristretto255Sha512 => ServerLoginStateInner::Ristretto255Sha512(Some(
                    ServerLogin::<Ristretto255Sha512>::deserialize(&data)
                        .map_err(deserialize_py_err)?,
                )),
                SuiteId::P256Sha256 => ServerLoginStateInner::P256Sha256(Some(
                    ServerLogin::<P256Sha256>::deserialize(&data).map_err(deserialize_py_err)?,
                )),
                SuiteId::P384Sha384 => ServerLoginStateInner::P384Sha384(Some(
                    ServerLogin::<P384Sha384>::deserialize(&data).map_err(deserialize_py_err)?,
                )),
                SuiteId::P521Sha512 => ServerLoginStateInner::P521Sha512(Some(
                    ServerLogin::<P521Sha512>::deserialize(&data).map_err(deserialize_py_err)?,
                )),
                SuiteId::MlKem768Ristretto255Sha512 => {
                    ServerLoginStateInner::MlKem768Ristretto255Sha512(Some(
                        ServerLogin::<MlKem768Ristretto255Sha512>::deserialize(&data)
                            .map_err(deserialize_py_err)?,
                    ))
                }
            })
        })?;
        Ok(Self { inner })
    }

    fn serialize(&self, py: Python<'_>) -> PyResult<Py<PyBytes>> {
        let serialized = match &self.inner {
            ServerLoginStateInner::Ristretto255Sha512(inner) => inner
                .as_ref()
                .ok_or_else(|| invalid_state_err("ServerLoginState has already been used"))?
                .serialize()
                .to_vec(),
            ServerLoginStateInner::P256Sha256(inner) => inner
                .as_ref()
                .ok_or_else(|| invalid_state_err("ServerLoginState has already been used"))?
                .serialize()
                .to_vec(),
            ServerLoginStateInner::P384Sha384(inner) => inner
                .as_ref()
                .ok_or_else(|| invalid_state_err("ServerLoginState has already been used"))?
                .serialize()
                .to_vec(),
            ServerLoginStateInner::P521Sha512(inner) => inner
                .as_ref()
                .ok_or_else(|| invalid_state_err("ServerLoginState has already been used"))?
                .serialize()
                .to_vec(),
            ServerLoginStateInner::MlKem768Ristretto255Sha512(inner) => inner
                .as_ref()
                .ok_or_else(|| invalid_state_err("ServerLoginState has already been used"))?
                .serialize()
                .to_vec(),
        };
        Ok(py_utils::to_pybytes(py, &serialized))
    }
}

impl ServerLoginState {
    pub(crate) fn suite_id(&self) -> SuiteId {
        self.inner.suite_id()
    }

    pub(crate) fn take_ristretto(&mut self) -> PyResult<ServerLogin<Ristretto255Sha512>> {
        match &mut self.inner {
            ServerLoginStateInner::Ristretto255Sha512(inner) => inner
                .take()
                .ok_or_else(|| invalid_state_err("ServerLoginState has already been used")),
            _ => Err(invalid_state_err(
                "ServerLoginState does not match requested cipher suite",
            )),
        }
    }

    pub(crate) fn take_p256(&mut self) -> PyResult<ServerLogin<P256Sha256>> {
        match &mut self.inner {
            ServerLoginStateInner::P256Sha256(inner) => inner
                .take()
                .ok_or_else(|| invalid_state_err("ServerLoginState has already been used")),
            _ => Err(invalid_state_err(
                "ServerLoginState does not match requested cipher suite",
            )),
        }
    }

    pub(crate) fn take_p384(&mut self) -> PyResult<ServerLogin<P384Sha384>> {
        match &mut self.inner {
            ServerLoginStateInner::P384Sha384(inner) => inner
                .take()
                .ok_or_else(|| invalid_state_err("ServerLoginState has already been used")),
            _ => Err(invalid_state_err(
                "ServerLoginState does not match requested cipher suite",
            )),
        }
    }

    pub(crate) fn take_p521(&mut self) -> PyResult<ServerLogin<P521Sha512>> {
        match &mut self.inner {
            ServerLoginStateInner::P521Sha512(inner) => inner
                .take()
                .ok_or_else(|| invalid_state_err("ServerLoginState has already been used")),
            _ => Err(invalid_state_err(
                "ServerLoginState does not match requested cipher suite",
            )),
        }
    }

    pub(crate) fn take_kem(&mut self) -> PyResult<ServerLogin<MlKem768Ristretto255Sha512>> {
        match &mut self.inner {
            ServerLoginStateInner::MlKem768Ristretto255Sha512(inner) => inner
                .take()
                .ok_or_else(|| invalid_state_err("ServerLoginState has already been used")),
            _ => Err(invalid_state_err(
                "ServerLoginState does not match requested cipher suite",
            )),
        }
    }
}

pub fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let module = py_utils::new_submodule(py, parent, "types")?;
    module.add_class::<Identifiers>()?;
    module.add_class::<Argon2Params>()?;
    module.add_class::<KeyStretching>()?;
    module.add_class::<ClientRegistrationFinishParameters>()?;
    module.add_class::<ServerLoginParameters>()?;
    module.add_class::<ClientLoginFinishParameters>()?;
    module.add_class::<ServerSetup>()?;
    module.add_class::<ServerRegistration>()?;
    module.add_class::<ClientRegistrationState>()?;
    module.add_class::<ClientLoginState>()?;
    module.add_class::<ServerLoginState>()?;
    py_utils::add_submodule(py, parent, "types", &module)?;
    Ok(())
}
