use opaque_ke::rand::rngs::OsRng;
use opaque_ke::{
    ClientRegistration, ClientRegistrationFinishParameters, RegistrationRequest,
    RegistrationResponse, RegistrationUpload, ServerRegistration,
};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyModule};

use crate::errors::{invalid_state_err, to_py_err};
use crate::py_utils::per_suite_dispatch;
use crate::suite::{
    MlKem768Ristretto255Sha512, P256Sha256, P384Sha384, P521Sha512, Ristretto255Sha512, SuiteId,
    parse_suite,
};
use crate::types::{
    ClientRegistrationFinishParameters as PyClientRegistrationFinishParameters,
    ClientRegistrationState, ClientRegistrationStateInner, KeyStretching,
    ServerRegistration as PyServerRegistration, ServerRegistrationInner, ServerSetup,
    ServerSetupInner,
};
use crate::{ensure_suite, py_utils};

#[pyfunction(name = "start_registration")]
#[pyo3(signature = (password, suite=None))]
fn client_start_registration(
    py: Python<'_>,
    password: Vec<u8>,
    suite: Option<String>,
) -> PyResult<(Py<PyBytes>, ClientRegistrationState)> {
    let suite = parse_suite(suite.as_deref())?;
    let mut rng = OsRng;
    per_suite_dispatch!(
        suite = suite,
        py = py,
        rng = rng,
        password = password,
        start = ClientRegistration,
        state_type = ClientRegistrationState,
        state_inner = ClientRegistrationStateInner,
        [
            (
                SuiteId::Ristretto255Sha512,
                Ristretto255Sha512,
                Ristretto255Sha512
            ),
            (SuiteId::P256Sha256, P256Sha256, P256Sha256),
            (SuiteId::P384Sha384, P384Sha384, P384Sha384),
            (SuiteId::P521Sha512, P521Sha512, P521Sha512),
            (
                SuiteId::MlKem768Ristretto255Sha512,
                MlKem768Ristretto255Sha512,
                MlKem768Ristretto255Sha512
            ),
        ]
    )
}

#[pyfunction(name = "finish_registration")]
#[pyo3(signature = (state, password, response, params=None, suite=None))]
pub(crate) fn client_finish_registration(
    py: Python<'_>,
    mut state: PyRefMut<'_, ClientRegistrationState>,
    password: Vec<u8>,
    response: Vec<u8>,
    params: Option<PyRef<'_, PyClientRegistrationFinishParameters>>,
    suite: Option<String>,
) -> PyResult<(Py<PyBytes>, Py<PyBytes>)> {
    let state_suite = state.suite_id();
    if let Some(requested) = suite {
        let requested = parse_suite(Some(requested.as_str()))?;
        ensure_suite(requested, state_suite, "ClientRegistrationState")?;
    }
    let identifiers = params
        .as_ref()
        .and_then(|params| params.identifiers().cloned());
    let opaque_identifiers = identifiers
        .as_ref()
        .map(|ids| ids.as_opaque())
        .unwrap_or_default();
    let key_stretching = params
        .as_ref()
        .and_then(|params| params.key_stretching())
        .cloned()
        .unwrap_or_else(KeyStretching::default_js_compatible);
    let ksf = key_stretching.build_ksf()?;
    let mut rng = OsRng;
    match state_suite {
        SuiteId::Ristretto255Sha512 => {
            let state = state.take_ristretto()?;
            let response = RegistrationResponse::<Ristretto255Sha512>::deserialize(&response)
                .map_err(to_py_err)?;
            let finish_params = ClientRegistrationFinishParameters::<Ristretto255Sha512>::new(
                opaque_identifiers,
                Some(&ksf),
            );
            let result = state
                .finish(&mut rng, &password, response, finish_params)
                .map_err(to_py_err)?;
            let message = result.message.serialize().to_vec();
            let export_key = result.export_key.to_vec();
            Ok((
                py_utils::to_pybytes(py, &message),
                py_utils::to_pybytes(py, &export_key),
            ))
        }
        SuiteId::P256Sha256 => {
            let state = state.take_p256()?;
            let response =
                RegistrationResponse::<P256Sha256>::deserialize(&response).map_err(to_py_err)?;
            let finish_params = ClientRegistrationFinishParameters::<P256Sha256>::new(
                opaque_identifiers,
                Some(&ksf),
            );
            let result = state
                .finish(&mut rng, &password, response, finish_params)
                .map_err(to_py_err)?;
            let message = result.message.serialize().to_vec();
            let export_key = result.export_key.to_vec();
            Ok((
                py_utils::to_pybytes(py, &message),
                py_utils::to_pybytes(py, &export_key),
            ))
        }
        SuiteId::P384Sha384 => {
            let state = state.take_p384()?;
            let response =
                RegistrationResponse::<P384Sha384>::deserialize(&response).map_err(to_py_err)?;
            let finish_params = ClientRegistrationFinishParameters::<P384Sha384>::new(
                opaque_identifiers,
                Some(&ksf),
            );
            let result = state
                .finish(&mut rng, &password, response, finish_params)
                .map_err(to_py_err)?;
            let message = result.message.serialize().to_vec();
            let export_key = result.export_key.to_vec();
            Ok((
                py_utils::to_pybytes(py, &message),
                py_utils::to_pybytes(py, &export_key),
            ))
        }
        SuiteId::P521Sha512 => {
            let state = state.take_p521()?;
            let response =
                RegistrationResponse::<P521Sha512>::deserialize(&response).map_err(to_py_err)?;
            let finish_params = ClientRegistrationFinishParameters::<P521Sha512>::new(
                opaque_identifiers,
                Some(&ksf),
            );
            let result = state
                .finish(&mut rng, &password, response, finish_params)
                .map_err(to_py_err)?;
            let message = result.message.serialize().to_vec();
            let export_key = result.export_key.to_vec();
            Ok((
                py_utils::to_pybytes(py, &message),
                py_utils::to_pybytes(py, &export_key),
            ))
        }
        SuiteId::MlKem768Ristretto255Sha512 => {
            let state = state.take_kem()?;
            let response =
                RegistrationResponse::<MlKem768Ristretto255Sha512>::deserialize(&response)
                    .map_err(to_py_err)?;
            let finish_params =
                ClientRegistrationFinishParameters::<MlKem768Ristretto255Sha512>::new(
                    opaque_identifiers,
                    Some(&ksf),
                );
            let result = state
                .finish(&mut rng, &password, response, finish_params)
                .map_err(to_py_err)?;
            let message = result.message.serialize().to_vec();
            let export_key = result.export_key.to_vec();
            Ok((
                py_utils::to_pybytes(py, &message),
                py_utils::to_pybytes(py, &export_key),
            ))
        }
    }
}

#[pyfunction(name = "start_registration")]
#[pyo3(signature = (server_setup, request, credential_identifier, suite=None))]
pub(crate) fn server_start_registration(
    py: Python<'_>,
    server_setup: PyRef<'_, ServerSetup>,
    request: Vec<u8>,
    credential_identifier: Vec<u8>,
    suite: Option<String>,
) -> PyResult<Py<PyBytes>> {
    let setup_suite = server_setup.suite_id();
    if let Some(requested) = suite {
        let requested = parse_suite(Some(requested.as_str()))?;
        ensure_suite(requested, setup_suite, "ServerSetup")?;
    }
    match &server_setup.inner {
        ServerSetupInner::Ristretto255Sha512(inner) => {
            let request = RegistrationRequest::<Ristretto255Sha512>::deserialize(&request)
                .map_err(to_py_err)?;
            let result = ServerRegistration::<Ristretto255Sha512>::start(
                inner,
                request,
                &credential_identifier,
            )
            .map_err(to_py_err)?;
            let message = result.message.serialize().to_vec();
            Ok(py_utils::to_pybytes(py, &message))
        }
        ServerSetupInner::P256Sha256(inner) => {
            let request =
                RegistrationRequest::<P256Sha256>::deserialize(&request).map_err(to_py_err)?;
            let result =
                ServerRegistration::<P256Sha256>::start(inner, request, &credential_identifier)
                    .map_err(to_py_err)?;
            let message = result.message.serialize().to_vec();
            Ok(py_utils::to_pybytes(py, &message))
        }
        ServerSetupInner::P384Sha384(inner) => {
            let request =
                RegistrationRequest::<P384Sha384>::deserialize(&request).map_err(to_py_err)?;
            let result =
                ServerRegistration::<P384Sha384>::start(inner, request, &credential_identifier)
                    .map_err(to_py_err)?;
            let message = result.message.serialize().to_vec();
            Ok(py_utils::to_pybytes(py, &message))
        }
        ServerSetupInner::P521Sha512(inner) => {
            let request =
                RegistrationRequest::<P521Sha512>::deserialize(&request).map_err(to_py_err)?;
            let result =
                ServerRegistration::<P521Sha512>::start(inner, request, &credential_identifier)
                    .map_err(to_py_err)?;
            let message = result.message.serialize().to_vec();
            Ok(py_utils::to_pybytes(py, &message))
        }
        ServerSetupInner::MlKem768Ristretto255Sha512(inner) => {
            let request = RegistrationRequest::<MlKem768Ristretto255Sha512>::deserialize(&request)
                .map_err(to_py_err)?;
            let result = ServerRegistration::<MlKem768Ristretto255Sha512>::start(
                inner,
                request,
                &credential_identifier,
            )
            .map_err(to_py_err)?;
            let message = result.message.serialize().to_vec();
            Ok(py_utils::to_pybytes(py, &message))
        }
    }
}

#[pyfunction(name = "finish_registration")]
#[pyo3(signature = (upload, suite=None))]
pub(crate) fn server_finish_registration(
    upload: Vec<u8>,
    suite: Option<String>,
) -> PyResult<PyServerRegistration> {
    let suite = parse_suite(suite.as_deref())?;
    server_finish_registration_with_suite(upload, suite)
}

pub(crate) fn server_finish_registration_with_suite(
    upload: Vec<u8>,
    suite: SuiteId,
) -> PyResult<PyServerRegistration> {
    match suite {
        SuiteId::Ristretto255Sha512 => {
            let upload = RegistrationUpload::<Ristretto255Sha512>::deserialize(&upload)
                .map_err(|err| registration_upload_err(err, &upload, suite))?;
            Ok(PyServerRegistration {
                inner: ServerRegistrationInner::Ristretto255Sha512(ServerRegistration::<
                    Ristretto255Sha512,
                >::finish(
                    upload
                )),
            })
        }
        SuiteId::P256Sha256 => {
            let upload = RegistrationUpload::<P256Sha256>::deserialize(&upload)
                .map_err(|err| registration_upload_err(err, &upload, suite))?;
            Ok(PyServerRegistration {
                inner: ServerRegistrationInner::P256Sha256(
                    ServerRegistration::<P256Sha256>::finish(upload),
                ),
            })
        }
        SuiteId::P384Sha384 => {
            let upload = RegistrationUpload::<P384Sha384>::deserialize(&upload)
                .map_err(|err| registration_upload_err(err, &upload, suite))?;
            Ok(PyServerRegistration {
                inner: ServerRegistrationInner::P384Sha384(
                    ServerRegistration::<P384Sha384>::finish(upload),
                ),
            })
        }
        SuiteId::P521Sha512 => {
            let upload = RegistrationUpload::<P521Sha512>::deserialize(&upload)
                .map_err(|err| registration_upload_err(err, &upload, suite))?;
            Ok(PyServerRegistration {
                inner: ServerRegistrationInner::P521Sha512(
                    ServerRegistration::<P521Sha512>::finish(upload),
                ),
            })
        }
        SuiteId::MlKem768Ristretto255Sha512 => {
            let upload = RegistrationUpload::<MlKem768Ristretto255Sha512>::deserialize(&upload)
                .map_err(|err| registration_upload_err(err, &upload, suite))?;
            Ok(PyServerRegistration {
                inner: ServerRegistrationInner::MlKem768Ristretto255Sha512(ServerRegistration::<
                    MlKem768Ristretto255Sha512,
                >::finish(
                    upload
                )),
            })
        }
    }
}

fn registration_upload_err<T: std::fmt::Display>(
    err: opaque_ke::errors::ProtocolError<T>,
    upload: &[u8],
    expected: SuiteId,
) -> PyErr {
    if registration_upload_matches_other_suite(upload, expected) {
        invalid_state_err("RegistrationUpload does not match this server instance")
    } else {
        to_py_err(err)
    }
}

fn registration_upload_matches_other_suite(upload: &[u8], expected: SuiteId) -> bool {
    [
        (
            SuiteId::Ristretto255Sha512,
            RegistrationUpload::<Ristretto255Sha512>::deserialize(upload).is_ok(),
        ),
        (
            SuiteId::P256Sha256,
            RegistrationUpload::<P256Sha256>::deserialize(upload).is_ok(),
        ),
        (
            SuiteId::P384Sha384,
            RegistrationUpload::<P384Sha384>::deserialize(upload).is_ok(),
        ),
        (
            SuiteId::P521Sha512,
            RegistrationUpload::<P521Sha512>::deserialize(upload).is_ok(),
        ),
        (
            SuiteId::MlKem768Ristretto255Sha512,
            RegistrationUpload::<MlKem768Ristretto255Sha512>::deserialize(upload).is_ok(),
        ),
    ]
    .into_iter()
    .any(|(suite, matches)| suite != expected && matches)
}

pub fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let module = py_utils::new_submodule(py, parent, "registration")?;

    let client = py_utils::new_submodule(py, &module, "client")?;
    client.add_function(wrap_pyfunction!(client_start_registration, &client)?)?;
    client.add_function(wrap_pyfunction!(client_finish_registration, &client)?)?;
    py_utils::add_submodule(py, &module, "client", &client)?;

    let server = py_utils::new_submodule(py, &module, "server")?;
    server.add_function(wrap_pyfunction!(server_start_registration, &server)?)?;
    server.add_function(wrap_pyfunction!(server_finish_registration, &server)?)?;
    py_utils::add_submodule(py, &module, "server", &server)?;

    py_utils::add_submodule(py, parent, "registration", &module)?;
    Ok(())
}
