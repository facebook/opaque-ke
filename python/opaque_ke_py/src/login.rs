use opaque_ke::rand::rngs::OsRng;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, CredentialFinalization, CredentialRequest,
    CredentialResponse, ServerLogin, ServerLoginParameters,
};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyModule};

use crate::errors::{invalid_login_err, invalid_state_err, to_py_err};
use crate::py_utils::per_suite_dispatch;
use crate::suite::{
    MlKem768Ristretto255Sha512, P256Sha256, P384Sha384, P521Sha512, Ristretto255Sha512, SuiteId,
    parse_suite,
};
use crate::types::{
    ClientLoginFinishParameters as PyClientLoginFinishParameters, ClientLoginState,
    ClientLoginStateInner, KeyStretching, ServerLoginParameters as PyServerLoginParameters,
    ServerLoginState, ServerLoginStateInner, ServerRegistration, ServerRegistrationInner,
    ServerSetup, ServerSetupInner,
};
use crate::{ensure_suite, py_utils};

fn build_server_login_params<'a>(
    params: Option<&'a PyRef<'a, PyServerLoginParameters>>,
) -> ServerLoginParameters<'a, 'a> {
    if let Some(params) = params {
        let identifiers = params
            .identifiers()
            .map(|ids| ids.as_opaque())
            .unwrap_or_default();
        ServerLoginParameters {
            context: params.context(),
            identifiers,
        }
    } else {
        ServerLoginParameters::default()
    }
}

#[pyfunction(name = "start_login")]
#[pyo3(signature = (password, suite=None))]
fn client_start_login(
    py: Python<'_>,
    password: Vec<u8>,
    suite: Option<String>,
) -> PyResult<(Py<PyBytes>, ClientLoginState)> {
    let suite = parse_suite(suite.as_deref())?;
    let mut rng = OsRng;
    per_suite_dispatch!(
        suite = suite,
        py = py,
        rng = rng,
        password = password,
        start = ClientLogin,
        state_type = ClientLoginState,
        state_inner = ClientLoginStateInner,
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

#[pyfunction(name = "finish_login")]
#[pyo3(signature = (state, password, response, params=None, suite=None))]
pub(crate) fn client_finish_login(
    py: Python<'_>,
    mut state: PyRefMut<'_, ClientLoginState>,
    password: Vec<u8>,
    response: Vec<u8>,
    params: Option<PyRef<'_, PyClientLoginFinishParameters>>,
    suite: Option<String>,
) -> PyResult<(Py<PyBytes>, Py<PyBytes>, Py<PyBytes>, Py<PyBytes>)> {
    let state_suite = state.suite_id();
    if let Some(requested) = suite {
        let requested = parse_suite(Some(requested.as_str()))?;
        ensure_suite(requested, state_suite, "ClientLoginState")?;
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
    let context = params
        .as_ref()
        .and_then(|params| params.context().map(|value| value.to_vec()));
    let expected_server_s_pk = params
        .as_ref()
        .and_then(|params| params.server_s_pk().map(|value| value.to_vec()));
    let mut rng = OsRng;
    match state_suite {
        SuiteId::Ristretto255Sha512 => {
            let state = state.take_ristretto()?;
            let response = CredentialResponse::<Ristretto255Sha512>::deserialize(&response)
                .map_err(to_py_err)?;
            let finish_params = ClientLoginFinishParameters::<Ristretto255Sha512>::new(
                context.as_deref(),
                opaque_identifiers,
                Some(&ksf),
            );
            let result = state
                .finish(&mut rng, &password, response, finish_params)
                .map_err(to_py_err)?;
            let server_s_pk = result.server_s_pk.serialize().to_vec();
            if let Some(expected) = expected_server_s_pk {
                if expected != server_s_pk {
                    return Err(invalid_login_err("server public key mismatch"));
                }
            }
            let message = result.message.serialize().to_vec();
            let session_key = result.session_key.to_vec();
            let export_key = result.export_key.to_vec();
            Ok((
                py_utils::to_pybytes(py, &message),
                py_utils::to_pybytes(py, &session_key),
                py_utils::to_pybytes(py, &export_key),
                py_utils::to_pybytes(py, &server_s_pk),
            ))
        }
        SuiteId::P256Sha256 => {
            let state = state.take_p256()?;
            let response =
                CredentialResponse::<P256Sha256>::deserialize(&response).map_err(to_py_err)?;
            let finish_params = ClientLoginFinishParameters::<P256Sha256>::new(
                context.as_deref(),
                opaque_identifiers,
                Some(&ksf),
            );
            let result = state
                .finish(&mut rng, &password, response, finish_params)
                .map_err(to_py_err)?;
            let server_s_pk = result.server_s_pk.serialize().to_vec();
            if let Some(expected) = expected_server_s_pk {
                if expected != server_s_pk {
                    return Err(invalid_login_err("server public key mismatch"));
                }
            }
            let message = result.message.serialize().to_vec();
            let session_key = result.session_key.to_vec();
            let export_key = result.export_key.to_vec();
            Ok((
                py_utils::to_pybytes(py, &message),
                py_utils::to_pybytes(py, &session_key),
                py_utils::to_pybytes(py, &export_key),
                py_utils::to_pybytes(py, &server_s_pk),
            ))
        }
        SuiteId::P384Sha384 => {
            let state = state.take_p384()?;
            let response =
                CredentialResponse::<P384Sha384>::deserialize(&response).map_err(to_py_err)?;
            let finish_params = ClientLoginFinishParameters::<P384Sha384>::new(
                context.as_deref(),
                opaque_identifiers,
                Some(&ksf),
            );
            let result = state
                .finish(&mut rng, &password, response, finish_params)
                .map_err(to_py_err)?;
            let server_s_pk = result.server_s_pk.serialize().to_vec();
            if let Some(expected) = expected_server_s_pk {
                if expected != server_s_pk {
                    return Err(invalid_login_err("server public key mismatch"));
                }
            }
            let message = result.message.serialize().to_vec();
            let session_key = result.session_key.to_vec();
            let export_key = result.export_key.to_vec();
            Ok((
                py_utils::to_pybytes(py, &message),
                py_utils::to_pybytes(py, &session_key),
                py_utils::to_pybytes(py, &export_key),
                py_utils::to_pybytes(py, &server_s_pk),
            ))
        }
        SuiteId::P521Sha512 => {
            let state = state.take_p521()?;
            let response =
                CredentialResponse::<P521Sha512>::deserialize(&response).map_err(to_py_err)?;
            let finish_params = ClientLoginFinishParameters::<P521Sha512>::new(
                context.as_deref(),
                opaque_identifiers,
                Some(&ksf),
            );
            let result = state
                .finish(&mut rng, &password, response, finish_params)
                .map_err(to_py_err)?;
            let server_s_pk = result.server_s_pk.serialize().to_vec();
            if let Some(expected) = expected_server_s_pk {
                if expected != server_s_pk {
                    return Err(invalid_login_err("server public key mismatch"));
                }
            }
            let message = result.message.serialize().to_vec();
            let session_key = result.session_key.to_vec();
            let export_key = result.export_key.to_vec();
            Ok((
                py_utils::to_pybytes(py, &message),
                py_utils::to_pybytes(py, &session_key),
                py_utils::to_pybytes(py, &export_key),
                py_utils::to_pybytes(py, &server_s_pk),
            ))
        }
        SuiteId::MlKem768Ristretto255Sha512 => {
            let state = state.take_kem()?;
            let response = CredentialResponse::<MlKem768Ristretto255Sha512>::deserialize(&response)
                .map_err(to_py_err)?;
            let finish_params = ClientLoginFinishParameters::<MlKem768Ristretto255Sha512>::new(
                context.as_deref(),
                opaque_identifiers,
                Some(&ksf),
            );
            let result = state
                .finish(&mut rng, &password, response, finish_params)
                .map_err(to_py_err)?;
            let server_s_pk = result.server_s_pk.serialize().to_vec();
            if let Some(expected) = expected_server_s_pk {
                if expected != server_s_pk {
                    return Err(invalid_login_err("server public key mismatch"));
                }
            }
            let message = result.message.serialize().to_vec();
            let session_key = result.session_key.to_vec();
            let export_key = result.export_key.to_vec();
            Ok((
                py_utils::to_pybytes(py, &message),
                py_utils::to_pybytes(py, &session_key),
                py_utils::to_pybytes(py, &export_key),
                py_utils::to_pybytes(py, &server_s_pk),
            ))
        }
    }
}

#[pyfunction(name = "start_login")]
#[pyo3(signature = (server_setup, password_file, request, credential_identifier, params=None, suite=None))]
pub(crate) fn server_start_login(
    py: Python<'_>,
    server_setup: PyRef<'_, ServerSetup>,
    password_file: PyRef<'_, ServerRegistration>,
    request: Vec<u8>,
    credential_identifier: Vec<u8>,
    params: Option<PyRef<'_, PyServerLoginParameters>>,
    suite: Option<String>,
) -> PyResult<(Py<PyBytes>, ServerLoginState)> {
    let setup_suite = server_setup.suite_id();
    let password_suite = password_file.suite_id();
    if setup_suite != password_suite {
        return Err(invalid_state_err(
            "ServerSetup and ServerRegistration use different cipher suites",
        ));
    }
    if let Some(requested) = suite {
        let requested = parse_suite(Some(requested.as_str()))?;
        ensure_suite(requested, setup_suite, "ServerSetup")?;
    }
    let mut rng = OsRng;
    let parameters = build_server_login_params(params.as_ref());
    match (&server_setup.inner, &password_file.inner) {
        (
            ServerSetupInner::Ristretto255Sha512(setup),
            ServerRegistrationInner::Ristretto255Sha512(reg),
        ) => {
            let request = CredentialRequest::<Ristretto255Sha512>::deserialize(&request)
                .map_err(to_py_err)?;
            let result = ServerLogin::<Ristretto255Sha512>::start(
                &mut rng,
                setup,
                Some(reg.clone()),
                request,
                &credential_identifier,
                parameters,
            )
            .map_err(to_py_err)?;
            let message = result.message.serialize().to_vec();
            Ok((
                py_utils::to_pybytes(py, &message),
                ServerLoginState {
                    inner: ServerLoginStateInner::Ristretto255Sha512(Some(result.state)),
                },
            ))
        }
        (ServerSetupInner::P256Sha256(setup), ServerRegistrationInner::P256Sha256(reg)) => {
            let request =
                CredentialRequest::<P256Sha256>::deserialize(&request).map_err(to_py_err)?;
            let result = ServerLogin::<P256Sha256>::start(
                &mut rng,
                setup,
                Some(reg.clone()),
                request,
                &credential_identifier,
                parameters,
            )
            .map_err(to_py_err)?;
            let message = result.message.serialize().to_vec();
            Ok((
                py_utils::to_pybytes(py, &message),
                ServerLoginState {
                    inner: ServerLoginStateInner::P256Sha256(Some(result.state)),
                },
            ))
        }
        (ServerSetupInner::P384Sha384(setup), ServerRegistrationInner::P384Sha384(reg)) => {
            let request =
                CredentialRequest::<P384Sha384>::deserialize(&request).map_err(to_py_err)?;
            let result = ServerLogin::<P384Sha384>::start(
                &mut rng,
                setup,
                Some(reg.clone()),
                request,
                &credential_identifier,
                parameters,
            )
            .map_err(to_py_err)?;
            let message = result.message.serialize().to_vec();
            Ok((
                py_utils::to_pybytes(py, &message),
                ServerLoginState {
                    inner: ServerLoginStateInner::P384Sha384(Some(result.state)),
                },
            ))
        }
        (ServerSetupInner::P521Sha512(setup), ServerRegistrationInner::P521Sha512(reg)) => {
            let request =
                CredentialRequest::<P521Sha512>::deserialize(&request).map_err(to_py_err)?;
            let result = ServerLogin::<P521Sha512>::start(
                &mut rng,
                setup,
                Some(reg.clone()),
                request,
                &credential_identifier,
                parameters,
            )
            .map_err(to_py_err)?;
            let message = result.message.serialize().to_vec();
            Ok((
                py_utils::to_pybytes(py, &message),
                ServerLoginState {
                    inner: ServerLoginStateInner::P521Sha512(Some(result.state)),
                },
            ))
        }
        (
            ServerSetupInner::MlKem768Ristretto255Sha512(setup),
            ServerRegistrationInner::MlKem768Ristretto255Sha512(reg),
        ) => {
            let request = CredentialRequest::<MlKem768Ristretto255Sha512>::deserialize(&request)
                .map_err(to_py_err)?;
            let result = ServerLogin::<MlKem768Ristretto255Sha512>::start(
                &mut rng,
                setup,
                Some(reg.clone()),
                request,
                &credential_identifier,
                parameters,
            )
            .map_err(to_py_err)?;
            let message = result.message.serialize().to_vec();
            Ok((
                py_utils::to_pybytes(py, &message),
                ServerLoginState {
                    inner: ServerLoginStateInner::MlKem768Ristretto255Sha512(Some(result.state)),
                },
            ))
        }
        _ => unreachable!("mismatched ServerSetup/ServerRegistration suites"),
    }
}

#[pyfunction(name = "finish_login")]
#[pyo3(signature = (state, finalization, params=None, suite=None))]
pub(crate) fn server_finish_login(
    py: Python<'_>,
    mut state: PyRefMut<'_, ServerLoginState>,
    finalization: Vec<u8>,
    params: Option<PyRef<'_, PyServerLoginParameters>>,
    suite: Option<String>,
) -> PyResult<Py<PyBytes>> {
    let state_suite = state.suite_id();
    if let Some(requested) = suite {
        let requested = parse_suite(Some(requested.as_str()))?;
        ensure_suite(requested, state_suite, "ServerLoginState")?;
    }
    let parameters = build_server_login_params(params.as_ref());
    match state_suite {
        SuiteId::Ristretto255Sha512 => {
            let state = state.take_ristretto()?;
            let finalization =
                CredentialFinalization::<Ristretto255Sha512>::deserialize(&finalization)
                    .map_err(to_py_err)?;
            let result = state.finish(finalization, parameters).map_err(to_py_err)?;
            let session_key = result.session_key.to_vec();
            Ok(py_utils::to_pybytes(py, &session_key))
        }
        SuiteId::P256Sha256 => {
            let state = state.take_p256()?;
            let finalization = CredentialFinalization::<P256Sha256>::deserialize(&finalization)
                .map_err(to_py_err)?;
            let result = state.finish(finalization, parameters).map_err(to_py_err)?;
            let session_key = result.session_key.to_vec();
            Ok(py_utils::to_pybytes(py, &session_key))
        }
        SuiteId::P384Sha384 => {
            let state = state.take_p384()?;
            let finalization = CredentialFinalization::<P384Sha384>::deserialize(&finalization)
                .map_err(to_py_err)?;
            let result = state.finish(finalization, parameters).map_err(to_py_err)?;
            let session_key = result.session_key.to_vec();
            Ok(py_utils::to_pybytes(py, &session_key))
        }
        SuiteId::P521Sha512 => {
            let state = state.take_p521()?;
            let finalization = CredentialFinalization::<P521Sha512>::deserialize(&finalization)
                .map_err(to_py_err)?;
            let result = state.finish(finalization, parameters).map_err(to_py_err)?;
            let session_key = result.session_key.to_vec();
            Ok(py_utils::to_pybytes(py, &session_key))
        }
        SuiteId::MlKem768Ristretto255Sha512 => {
            let state = state.take_kem()?;
            let finalization =
                CredentialFinalization::<MlKem768Ristretto255Sha512>::deserialize(&finalization)
                    .map_err(to_py_err)?;
            let result = state.finish(finalization, parameters).map_err(to_py_err)?;
            let session_key = result.session_key.to_vec();
            Ok(py_utils::to_pybytes(py, &session_key))
        }
    }
}

pub fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let module = py_utils::new_submodule(py, parent, "login")?;

    let client = py_utils::new_submodule(py, &module, "client")?;
    client.add_function(wrap_pyfunction!(client_start_login, &client)?)?;
    client.add_function(wrap_pyfunction!(client_finish_login, &client)?)?;
    py_utils::add_submodule(py, &module, "client", &client)?;

    let server = py_utils::new_submodule(py, &module, "server")?;
    server.add_function(wrap_pyfunction!(server_start_login, &server)?)?;
    server.add_function(wrap_pyfunction!(server_finish_login, &server)?)?;
    py_utils::add_submodule(py, &module, "server", &server)?;

    py_utils::add_submodule(py, parent, "login", &module)?;
    Ok(())
}
