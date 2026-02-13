use opaque_ke::errors::ProtocolError;
use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::PyModule;

use crate::py_utils;

create_exception!(opaque_ke.errors, OpaqueError, PyException);
create_exception!(opaque_ke.errors, InvalidLoginError, OpaqueError);
create_exception!(opaque_ke.errors, InvalidStateError, OpaqueError);
create_exception!(opaque_ke.errors, SerializationError, OpaqueError);
create_exception!(opaque_ke.errors, SizeError, OpaqueError);
create_exception!(opaque_ke.errors, ReflectedValueError, OpaqueError);
create_exception!(opaque_ke.errors, LibraryError, OpaqueError);

pub(crate) fn to_py_err<T: std::fmt::Display>(err: ProtocolError<T>) -> PyErr {
    match err {
        ProtocolError::InvalidLoginError => PyErr::new::<InvalidLoginError, _>(err.to_string()),
        ProtocolError::SerializationError => PyErr::new::<SerializationError, _>(err.to_string()),
        ProtocolError::SizeError { .. } => PyErr::new::<SizeError, _>(err.to_string()),
        ProtocolError::ReflectedValueError => PyErr::new::<ReflectedValueError, _>(err.to_string()),
        ProtocolError::LibraryError(_) | ProtocolError::Custom(_) => {
            PyErr::new::<LibraryError, _>(err.to_string())
        }
    }
}

pub(crate) fn invalid_state_err(message: &str) -> PyErr {
    PyErr::new::<InvalidStateError, _>(message.to_string())
}

pub(crate) fn invalid_login_err(message: &str) -> PyErr {
    PyErr::new::<InvalidLoginError, _>(message.to_string())
}

pub(crate) fn serialization_err(message: &str) -> PyErr {
    PyErr::new::<SerializationError, _>(message.to_string())
}

pub fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let module = py_utils::new_submodule(py, parent, "errors")?;
    module.add("OpaqueError", py.get_type_bound::<OpaqueError>())?;
    module.add(
        "InvalidLoginError",
        py.get_type_bound::<InvalidLoginError>(),
    )?;
    module.add(
        "InvalidStateError",
        py.get_type_bound::<InvalidStateError>(),
    )?;
    module.add(
        "SerializationError",
        py.get_type_bound::<SerializationError>(),
    )?;
    module.add("SizeError", py.get_type_bound::<SizeError>())?;
    module.add(
        "ReflectedValueError",
        py.get_type_bound::<ReflectedValueError>(),
    )?;
    module.add("LibraryError", py.get_type_bound::<LibraryError>())?;
    py_utils::add_submodule(py, parent, "errors", &module)?;
    Ok(())
}
