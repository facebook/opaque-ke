/// Max. size of a noise package.
pub const MAX_NOISE_PKG_LEN: usize = 65535;

/// Extension methods aiming at making writing to / reading form Noise States
/// easier: this allocates output buffers w/o reuse.
pub trait StateIO {
    fn read_message(&mut self, message: &[u8], payload: &mut [u8]) -> Result<usize, snow::Error>;
    fn write_message(&mut self, message: &[u8], payload: &mut [u8]) -> Result<usize, snow::Error>;

    fn fread_message(&mut self, msg: &[u8]) -> Result<Vec<u8>, snow::Error> {
        let mut read_buf = vec![0; MAX_NOISE_PKG_LEN];
        let len = self.read_message(&msg, &mut read_buf)?;
        read_buf = read_buf[..len].to_vec();
        Ok(read_buf)
    }

    fn fwrite_message(&mut self, message: &[u8]) -> Result<Vec<u8>, snow::Error> {
        let mut out_buf = vec![0; MAX_NOISE_PKG_LEN];
        let len = self.write_message(message, &mut out_buf)?;
        out_buf = out_buf[..len].to_vec();
        Ok(out_buf)
    }
}

impl StateIO for snow::TransportState {
    fn read_message(&mut self, message: &[u8], payload: &mut [u8]) -> Result<usize, snow::Error> {
        self.read_message(message, payload)
    }

    fn write_message(&mut self, message: &[u8], payload: &mut [u8]) -> Result<usize, snow::Error> {
        self.write_message(message, payload)
    }
}

impl StateIO for snow::HandshakeState {
    fn read_message(&mut self, message: &[u8], payload: &mut [u8]) -> Result<usize, snow::Error> {
        self.read_message(message, payload)
    }

    fn write_message(&mut self, message: &[u8], payload: &mut [u8]) -> Result<usize, snow::Error> {
        self.write_message(message, payload)
    }
}
