use std::collections::HashSet;
use std::mem::transmute;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use failure::Error;
use serde_json::Value;

use crate::wallet::Wallet;
use crate::GA_json;

#[derive(Debug)]
#[repr(C)]
pub struct GA_session {
    pub network: Option<String>,
    pub wallet: Option<Wallet>,
    pub notify: Option<(
        extern "C" fn(*const libc::c_void, *const GA_json),
        *const libc::c_void,
    )>,
}

// TODO protect access to raw GA_session pointers behind a mutex?

impl GA_session {
    pub fn new() -> *mut GA_session {
        let sess = GA_session {
            network: None,
            wallet: None,
            notify: None,
        };
        unsafe { transmute(Box::new(sess)) }
    }

    pub fn wallet(&self) -> Option<&Wallet> {
        self.wallet.as_ref()
    }

    pub fn tick(&mut self) -> Result<(), Error> {
        if let Some(ref mut wallet) = self.wallet {
            for msg in wallet.updates()? {
                self.notify(msg)
            }
        }
        Ok(())
    }

    fn notify(&self, data: Value) {
        debug!("push notification: {:?}", data);
        if let Some((handler, context)) = self.notify {
            handler(context, GA_json::new(data));
        } else {
            warn!("no registered handler to receive notification");
        }
    }
}

pub struct SessionManager {
    sessions: HashSet<*mut GA_session>,
}
unsafe impl Send for SessionManager {}

impl SessionManager {
    pub fn new() -> Arc<Mutex<Self>> {
        let manager = Arc::new(Mutex::new(SessionManager {
            sessions: HashSet::new(),
        }));

        // spawn a thread polling for updates every 5 seconds
        let t_manager = Arc::clone(&manager);
        thread::spawn(move || loop {
            t_manager.lock().unwrap().tick().expect("tick failed");
            thread::sleep(Duration::from_secs(5));
        });

        manager
    }

    pub fn register(&mut self, sess: *mut GA_session) -> Result<(), Error> {
        debug!("SessionManager::register({:?})", sess);
        if self.sessions.insert(sess) {
            Ok(())
        } else {
            bail!("session already registered")
        }
    }

    pub fn remove(&mut self, sess: *mut GA_session) -> Result<(), Error> {
        debug!("SessionManager::remove({:?})", sess);
        if self.sessions.remove(&sess) {
            unsafe { drop(&*sess) };
            Ok(())
        } else {
            bail!("session not registered")
        }
    }

    pub fn tick(&self) -> Result<(), Error> {
        info!("tick(), {} active sessions", self.sessions.len());
        for sess in &self.sessions {
            let sess = unsafe { &mut **sess };
            sess.tick()?;
        }
        Ok(())
    }
}
