use std::collections::HashSet;
use std::mem::transmute;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde_json::Value;

use crate::errors::Error;
use crate::network::Network;
use crate::settings::Settings;
use crate::wallet::Wallet;
use crate::GA_json;

#[derive(Debug)]
#[repr(C)]
pub struct GA_session {
    pub settings: Settings,
    pub network: Option<&'static Network>,
    pub wallet: Option<Wallet>,
    pub notify: Option<(
        extern "C" fn(*const libc::c_void, *const GA_json),
        *const libc::c_void,
    )>,
}

impl GA_session {
    fn new() -> *mut GA_session {
        let sess = GA_session {
            settings: Settings::default(),
            network: None,
            wallet: None,
            notify: None,
        };
        unsafe { transmute(Box::new(sess)) }
    }

    pub fn wallet(&self) -> Option<&Wallet> {
        self.wallet.as_ref()
    }

    pub fn wallet_mut(&mut self) -> Option<&mut Wallet> {
        self.wallet.as_mut()
    }

    pub fn tick(&mut self) -> Result<(), Error> {
        if let Some(ref mut wallet) = self.wallet {
            for msg in wallet.updates()? {
                self.notify(msg)
            }
        }
        Ok(())
    }

    // called when the wallet is initialized and logged in
    pub fn hello(&mut self) -> Result<(), Error> {
        self.notify(json!({ "event": "settings", "settings": self.settings }));
        self.tick()
    }

    pub fn notify(&self, data: Value) {
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
        Arc::new(Mutex::new(SessionManager {
            sessions: HashSet::new(),
        }))
    }

    pub fn register(&mut self) -> *mut GA_session {
        let sess = GA_session::new();
        debug!("SessionManager::register({:?})", sess);
        assert!(self.sessions.insert(sess));
        sess
    }

    pub fn get(&self, sess: *const GA_session) -> Result<&GA_session, Error> {
        if !self.sessions.contains(&(sess as *mut GA_session)) {
            throw!("session is unmanaged");
        };
        Ok(unsafe { &*sess })
    }

    pub fn get_mut(&self, sess: *mut GA_session) -> Result<&mut GA_session, Error> {
        if !self.sessions.contains(&sess) {
            throw!("session is unmanaged");
        }
        Ok(unsafe { &mut *sess })
    }

    pub fn remove(&mut self, sess: *mut GA_session) -> Result<(), Error> {
        debug!("SessionManager::remove({:?})", sess);
        if !self.sessions.remove(&sess) {
            throw!("session is unmanaged");
        }
        unsafe { drop(&*sess) };
        Ok(())
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

pub fn spawn_ticker(manager: Arc<Mutex<SessionManager>>) {
    thread::spawn(move || loop {
        manager.lock().unwrap().tick().expect("tick failed");
        thread::sleep(Duration::from_secs(5));
    });
}
