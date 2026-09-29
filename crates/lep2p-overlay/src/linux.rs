//! Linux TUN device configured with the node's overlay IPv6 address.
//!
//! Creating and configuring a TUN device requires `CAP_NET_ADMIN` (run as
//! root, or grant the capability) and the kernel `tun` module
//! (`sudo modprobe tun`).

use crate::{RouteHooks, TunRead, TunWrite};
use async_trait::async_trait;
use std::io;
use std::net::Ipv6Addr;
use std::process::Command;
use std::sync::Arc;
use tun::AbstractDevice as _;

/// Installs and removes peer `/128` routes on a Linux TUN device via `ip`.
pub struct LinuxRouteHooks {
    device: String,
}

impl LinuxRouteHooks {
    pub fn new(device: impl Into<String>) -> Self {
        Self {
            device: device.into(),
        }
    }
}

impl RouteHooks for LinuxRouteHooks {
    fn route_added(&self, peer: Ipv6Addr) {
        let route = format!("{peer}/128");
        if let Err(e) = run_ip(&["-6", "route", "replace", &route, "dev", &self.device]) {
            tracing::warn!("failed to add overlay route {route}: {e}");
        }
    }

    fn route_removed(&self, peer: Ipv6Addr) {
        let route = format!("{peer}/128");
        if let Err(e) = run_ip(&["-6", "route", "del", &route, "dev", &self.device]) {
            tracing::debug!("failed to remove overlay route {route}: {e}");
        }
    }
}

/// A Linux TUN device with its overlay address configured.
pub struct LinuxTun {
    device: Arc<tun::AsyncDevice>,
    name: String,
}

impl LinuxTun {
    /// Create and configure a TUN device: overlay `/128` address, MTU, up.
    pub fn create(name: &str, overlay_ipv6: Ipv6Addr, mtu: u16) -> io::Result<Self> {
        let mut config = tun::Configuration::default();
        config.tun_name(name);
        let device = tun::create_as_async(&config).map_err(to_io)?;
        let actual = device.tun_name().unwrap_or_else(|_| name.to_string());

        // TUN devices inherit the host's IPv6 defaults; some hosts disable
        // IPv6 by default, which would break the overlay addressing.
        enable_ipv6(&actual)?;

        run_ip(&["link", "set", "dev", &actual, "mtu", &mtu.to_string()])?;
        run_ip(&[
            "-6",
            "addr",
            "add",
            &format!("{overlay_ipv6}/128"),
            "dev",
            &actual,
        ])?;
        run_ip(&["link", "set", "dev", &actual, "up"])?;

        Ok(Self {
            device: Arc::new(device),
            name: actual,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Reader half for an [`crate::OverlayNode`].
    pub fn reader(&self) -> LinuxTunReader {
        LinuxTunReader {
            device: self.device.clone(),
        }
    }

    /// Writer half for an [`crate::OverlayNode`].
    pub fn writer(&self) -> LinuxTunWriter {
        LinuxTunWriter {
            device: self.device.clone(),
        }
    }
}

/// Reader half of a [`LinuxTun`].
pub struct LinuxTunReader {
    device: Arc<tun::AsyncDevice>,
}

#[async_trait]
impl TunRead for LinuxTunReader {
    async fn read_packet(&mut self) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; 65_536];
        let n = self.device.recv(&mut buf).await?;
        buf.truncate(n);
        Ok(buf)
    }
}

/// Writer half of a [`LinuxTun`].
pub struct LinuxTunWriter {
    device: Arc<tun::AsyncDevice>,
}

#[async_trait]
impl TunWrite for LinuxTunWriter {
    async fn write_packet(&self, packet: &[u8]) -> io::Result<()> {
        let n = self.device.send(packet).await?;
        if n != packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "partial write to TUN device",
            ));
        }
        Ok(())
    }
}

/// Enable IPv6 on a freshly created interface (`disable_ipv6=0`).
fn enable_ipv6(device: &str) -> io::Result<()> {
    let path = format!("/proc/sys/net/ipv6/conf/{device}/disable_ipv6");
    if std::path::Path::new(&path).exists() {
        std::fs::write(&path, "0")?;
    }
    Ok(())
}

fn run_ip(args: &[&str]) -> io::Result<()> {
    let output = Command::new("ip").args(args).output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "ip {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

fn to_io(e: tun::Error) -> io::Error {
    io::Error::other(e)
}
