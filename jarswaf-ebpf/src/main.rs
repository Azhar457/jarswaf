#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_uid_gid},
    macros::{kprobe, map, xdp},
    maps::{HashMap, PerfEventArray},
    programs::{ProbeContext, XdpContext},
};
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecveEvent {
    pub pid: u32,
    pub uid: u32,
    pub command: [u8; 128],
}


#[map(name = "BLOCKLIST")]
static BLOCKLIST: HashMap<u32, u8> = HashMap::<u32, u8>::with_max_entries(10240, 0);

#[map(name = "RASP_EVENTS")]
static RASP_EVENTS: PerfEventArray<ExecveEvent> = PerfEventArray::new(0);

#[xdp]
pub fn jarswaf_ebpf(ctx: XdpContext) -> u32 {
    match try_jarswaf_ebpf(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

fn try_jarswaf_ebpf(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let source_ip = unsafe { (*ipv4hdr).src_addr }; // network byte order

    if unsafe { BLOCKLIST.get(&source_ip) }.is_some() {
        return Ok(xdp_action::XDP_DROP);
    }

    Ok(xdp_action::XDP_PASS)
}

#[kprobe]
pub fn jarswaf_rasp_exec(ctx: ProbeContext) -> u32 {
    match try_jarswaf_rasp_exec(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_jarswaf_rasp_exec(ctx: ProbeContext) -> Result<u32, i64> {
    let filename_ptr: *const u8 = ctx.arg(0).ok_or(1)?;
    
    let pid = bpf_get_current_pid_tgid() as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    
    let mut event = ExecveEvent {
        pid,
        uid,
        command: [0; 128],
    };
    
    let _ = unsafe { aya_ebpf::helpers::bpf_probe_read_user_str_bytes(filename_ptr, &mut event.command) };
    
    RASP_EVENTS.output(&ctx, &event, 0);
    
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
