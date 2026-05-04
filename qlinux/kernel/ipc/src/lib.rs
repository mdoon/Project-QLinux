#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(feature = "std_test")]
extern crate std;

use core::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use zeroize::Zeroize;

pub const MQ_CAPACITY:     usize = 32;
pub const MAX_MSG_PAYLOAD: usize = 256;
pub const PIPE_BUF_SIZE:   usize = 4096;

#[derive(Zeroize)]
pub struct Message {
    pub sender_tid:  u32,
    pub msg_type:    u32,
    pub payload_len: usize,
    pub payload:     [u8; MAX_MSG_PAYLOAD],
}

impl Message {
    pub const fn empty() -> Self {
        Self { sender_tid:0, msg_type:0, payload_len:0, payload:[0u8; MAX_MSG_PAYLOAD] }
    }
    pub fn set_payload(&mut self, data: &[u8]) -> Result<(), IpcError> {
        if data.len() > MAX_MSG_PAYLOAD { return Err(IpcError::PayloadTooLarge); }
        self.payload_len = data.len();
        self.payload[..data.len()].copy_from_slice(data);
        Ok(())
    }
    pub fn payload_bytes(&self) -> &[u8] { &self.payload[..self.payload_len] }
}

pub struct MessageQueue {
    buf:   [Message; MQ_CAPACITY],
    head:  AtomicUsize,
    tail:  AtomicUsize,
    count: AtomicUsize,
}

impl MessageQueue {
    pub const fn new() -> Self {
        const E: Message = Message::empty();
        Self { buf:[E; MQ_CAPACITY], head:AtomicUsize::new(0), tail:AtomicUsize::new(0), count:AtomicUsize::new(0) }
    }

    pub fn send(&mut self, msg: Message) -> Result<(), IpcError> {
        if self.count.load(Ordering::SeqCst) >= MQ_CAPACITY { return Err(IpcError::QueueFull); }
        let tail = self.tail.load(Ordering::Relaxed);
        self.buf[tail] = msg;
        self.tail.store((tail + 1) % MQ_CAPACITY, Ordering::Release);
        self.count.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    pub fn recv(&mut self) -> Result<Message, IpcError> {
        if self.count.load(Ordering::SeqCst) == 0 { return Err(IpcError::QueueEmpty); }
        let head = self.head.load(Ordering::Acquire);
        let msg = core::mem::replace(&mut self.buf[head], Message::empty());
        self.buf[head].zeroize();
        self.head.store((head + 1) % MQ_CAPACITY, Ordering::Release);
        self.count.fetch_sub(1, Ordering::SeqCst);
        Ok(msg)
    }

    pub fn len(&self)      -> usize { self.count.load(Ordering::Relaxed) }
    pub fn is_empty(&self) -> bool  { self.len() == 0 }
    pub fn is_full(&self)  -> bool  { self.len() >= MQ_CAPACITY }
}

pub struct Semaphore { count: AtomicI32, max: i32 }

impl Semaphore {
    pub const fn new(initial: i32, max: i32) -> Self { Self { count: AtomicI32::new(initial), max } }

    pub fn try_wait(&self) -> Result<(), IpcError> {
        let mut c = self.count.load(Ordering::Acquire);
        loop {
            if c <= 0 { return Err(IpcError::WouldBlock); }
            match self.count.compare_exchange_weak(c, c-1, Ordering::SeqCst, Ordering::Relaxed) {
                Ok(_)  => return Ok(()),
                Err(v) => c = v,
            }
        }
    }

    pub fn signal(&self) -> Result<(), IpcError> {
        self.count.fetch_update(Ordering::SeqCst, Ordering::Relaxed, |c| {
            if c < self.max { Some(c + 1) } else { None }
        }).map(|_| ()).map_err(|_| IpcError::SemaphoreOverflow)
    }

    pub fn count(&self) -> i32 { self.count.load(Ordering::Relaxed) }
}

pub struct Pipe { buf: [u8; PIPE_BUF_SIZE], head: usize, tail: usize, count: usize }

impl Pipe {
    pub const fn new() -> Self { Self { buf:[0u8; PIPE_BUF_SIZE], head:0, tail:0, count:0 } }

    pub fn write(&mut self, data: &[u8]) -> usize {
        let to_write = data.len().min(PIPE_BUF_SIZE - self.count);
        for &b in &data[..to_write] {
            self.buf[self.tail] = b;
            self.tail = (self.tail + 1) % PIPE_BUF_SIZE;
        }
        self.count += to_write;
        to_write
    }

    pub fn read(&mut self, dst: &mut [u8]) -> usize {
        let to_read = dst.len().min(self.count);
        for i in 0..to_read {
            dst[i] = self.buf[self.head];
            self.buf[self.head] = 0;
            self.head = (self.head + 1) % PIPE_BUF_SIZE;
        }
        self.count -= to_read;
        to_read
    }

    pub fn readable_bytes(&self) -> usize { self.count }
    pub fn is_empty(&self)       -> bool  { self.count == 0 }
}

#[derive(Debug, PartialEq, Eq)]
pub enum IpcError { QueueFull, QueueEmpty, WouldBlock, PayloadTooLarge, SemaphoreOverflow }

pub fn init() {}

#[cfg(all(test, feature = "std_test"))]
mod tests {
    use super::*;

    #[test]
    fn test_mq_send_recv() {
        let mut q = MessageQueue::new();
        let mut m = Message::empty();
        m.sender_tid = 42;
        m.set_payload(b"hello").unwrap();
        q.send(m).unwrap();
        let r = q.recv().unwrap();
        assert_eq!(r.sender_tid, 42);
        assert_eq!(r.payload_bytes(), b"hello");
    }

    #[test]
    fn test_semaphore() {
        let s = Semaphore::new(2, 4);
        s.try_wait().unwrap();
        s.try_wait().unwrap();
        assert_eq!(s.try_wait(), Err(IpcError::WouldBlock));
        s.signal().unwrap();
        assert_eq!(s.count(), 1);
    }

    #[test]
    fn test_pipe() {
        let mut p = Pipe::new();
        assert_eq!(p.write(b"world"), 5);
        let mut buf = [0u8; 5];
        assert_eq!(p.read(&mut buf), 5);
        assert_eq!(&buf, b"world");
        assert!(p.is_empty());
    }

    #[test]
    fn test_mq_full() {
        let mut q = MessageQueue::new();
        for i in 0..MQ_CAPACITY as u32 {
            let mut m = Message::empty(); m.msg_type = i;
            q.send(m).unwrap();
        }
        assert_eq!(q.send(Message::empty()), Err(IpcError::QueueFull));
    }
}
