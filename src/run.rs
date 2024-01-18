use error::Error;
use nix::fcntl::OFlag;
use nix::poll::{PollFd, PollFlags};
use nix::unistd::pipe2;
use std::cmp;
use std::collections::HashMap;
use std::os::fd::{AsFd, FromRawFd, OwnedFd};
use std::sync::mpsc::{Receiver, TryRecvError};
use std::sync::Arc;
use x11rb::connection::Connection;
use x11rb::protocol::xproto::{
    Atom, ChangeWindowAttributesAux, ConnectionExt, PropMode, Property, SelectionNotifyEvent,
    Window, SELECTION_NOTIFY_EVENT,
};
use x11rb::protocol::Event;
use {AtomEnum, EventMask};
use {Context, SetMap, INCR_CHUNK_SIZE};

macro_rules! try_continue {
    ( $expr:expr ) => {
        match $expr {
            Some(val) => val,
            None => continue,
        }
    };
}

// Owned fds drops on close, results in a PollHup
pub(crate) struct PipeWrite(OwnedFd);

pub(crate) struct PipeRead(OwnedFd);

pub(crate) fn create_drop_pipe() -> Result<(PipeRead, PipeWrite), Error> {
    let (read, write) = pipe2(OFlag::O_CLOEXEC).map_err(Error::PipeCreate)?;
    // Safety: Creating OwnedFds from owned fds (that were just created)
    unsafe {
        Ok((
            PipeRead(OwnedFd::from_raw_fd(read)),
            PipeWrite(OwnedFd::from_raw_fd(write)),
        ))
    }
}

struct IncrState {
    selection: Atom,
    requestor: Window,
    property: Atom,
    pos: usize,
}

pub fn run(
    context: &Arc<Context>,
    setmap: &SetMap,
    max_length: usize,
    receiver: &Receiver<Atom>,
    pipe_read: PipeRead,
) {
    let mut incr_map = HashMap::<Atom, Atom>::new();
    let mut state_map = HashMap::<Atom, IncrState>::new();
    let con_fd = context.connection.stream().as_fd();

    // Connection polled for new events, pipe polled for any, although it should be POLLHUP.
    let mut poll_fds = [
        PollFd::new(&con_fd, PollFlags::POLLIN),
        PollFd::new(&pipe_read.0, PollFlags::all()),
    ];

    // Poll with an indefinite timout
    while let Ok(_res) = nix::poll::poll(&mut poll_fds, -1) {
        // If it has a non-zero event, bail.
        if !matches!(poll_fds[1].revents().map(|pf| pf.bits()), Some(0)) {
            return;
        }

        loop {
            let Ok(maybe_event) = context.connection.poll_for_event() else {
                // Die on error
                return;
            };
            let Some(event) = maybe_event else {
                // Drained this poll-cycle
                break;
            };
            loop {
                match receiver.try_recv() {
                    Ok(selection) => {
                        if let Some(property) = incr_map.remove(&selection) {
                            state_map.remove(&property);
                        }
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        if state_map.is_empty() {
                            return;
                        }
                    }
                }
            }

            match event {
                Event::SelectionRequest(event) => {
                    let read_map = try_continue!(setmap.read().ok());
                    let &(target, ref value) = try_continue!(read_map.get(&event.selection));

                    if event.target == context.atoms.targets {
                        let _ = x11rb::wrapper::ConnectionExt::change_property32(
                            &context.connection,
                            PropMode::REPLACE,
                            event.requestor,
                            event.property,
                            Atom::from(AtomEnum::ATOM),
                            &[context.atoms.targets, target],
                        );
                    } else if value.len() < max_length - 24 {
                        let _ = x11rb::wrapper::ConnectionExt::change_property8(
                            &context.connection,
                            PropMode::REPLACE,
                            event.requestor,
                            event.property,
                            target,
                            value,
                        );
                    } else {
                        let _ = context.connection.change_window_attributes(
                            event.requestor,
                            &ChangeWindowAttributesAux::new()
                                .event_mask(EventMask::PROPERTY_CHANGE),
                        );
                        let _ = x11rb::wrapper::ConnectionExt::change_property32(
                            &context.connection,
                            PropMode::REPLACE,
                            event.requestor,
                            event.property,
                            context.atoms.incr,
                            &[0u32; 0],
                        );
                        incr_map.insert(event.selection, event.property);
                        state_map.insert(
                            event.property,
                            IncrState {
                                selection: event.selection,
                                requestor: event.requestor,
                                property: event.property,
                                pos: 0,
                            },
                        );
                    }
                    let _ = context.connection.send_event(
                        false,
                        event.requestor,
                        EventMask::default(),
                        SelectionNotifyEvent {
                            response_type: SELECTION_NOTIFY_EVENT,
                            sequence: 0,
                            time: event.time,
                            requestor: event.requestor,
                            selection: event.selection,
                            target: event.target,
                            property: event.property,
                        },
                    );
                    let _ = context.connection.flush();
                }
                Event::PropertyNotify(event) => {
                    if event.state != Property::DELETE {
                        continue;
                    };

                    let is_end = {
                        let state = try_continue!(state_map.get_mut(&event.atom));
                        let read_setmap = try_continue!(setmap.read().ok());
                        let &(target, ref value) = try_continue!(read_setmap.get(&state.selection));

                        let len = cmp::min(INCR_CHUNK_SIZE, value.len() - state.pos);
                        let _ = x11rb::wrapper::ConnectionExt::change_property8(
                            &context.connection,
                            PropMode::REPLACE,
                            state.requestor,
                            state.property,
                            target,
                            &value[state.pos..][..len],
                        );
                        state.pos += len;
                        len == 0
                    };

                    if is_end {
                        state_map.remove(&event.atom);
                    }
                    let _ = context.connection.flush();
                }
                Event::SelectionClear(event) => {
                    if let Some(property) = incr_map.remove(&event.selection) {
                        state_map.remove(&property);
                    }
                    if let Ok(mut write_setmap) = setmap.write() {
                        write_setmap.remove(&event.selection);
                    }
                }
                _ => (),
            }
        }
    }
}
