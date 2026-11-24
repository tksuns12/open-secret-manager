# Reaching devices on other networks

How a vault's devices reach each other when they are not on one network: a
phone on mobile data and the computer at home, or two computers in two
homes. This began as a design, written on 2026-10-12 for the owner to decide
on before Phase 16; the owner chose options A and B below, and both are
built. What is and is not verified is in
[implementation-status.md](implementation-status.md) ("Devices on other
networks"); the relay has been tried in process and in a Linux container,
and **not yet on a machine of its own on the internet**.

## What happens now

- Each device listens on TCP port 47820 (or any free port) over IPv6 and
  IPv4 alike, on one socket.
- An invitation names up to four addresses of the inviter: the IPv4 and
  IPv6 ones its route to the internet leaves from, then its other
  interfaces', such as a VPN's. Loopback, link-local and similar addresses
  are left out.
- Each device keeps up to eight addresses for each other device, best
  first, adding what members report and what an invitation named. A dial
  tries them in turn, each 300 ms after the one before unless that one has
  failed, and keeps the first that answers.
- With a relay set up (below), a device that cannot reach another directly
  reaches it through the relay.
- Nothing finds devices: there is no discovery, no port mapping on the
  router.

So with no VPN and no relay, two devices still sync only when one can open
a TCP connection to the other: on one home network, on a network that
gives devices global IPv6 addresses and lets the connection in, or with a
port forwarded on the router by hand. A phone that leaves the house syncs
again when it is back. A phone is never reachable from outside; it always
dials.

What stays, whatever is chosen: devices authenticate each other by the
pinned TLS certificates of their members, and an address only says where to
try (formats: "Addresses are advisory; the pin authenticates whatever
answers"). No server ever holds a key or plaintext. A vault used on one
network needs no server and no account.

## Joining from another network (Phase 21)

A new device can join a vault while away from every network the inviter is
on. The owner asks for an invitation "for a device away"; it carries the
vault's relay (address, pin, token) as well as the inviter's addresses, and
the joiner reaches the inviter through the relay when its addresses do not
answer. The new device then stays registered at the relay, so that the
vault's devices, which must also use the relay, reach it there while it is
enrolled and given its keys. The invitation then holds the relay's token (see
the threat model); the ordinary invitation, without the relay, is the
default and is what the released apps read. In the desktop's Devices panel, "Invite a
device" offers it when this computer is connected to the relay ("The new
device is away from your networks…"); a computer or a phone joins with such an
invitation as with any other (pasted, or a phone scans it), and keeps the
relay it names, in memory while it joins and in its peer store once it has
joined, until the vault's own has reached it. It is
also what `osm-peer` does (`invite away`, `join-device … -`). The phones'
screens only take such an invitation; they do not make one. An invitation is
only as good as the relay is reachable: the inviting computer must be
connected to it while the invitation is open, and so must the vault's other
voting devices for the enrollment to complete.

## What it was before Phase 16

A device listened on IPv4 only (`0.0.0.0`), an invitation named one
address, and each device kept one address for each other. The options
below were weighed against that.

## The options

**A. Several addresses per device, and IPv6.** Each device listens on IPv6
as well, names every address it has in invitations and rosters (the home
network's, a global IPv6 address, a VPN's such as Tailscale's `100.x` or a
WireGuard tunnel's), keeps several per device, and tries them in turn.
Nothing new to trust: addresses stay advice. With it, an owner who runs a
VPN between their devices, or whose network gives devices global IPv6
addresses and lets the connection in, needs nothing else. Without one,
nothing changes. *Size: small (the peer crate's address book and roster,
the two listeners, the invitation, tests).*

**B. A relay the owner runs.** A small program, `osm-relay`, on a machine
with a public address: a rented server, or a computer at home with one port
forwarded. Every device keeps a connection out to it while it syncs; a
device that cannot reach another directly asks the relay to join it to the
device with a given certificate pin, and the relay then only passes bytes
between them. The TLS session between the two devices runs inside, end to
end, with the same pins: the relay can neither read nor alter what passes,
nor pass for a device. It does see which devices (by pin) talk to each
other, when, and how much, which the threat model already counts as
routing metadata. To keep strangers off it, a device presents a relay
token, a random secret made when the owner sets the relay up and kept in
the vault (encrypted and synced like the backup note of Phase 15); a removed
device still holds it until the owner makes a new one, but can do nothing
with it except reach devices that will refuse it. Phones on mobile data and
computers in two homes reach each other this way, whatever their routers
do. *Size: medium (the relay program and its Linux package, a dial path
through it in the peer crate, the relay's address and token in the vault,
the desktop's setting, the phones' use of it, tests through a relay in
process and in the Linux container).* The owner has to run the machine.

**C. Hole punching.** A meeting point tells two devices each other's public
address and both send at once, so that their routers let the other in. It
works for many home routers over UDP, rarely over TCP, and not behind the
carrier-grade NAT most mobile networks use, so it would still need B as the
fallback, and it means moving the transport from TCP to QUIC. *Size: large.*
Not now.

**D. A mailbox.** Devices leave their encrypted revisions in storage the
owner has (a WebDAV folder, an S3 bucket, a server of their own) and pick
up the others', so a phone and a computer need not be online at the same
time, which matters with the phones' short background time. Revisions are
already signed and encrypted, but the control plane (Raft, the epoch keys a
removal hands out) needs live connections, and the mailbox would see item
IDs, revision sizes, and how often items change. *Size: large.* Worth
looking at only if live syncing through B proves too little for the phones.

**E. Port mapping on the router (UPnP, NAT-PMP).** The computer asks the
router to forward its port. Often turned off, no use behind carrier-grade
NAT, and it opens the listener to the whole internet. Not recommended.

## Recommendation (at the time)

Phase 16: A, then B.

A first, because it is small, adds nothing to trust, and on its own lets an
owner with a VPN (or open IPv6) sync from anywhere. B next, because it is
the one way that works for any network without a third party, at the cost
of a machine the owner runs. C, D, and E wait.

For B the threat model gains a section: what the relay sees, that it cannot
read, alter, or impersonate, that it can refuse to pass bytes (an outage,
not a breach), and what the relay token does and does not protect.

## What the owner decides

1. Whether to do A, A then B, or something else.
2. For B: whether there is a machine to run the relay on (a rented server,
   or a computer at home whose router can forward a port).
3. Whether a VPN such as Tailscale is already on the owner's devices; if it
   is, A alone may be enough, and it can be tried on the real devices.
4. Whether syncing while the computer is off (D) matters, or live syncing
   is enough.

## Decided (2026-10-12)

The owner chose A, then B (Phase 16). A VPN is already on the owner's
devices, so A can be tried on them. There is no machine for a relay yet:
B is built and tried here (in process, and with the relay in the Linux
container), and set up for real later.

## Setting up a relay (once there is a machine for it)

Not yet done on a real server: these steps are what the tests did on a
Mac and in a Linux container, written for one.

1. A machine every device can reach at one address or name: a rented
   Linux server, or a computer at home with TCP port 47830 forwarded to it
   on the router. Let TCP 47830 in through its firewall.
2. Build the relay there from this repository (Rust 1.95):
   `cargo build --release --locked -p osm-vault-peer --bin osm-relay`, and
   copy `target/release/osm-relay` to `/usr/local/bin`.
3. Run it with a folder of its own, where it listens, and where the devices
   reach it:
   `osm-relay /var/lib/osm-relay '[::]:47830' relay.example.org:47830`.
   On its first run it makes its TLS identity and its token in that folder,
   readable by its user only, and prints `RELAY-CODE OSM-RELAY1-…`. To keep
   it running, a systemd service such as:

   ```ini
   [Unit]
   Description=Open Secret Manager relay
   After=network-online.target

   [Service]
   ExecStart=/usr/local/bin/osm-relay /var/lib/osm-relay [::]:47830 relay.example.org:47830
   DynamicUser=yes
   StateDirectory=osm-relay
   Restart=on-failure

   [Install]
   WantedBy=multi-user.target
   ```

   and `journalctl -u osm-relay` shows the code.
4. In the desktop app, unlocked: Devices, then "On different networks?
   Reach your devices through a relay you run…", and paste the code. The
   panel then says whether this computer is connected to the relay. The
   other devices take the relay in with their next sync, while they can
   still reach each other directly, at home; from then on they use it
   whenever they cannot.
5. To shut out a device that was removed from the vault, or a code that
   got out: stop the relay, delete `token` in its folder, start it again,
   and paste the new code in the desktop app. Devices that have not synced
   since cannot use the relay until they have, at home.
   An invitation made for a device away (Phase 21) holds the relay's code, so
   one that got out, or was shown to someone who is then refused, is a reason to
   do this too.
6. To stop: Stop using it, in the same panel; the other devices stop with
   their next sync.
