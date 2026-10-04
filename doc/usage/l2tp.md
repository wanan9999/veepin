# Running L2TP/IPsec

See the [README](../../README.md#run) for the one-time `CAP_NET_ADMIN` / `setcap`
setup that every TUN-based protocol needs.

## Connecting as an L2TP/IPsec client

`veepin connect l2tp` runs the whole stack in userspace: IKEv1 Main Mode with the
pre-shared key, Quick Mode for the ESP transport SA, then L2TP and PPP inside it.
The address, netmask and DNS all come from IPCP, so only credentials are
configured:

```sh
sudo ./veepin connect l2tp \
  -server vpn.example.com -psk secret -user alice -pass hunter2
```

## Running an L2TP/IPsec server

`veepin serve l2tp` is the responder for the same stack. One UDP socket serves
every client, demultiplexed by source address into a per-peer IKEv1 responder,
ESP SA, L2TP tunnel and PPP session; a shared TUN is routed by inner destination
address.

```sh
sudo ./veepin serve l2tp \
  -psk secret -user alice -pass hunter2 \
  -pool 10.20.0.0/24 -dns 1.1.1.1 -setup-nat -wan eth0
```

Both sides speak NAT traversal (RFC 3947/3948): Main Mode starts on UDP/500 and
floats to UDP/4500, where IKE rides behind the non-ESP marker alongside
UDP-encapsulated ESP. veepin always forces that float — it advertises itself as
being behind a NAT, exactly as strongSwan's `encap = yes` does — because its data
path is a userspace UDP socket with no raw-ESP fallback. A peer that never
advertises NAT-T is therefore rejected during Main Mode rather than left to fail
silently later. Both directions are verified in Docker against strongSwan +
xl2tpd.

## TunnelForge algorithm compatibility

The L2TP server accepts TunnelForge v0.7.4's AES-128-CBC / SHA-1 / MODP-2048
Main Mode offer and AES-128-CBC / HMAC-SHA1-96 transport-mode ESP offer. No
additional CLI flag is needed. AES-256 suites remain accepted and the veepin
client's default offers remain unchanged. 3DES is not enabled.

TunnelForge v0.7.4 completes Main Mode on UDP/500 and moves to UDP/4500 for
Quick Mode. This is a compatibility exception: RFC 3947 section 4 requires a
NAT-detecting initiator to float when sending MM5, not after MM6. Standard
clients retain that path. The server follows the authenticated IKE transport rather than sending
MM6 to a guessed client port 4500 as soon as NAT-T is negotiated. Clients that
float before MM5 or start on UDP/4500 remain supported. Exact retransmissions
receive the cached reply without advancing CBC state or resetting the timeout.
The initial endpoint is fixed at peer creation. Existing mappings change only
after IKE authentication, or after ESP integrity and anti-replay validation;
cookies, plaintext packets and cached IKE retries do not authorize rebinding.
After a verified float, old UDP/500 traffic is discarded. This fixes endpoint
tracking, not all authentication, rekey or lifecycle limitations of the stack.
`ignoring exchange type 2 while awaiting 32` alongside an MM6 timeout is a reason
to check this transport transition, not to change the PSK or expose UDP/1701.

The peer wire fixtures are pinned to TunnelForge commit
`bf3df64da2aa24c8b0ff379614dc991fa42f3f2a`, in
`android/app/src/main/cpp/ikev1.c` (`build_p1_sa`, `build_p2_esp_sa`). Unit tests
exercise Main Mode, Quick Mode and bidirectional ESP with those offers. A
separate strongSwan/xl2tpd cell restricts both phases to AES-128/SHA-1:

```sh
go test ./internal/ikev1 -run 'TestTunnelForge|TestAES128' -count=1 -v
go test ./internal/l2tp -run '^TestIKERepliesFollowObservedTransport$' -count=1 -v
go test ./internal/l2tp -run 'TestUnverifiedIKE|TestESPRebinding' -count=1 -v
cd tests/interop
docker compose -f compose.l2tp-server-aes128.yml down -v --remove-orphans
go test -tags interop -run '^TestInteropL2TPClientVeepinServerAES128$' -count=1 -v -timeout 15m .
```

The Docker test needs a Linux host with TUN, PPP and Docker Compose. It checks
the negotiated suites and a ping through PPP, not just a successful IKE SA.
It is an independent implementation using the same algorithms, **not** a
TunnelForge Android test. Phone acceptance still requires dialing the rebuilt
server, checking IPCP and `10.20.0.1`, then verifying IPv4 internet traffic and
DNS separately if NAT is configured. Long-lived connections/rekey, reconnects
and simultaneous clients require their own acceptance tests.

To deploy a local build, rebuild its image and recreate the existing service:

```sh
docker build -t veepin-local:tunnelforge .
# Set image: veepin-local:tunnelforge in your existing Compose file first.
docker compose up -d --force-recreate
docker compose logs -f
```

Preserve the public IP, credentials, UDP 500/4500 mappings and TUN/NET_ADMIN
settings. If `no acceptable IKE proposal offered` remains, verify the container
uses the rebuilt image and inspect the actual peer proposal. Passing this
algorithm regression does not resolve the implementation's other security or
lifecycle limitations.

## Downstream flow shaping

`-shape <bytes>` pads the first N bytes of each inner flow out to the tunnel
MTU, so the size pattern of a TLS handshake made *inside* the tunnel does not
survive encapsulation:

```sh
sudo ./veepin serve l2tp -shape 16384 ...
```

L2TP/IPsec nests PPP inside L2TP inside ESP, and the filler goes in the
innermost of those — the PPP Information field, which RFC 1661 §5.1 explicitly
allows to be padded up to the MRU and leaves the carried protocol to delimit (IP
does that with Total Length). Padding there rather than with ESP's own TFC
padding is what keeps the shaper reading the inner 5-tuple. **The client needs
no support for it**; it is verified in Docker against strongSwan + xl2tpd +
pppd, whose ping replies could not come back from a mis-trimmed packet.

Because the fingerprint it defends against targets handshakes, the budget is
spent per flow rather than per byte and bulk throughput is unaffected. It is off
by default. See [`doc/traffic-shaping.md`](../traffic-shaping.md) for what it
does and does not hide.
