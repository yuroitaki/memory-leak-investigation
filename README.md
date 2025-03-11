# Trying TLSN v0.1.0-alpha.8

Clone TLSN and checkout the tag `v0.1.0-alpha.8`:

```shell
git clone https://github.com/tlsnotary/tlsn.git tlsn-alpha.8
cd tlsn-alpha.8
git checkout v0.1.0-alpha.8
```

Run the Notary:

```shell
cd crates/notary/server/
cargo run --release -- --tls-enabled false
```

In the root of this repository run the app to perform notarization attempts:

```shell
cargo run --release
```

See the successful and failing attempts, similar to:

```log
Attempt 1 of 10
Starting an MPC TLS connection with the server
2025-03-11T21:43:32.471384Z ERROR mpc_tls::leader: error=internal error: "state error: must be in active or closed state to flush record layer"
2025-03-11T21:43:32.517259Z ERROR try_tlsn_alpha_8: connection closed before message completed

Attempt 2 of 10
Starting an MPC TLS connection with the server
2025-03-11T21:43:34.398229Z ERROR mpc_tls::leader: error=internal error: "state error: must be in active or closed state to flush record layer"
2025-03-11T21:43:34.445313Z ERROR try_tlsn_alpha_8: connection closed before message completed

Attempt 3 of 10
Starting an MPC TLS connection with the server
Got a response from the server: 200 OK
Notarization complete!
Notarization completed successfully!
The attestation has been written to `example-attestation.tlsn` and the corresponding secrets to `example-secrets.tlsn`.

Attempt 4 of 10
Starting an MPC TLS connection with the server
2025-03-11T21:43:40.400715Z ERROR mpc_tls::leader: error=internal error: "state error: must be in active or closed state to flush record layer"
2025-03-11T21:43:40.446192Z ERROR try_tlsn_alpha_8: connection closed before message completed

Attempt 5 of 10
Starting an MPC TLS connection with the server
2025-03-11T21:43:42.377165Z ERROR mpc_tls::leader: error=internal error: "state error: must be in active or closed state to flush record layer"
2025-03-11T21:43:42.419329Z ERROR try_tlsn_alpha_8: connection closed before message completed

Attempt 6 of 10
Starting an MPC TLS connection with the server
2025-03-11T21:43:44.206744Z ERROR mpc_tls::leader: error=internal error: "state error: must be in active or closed state to flush record layer"
2025-03-11T21:43:44.248321Z ERROR try_tlsn_alpha_8: connection closed before message completed

Attempt 7 of 10
Starting an MPC TLS connection with the server
2025-03-11T21:43:46.143305Z ERROR mpc_tls::leader: error=internal error: "state error: must be in active or closed state to flush record layer"
2025-03-11T21:43:46.186496Z ERROR try_tlsn_alpha_8: connection closed before message completed

Attempt 8 of 10
Starting an MPC TLS connection with the server
2025-03-11T21:43:48.099000Z ERROR mpc_tls::leader: error=internal error: "state error: must be in active or closed state to flush record layer"
2025-03-11T21:43:48.140716Z ERROR try_tlsn_alpha_8: connection closed before message completed

Attempt 9 of 10
Starting an MPC TLS connection with the server
Got a response from the server: 200 OK
Notarization complete!
Notarization completed successfully!
The attestation has been written to `example-attestation.tlsn` and the corresponding secrets to `example-secrets.tlsn`.

Attempt 10 of 10
Starting an MPC TLS connection with the server
2025-03-11T21:43:53.876759Z ERROR mpc_tls::leader: error=internal error: "state error: must be in active or closed state to flush record layer"
2025-03-11T21:43:53.916715Z ERROR try_tlsn_alpha_8: connection closed before message completed
```
