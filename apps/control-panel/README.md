# Software KVM Link Console

The Link Console is the native macOS/Windows setup UI for the two-host alpha. It creates local
credentials, exchanges a public pairing card, writes the selected-only display topology, validates
the secure runtime profile, and starts or stops `kvm-runtime`. Private keys never appear in a
pairing card or in the UI.

## Build prerequisites

Install the stable Rust toolchain (including `rustfmt` and `clippy`) and Node.js 20 or newer on both
computers.

- macOS: install Xcode Command Line Tools. Before routing input, allow the built `kvm-runtime`
  executable in **System Settings → Privacy & Security → Accessibility** and **Input Monitoring**.
- Windows 11: install Visual Studio Build Tools with the Desktop development with C++ workload.
  WebView2 is included with Windows 11. Allow the runtime on **Private networks** if Windows
  Firewall prompts when it first listens on TCP port 24800.

## Run from source

From the repository root on each computer:

```sh
cargo build --locked -p kvm-runtime --release
cd apps/control-panel
npm ci
npm run tauri dev
```

The console automatically finds `target/release/kvm-runtime`. To use a different build, set
`SOFTWARE_KVM_RUNTIME` to its absolute path before starting the console.

## Pair the two computers

1. Put both computers on the same trusted private Wi-Fi network. A DHCP reservation for each
   computer is strongly recommended.
2. Open the Link Console on both computers and select each computer's Wi-Fi address.
3. Create the private identity on each computer.
4. Copy the public link card from the Mac to Windows and from Windows to the Mac. Paste and verify
   the opposite card on each computer. The card contains the public certificate, address, and
   display inventory—not the private key.
5. Choose the physical left/right arrangement on both computers, then write and validate the
   configuration.
6. Start Software KVM on both computers. Test with no keys or buttons held, then move through the
   configured screen edge.

The emergency escape is **Ctrl + Alt + Shift + Backspace**. Routing is fail-open: if the callback,
session, or native capture path cannot prove that an event was queued safely, that event remains on
the local computer. Closing the Link Console does not stop an active runtime; reopen it and use
**Stop routing safely**.

## Alpha limitations

- Exactly one Mac and one Windows computer are supported.
- Setup is selected-peer-only and manual card exchange; discovery and arbitrary multi-peer routing
  remain disabled.
- Capture is aggregate whole-host capture, not per-device routing.
- Installers and a bundled runtime sidecar are not produced yet; this workflow runs from source.
- Physical validation is still required for sleep/resume, secure desktop/UIPI, macOS event-tap
  recovery, high-rate pointer motion, and permission prompts before treating the build as daily-use
  reliable.

The browser-only `npm run dev` command renders a mock setup flow for interface development. It does
not create credentials or start routing; use `npm run tauri dev` for the real native console.
