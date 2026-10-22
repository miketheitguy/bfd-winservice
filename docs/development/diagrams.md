# Maintain the architecture diagrams

Cowabunga, diagram crew. Keep both views clear and aligned with the code.
Commands run from the repository root.

The [communication guide](../service-communication.md) embeds the runtime and
lifecycle diagrams. The
[RPC reference](../rpc-authentication.md#rpc-authentication-flow) embeds the
authentication diagram. Each diagram has separate PNG and Mermaid sections,
with the PNG first for GitHub mobile. Edit the fenced `mermaid` blocks to update
the Mermaid versions; each includes an accessible title and description.

Mermaid uses the Draw.io palette, white rounded process boundaries, rounded
cards, and shorter labels. Keep BFD blue, broker purple, authentication gates
amber, validated telemetry green, and Windows/peers gray. Put details in the
linked references rather than filling cards with API argument lists.

Cross-process Mermaid arrows attach to process boundaries to preserve vertical
card order. Their labels identify the operation and direction. Internal arrows
show work inside a process. This avoids Mermaid's
[subgraph direction limitation](https://mermaid.js.org/syntax/flowchart.html#direction-in-subgraphs).

The [draw.io source](../service-communication.drawio) contains the same three
views as editable pages. Keep the whole diagram lineup in sync: Mermaid blocks,
draw.io pages, exported PNGs, and nearby prose must match the implementation.
Check the rendered diagrams in a Mermaid-enabled Markdown preview, including
service identities, RPC arrow directions, endpoint versions, and native resource
ownership. Check that the embedded PNGs display in the Markdown pages and link
to the full-size images.

With draw.io Desktop installed in its default Windows location, export from the
repository root:

```powershell
& 'C:\Program Files\draw.io\draw.io.exe' -x -f png -e -p 1 -b 20 `
    -o docs/images/service-communication-runtime-v2-hardened.png `
    docs/service-communication.drawio
& 'C:\Program Files\draw.io\draw.io.exe' -x -f png -e -p 2 -b 20 `
    -o docs/images/service-communication-lifecycle-v2-hardened.png `
    docs/service-communication.drawio
& 'C:\Program Files\draw.io\draw.io.exe' -x -f png -e -p 3 -b 20 `
    -o docs/images/service-communication-authentication-v2-hardened.png `
    docs/service-communication.drawio
```

The page numbers are one-based. `-e` embeds editable XML in each PNG; retain the
`.drawio` source as well. The `-v2-hardened.png` filenames identify the
telemetry interface generation; keep all consuming links on these names.
Add `--disable-gpu` if export fails during GPU initialization. If you installed draw.io elsewhere, substitute its actual path.

Open all three images and check text, clipping, arrow direction, process
boundaries, and identity labels. Keep the RPC worker inside the broker
process. Show the snapshot and typed status path, and preserve the
BGP control RPC interface and COM/MI provider path. Label both service RPC
paths `ncalrpc` and use single-headed arrows for call initiation: broker to BFD
for session status, BFD to broker for BGP control. Replies return on the existing calls; neither
binding permits server-initiated RPC callbacks. Ensure every diagram has a
matching text explanation and useful alt text in the consuming Markdown page.
