const fs = require('node:fs');
const path = require('node:path');

const out = __dirname;
const base = 'bfd-flower-power-lifecycle';
const W = 7600, H = 6570;
const P = {
  cream: '#FBF2DB', ink: '#462D42', orange: '#C95C31', gold: '#E7B747',
  teal: '#477B71', pink: '#CB7791', plum: '#735078', paper: '#FFFBEF',
  sage: '#E6EBD4', peach: '#F8DEBD', rose: '#F3DBDE', lilac: '#E9DFED',
  blue: '#DCEBE8', line: '#876251', muted: '#735F5E'
};
const cells = [], nodes = new Map(), sections = [], links = [];
let serial = 0;
const esc = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const html = s => esc(s).replace(/\n/g, '<br>');
function vertex(id, value, x, y, w, h, style, parent='1') {
  const p = nodes.get(parent);
  cells.push(`<mxCell id="${id}" value="${esc(value)}" style="${esc(style)}" vertex="1" parent="${parent}"><mxGeometry x="${x-(p?.x||0)}" y="${y-(p?.y||0)}" width="${w}" height="${h}" as="geometry"/></mxCell>`);
  nodes.set(id, {id, x,y,w,h,parent,value});
}
function text(id, value,x,y,w,h,size=26,color=P.ink,font='Segoe UI',bold=false,parent='1') {
  vertex(id, html(value), x,y,w,h,`text;html=1;whiteSpace=wrap;overflow=hidden;align=left;verticalAlign=middle;spacing=0;strokeColor=none;fillColor=none;fontFamily=${font};fontSize=${size};fontColor=${color};fontStyle=${bold?1:0};`,parent);
}
function panel(id,title,kicker,x,y,w,h,fill,color) {
  vertex(id,'',x,y,w,h,`rounded=1;arcSize=5;html=1;fillColor=${fill};strokeColor=${color};strokeWidth=4;container=1;collapsible=0;recursiveResize=0;`);
  text(id+'_title',title,x+70,y+38,w-140,65,37,color,'Cooper Black',false,id);
  text(id+'_sub',kicker,x+70,y+114,w-140,65,24,P.muted,'Segoe UI',false,id);
  const sec={id,title,kicker,x,y,w,h,fill,color,items:[]}; sections.push(sec); return sec;
}
function card(sec,id,title,body,x,y,w=600,h=280,fill=P.paper) {
  const value=`<div style="font-family:Segoe UI;font-size:25px;line-height:1.3;color:${P.ink}"><div style="font-family:Cooper Black;font-size:29px;color:${sec.color};margin-bottom:13px">${html(id+' / '+title)}</div><div>${html(body)}</div></div>`;
  vertex(id,value,x,y,w,h,`rounded=1;arcSize=13;whiteSpace=wrap;html=1;align=left;verticalAlign=middle;spacing=27;strokeWidth=2.4;strokeColor=${sec.color};fillColor=${fill};shadow=0;`,sec.id);
  const n=nodes.get(id); n.title=title; n.body=body; n.sec=sec; sec.items.push(n); return n;
}
function edge(from,to,label='',kind='flow',color=null) {
  if (!nodes.has(from)||!nodes.has(to)) throw Error(`Unknown edge ${from} -> ${to}`);
  const a=nodes.get(from), b=nodes.get(to);
  const parent=a.parent===b.parent?a.parent:'1';
  const c=color || (kind==='test'?P.plum:kind==='rpc'?P.orange:P.teal);
  const style=`edgeStyle=orthogonalEdgeStyle;rounded=1;orthogonalLoop=1;jettySize=28;html=1;endArrow=block;endFill=1;strokeWidth=${kind==='rpc'?5:kind==='test'?2.5:3};strokeColor=${c};fontColor=${c};fontSize=22;fontFamily=Segoe UI;labelBackgroundColor=${P.cream};labelBorderColor=none;${kind==='test'?'dashed=1;dashPattern=6 5;':''}${kind==='wire'?'startArrow=block;startFill=1;':''}`;
  cells.push(`<mxCell id="e${++serial}" value="${esc(label)}" style="${style}" edge="1" source="${from}" target="${to}" parent="${parent}"><mxGeometry relative="1" as="geometry"/></mxCell>`);
  links.push({from,to,label,kind});
}
function flower(cx,cy,r=100,c=P.pink,peace=false) {
  const id='flower'+(++serial);
  for(let i=0;i<10;i++) {
    const theta=i*Math.PI/5;
    vertex(`${id}p${i}`,'',cx+Math.cos(theta)*r*.63-r*.31,cy+Math.sin(theta)*r*.63-r*.6,r*.62,r*1.2,`ellipse;html=1;fillColor=${c};strokeColor=${P.ink};strokeWidth=2;rotation=${i*36+90};`);
  }
  vertex(id,'',cx-r*.38,cy-r*.38,r*.76,r*.76,`ellipse;html=1;fillColor=${P.gold};strokeColor=${P.ink};strokeWidth=3;`);
  if(peace) vertex(id+'peace','☮',cx-r*.33,cy-r*.34,r*.66,r*.66,`text;html=1;align=center;verticalAlign=middle;fontSize=${r*.53};fontFamily=Segoe UI Symbol;fontColor=${P.ink};`);
}

vertex('canvas','',0,0,W,H,`rounded=1;arcSize=2;html=1;fillColor=${P.cream};strokeColor=${P.ink};strokeWidth=16;`);
vertex('inner-border','',40,40,W-80,H-80,`rounded=1;arcSize=2;html=1;fillColor=none;strokeColor=${P.orange};strokeWidth=5;`);
flower(290,265,153,P.orange,true); flower(7310,265,153,P.pink,true);
text('masthead','BFD • THE WHOLE SOFTWARE TRIP',650,80,6300,172,119,P.orange,'Cooper Black');
text('tagline','PEACE, PACKETS & PROOF',1660,255,4400,68,55,P.plum,'Cooper Black');
text('subtitle','One functional map • runtime + connection tests + test harnesses + build, release & deployment',1070,347,5900,48,29,P.ink);
text('scope','Maintainers & operators  /  checkout bf3bda0 • package 6.0.1 • 23 OCT 2026  /  coverage map, not a claim that tests ran',1070,408,5900,45,25,P.muted);
text('legend','━━▶  flow, work or state     ◀━━▶  network exchange     ━━▶  orange: RPC call initiation; replies use the same call     ┄┄▶  purple: verifies',760,482,6300,42,25,P.ink);

const s=panel('seeds','01 / Plant the idea','Requirements → implementation → review → version',110,570,1640,1230,P.peach,P.orange);
card(s,'S1','Protocol & security contracts','RFC behavior, compatibility, supported roles\nTrust boundaries, performance, known limits',220,810,670,230);
card(s,'S2','Health integration proposal','PROPOSAL ONLY • no runtime implementation\nSeparate DNS/AD plugin host; broker AND rule',990,810,650,230,P.rose);
card(s,'S3','Reusable protocol library','Portable configuration, packet/auth codecs\nClassical/S-BFD state and stateless reflection',220,1140,670,230);
card(s,'S4','Contributor feedback loop','Implement → format → lint → test → rustdoc\nReview ownership, security & behavior receipts',990,1140,650,230);
card(s,'S5','Windows build environment','Pinned nightly + rust-src; locked dependencies\nx64 MSVC + Windows SDK; .NET/WiX tooling',220,1470,670,230);
card(s,'S6','Release compatibility decision','Judge the complete change set with SemVer\nFunctionality + migration impact in release notes\nvMAJOR.MINOR.PATCH; MSI numeric limits',990,1470,650,230);

const c=panel('ci','02 / Let the checks bloom','Three independent windows-2025 runners • same source and tag version',1830,570,2480,1230,P.sage,P.teal);
card(c,'C1','CI entry & version stamping','Pull requests to main or v* tag pushes → checkout → pinned toolchain\nPR uses package version; tag stamps service and both lockfiles',1940,810,2260,180);
card(c,'C2','ASan job','Select x64 compiler + matching runtime\nCompile sanitized graph; verify native hooks\nRun Rust/native tests; retain diagnostics',1940,1090,680,280);
card(c,'C3','Fuzz job','Audit, format, lint & harness regressions\nFour ASan campaigns: 15 s or 10,000 runs\nKeep crash inputs and logs',2730,1090,680,280);
card(c,'C4','Production build job','Audit + version/ACL/key/recovery fixtures\nOptimized tests + RPC/MI coexistence\nBuild, inspect and exercise installer lifecycle',3520,1090,680,280);
card(c,'C5','Separate build graphs','Tests unwind; ASan instruments tests\nProduction aborts on panic; normal release payload\nFuzz uses prebuilt std and its own workspace',1940,1470,1070,230);
card(c,'C6','Publication gate','Require ASan + fuzz + production job success\nSame tagged source; notes + asset checksum checks\nPR validation has read-only repository access',3120,1470,1080,230);

const p=panel('harvest','03 / Harvest & ship','Build ordinary release artifacts → validate lifecycle → publish verified assets',4390,570,3100,1230,P.rose,P.plum);
card(p,'P1','Hardened Rust graph','Service + dependencies + rebuilt standard library\nCFG, stack protection, checked arithmetic\nx64 ASLR/NX/EH-continuation/CET metadata',4500,810,850,280);
card(p,'P2','Native RPC build','Robust x64 MIDL → client/server C stubs\nMSVC C bridge + allocators + narrow SEH\nStatic library links Windows RPC runtime',5480,810,850,280);
card(p,'P3','Native resources & provenance','Event manifest + version resources\nStamp both executable versions\nRecord MSVC toolset and CRT versions',6460,810,850,280);
card(p,'P4','Production executables','BFD engine + BGP broker, panic=abort\nVerify PE protections and no ASan import\nNo release PDBs; match numeric versions',4500,1210,850,280);
card(p,'P5','Offline WiX/Burn bundle','Private x64 MSI + pinned Microsoft VC runtime\nCheck runtime signature/hash + compatibility\nEmbed binaries, events and administration tools',5480,1210,850,280);
card(p,'P6','Package inspection','Inspect MSI tables, ACLs, firewall and lifecycle\nCheck embedded payloads, version and runtime detection\nThen run disposable installation tests [10]',6460,1210,850,280);
card(p,'P7','Workflow artifacts','Setup + SHA-256: 30 days\nASan, fuzz, installer diagnostics: 14 days',4500,1550,850,190);
card(p,'P8','Tag-only publication','Separate job gets contents:write\nNotes required for release creation',5480,1550,850,190);
card(p,'P9','Published release','Setup executable + matching SHA-256 only\nPreserve published tags and existing assets',6460,1550,850,190);

const l=panel('host','04 / Host, boot & peers','Provision security before readiness',110,1920,1480,2450,P.peach,P.orange);
card(l,'L1','Remote BFD / S-BFD peers','IPv4 or IPv6 • 3784 single-hop / 4784 multihop\n7784 S-BFD requests; replies to initiator source port',220,2150,1260,170);
card(l,'L2','Elevated offline installation','Verify download hash → setup/runtime/MSI transaction\nProvision payload, service policy, ACLs, events & firewall',220,2375,1260,170);
card(l,'L3','Protected configuration & keys','Admin selects role, addresses, timers, auth, BGP target\nStopped-service key tool → machine DPAPI → protected Secrets',220,2600,1260,170);
card(l,'L4','Windows SCM issues service tokens','BFD starts independently; broker depends only on RpcSs\nDelayed auto start; minimum privilege and service-SID policy',220,2825,1260,170);
card(l,'L5','Fail-closed startup gates','Check exact account, enabled service SID and privileges\nBFD also checks restricting SIDs before resources or endpoints',220,3050,1260,170);
card(l,'L6','Worker and endpoint readiness','Validate configuration → initial observer → secure endpoints\nReport Running after bounded readiness; monitor starts afterward',220,3275,1260,170);
card(l,'L7','Separate operational states','SCM Running = service lifecycle; BFD Up = accepted probes\nRPC success and BGP Connected have independent meaning',220,3500,1260,170,P.sage);
card(l,'L8','Orderly stop / preshutdown','Close observer → announce AdminDown → finish final BGP action\nDrain RPC; bound cleanup; BFD preshutdown provisioned at 125 s',220,3725,1260,170);
card(l,'L9','Failure, recovery & restart','Transient socket faults back off while protocol timers continue\nFatal errors/crash use SCM recovery; ordinary Stop stays stopped',220,3950,1260,170);

const b=panel('bfd','05 / BfdWinService • the packet garden','LocalService + restricted BFD service SID • only SeChangeNotifyPrivilege • one mutable engine owner',1670,1920,2180,2450,P.blue,P.teal);
const bx=[1780,2460,3140], by=[2160,2590,3020,3450,3880];
card(b,'B1','UDP transport','Exclusive sockets; stable 49152–65535 source\nAncillary destination, interface, TTL/hop limit\nEvent-driven receive / stop / settings waits',bx[0],by[0]);
card(b,'B2','Path acceptance','Firewall is a separate kernel gate\nPeer / point-to-point, port, destination & interface\nSingle-hop TTL=255; optional MinTtl elsewhere',bx[1],by[0]);
card(b,'B3','Wire packet & auth','Header, length, flags and discriminators\nNone, password, meticulous MD5, keyed/meticulous SHA-1\nDigest/replay checks precede state updates',bx[2],by[0]);
card(b,'B4','Classical BFD','One asynchronous single-/multihop session\nDown → Init → Up; passive & Demand handling\nPoll/Final, learned discriminator & diagnostics',bx[0],by[1]);
card(b,'B5','S-BFD initiator','Provisioned remote discriminator; direct Up\nBounded outstanding probes + reply correlation\nReplay/expiry checks and anycast sources',bx[1],by[1]);
card(b,'B6','S-BFD reflector','One stateless listener, many initiators\nDemand/loop checks; reverse discriminator pair\nSequence reflection + bounded per-source replies',bx[2],by[1]);
card(b,'B7','Timer & work scheduler','Negotiated TX/RX, jitter, detection expiry\nPoll timing, suppression & congestion backoff\nReuse waits; bound receive and event work',bx[0],by[2]);
card(b,'B8','Single-owner engine','Selected protocol role owns accepted state\nRun receive, expiry, transmission & transitions\nFan out observations and optional BGP actions',bx[1],by[2],600,280,P.sage);
card(b,'B9','Transmit & socket recovery','Prepare → send → commit only on success\nFailed send keeps sequence/Poll/probe uncommitted\nReceive/wait recovery uses 10–250 ms backoff',bx[2],by[2]);
card(b,'B10','Settings updates','Registry notification reloads S-BFD timing\nReflector maintenance changes Up/AdminDown\nStartup role, key & BGP target need restart',bx[0],by[3]);
card(b,'B11','Immutable telemetry','Coherent ArcSwap snapshots; no reader lock\n100 ms change spacing / 1 s refresh target\nCounters publish on existing engine wakes',bx[1],by[3]);
card(b,'B12','BGP policy & mailbox','Optional; first Up enables Get / Start-if-stopped\nLater Down → Stop; AdminDown releases own Stop\nBounded latest Stop/Start pair; worker off engine',bx[2],by[3]);
card(b,'B13','Engine shutdown','Invalidate status observer immediately\nRole-permitted AdminDown announcements\nRelease own BGP Stop; finish bounded final action',bx[0],by[4]);
card(b,'B14','Bounded diagnostics','Lifecycle, communication, state, auth & errors\nBackground writer → ETW + optional file\nUTC lines; 64 MiB rotation + one backup',bx[1],by[4]);
card(b,'B15','Status RPC server','Read-only GetSessionStatusV1\nAuthorize broker; copy one fixed snapshot\nNo packet-loop query; unregister and drain',bx[2],by[4]);
text('bfd_limits','Multihop BGP requires meticulous authentication; reflectors reject BGP control. Classical Demand initiation, Echo, multipoint and discriminator signaling are unsupported.',1780,4220,1950,100,23,P.muted,'Segoe UI',false,b.id);

const r=panel('rpc','06 / Two local paths','Security checks apply to both',3930,1920,1050,2450,P.peach,P.orange);
card(r,'R1','Binding & server identity','ncalrpc only; WINNT + packet privacy\nStatic Identify/effective-only credentials\nV5 pins exact account AND service SID',4040,2160,830,280);
card(r,'R2','Endpoint & caller authorization','Protected service-SID ACLs\nEvery call: actual transport/auth + exact account\nEnabled service SID through Authz; no impersonation',4040,2590,830,280);
card(r,'R3','Native ownership & deadlines','Bounded records, admission and real async deadlines\nCancel/complete before freeing native call storage\nDeny runtime management; no reverse RPC callbacks',4040,3020,830,280);
card(r,'R4','BGP control → broker','BFD initiates Get / Start / Stop\nBfdWinService.Bgp.v2 • BgpControl 2.0\nRequest carries no caller-selected target',4040,3450,830,280,P.rose);
card(r,'R5','Session status → BFD','Broker initiates GetSessionStatusV1\nBfdWinService.Local.v2 • BfdLocal 2.0\nReplies return on the same initiated call',4040,3880,830,280,P.sage);
text('rpcnote','Orange arrows identify call initiation. Authorization callbacks are receiver-local checks.',4040,4250,830,60,23,P.muted,'Segoe UI',false,r.id);

const g=panel('broker','07 / BfdBgpBroker','SYSTEM + broker service SID • only SeChangeNotifyPrivilege',5060,1920,1530,2450,P.lilac,P.plum);
const gx=[5170,5870];
card(g,'G1','Broker COM/MI host','Verify own SCM-issued identity\nSet process COM security before provider use\nProvider runs as broker, without caller token',gx[0],by[0],610);
card(g,'G2','Protected fixed target','Read configured peer + routing domain\nGet / Start / Stop are the only operations\nNo public COM class factory or UDP listener',gx[1],by[0],610);
card(g,'G3','Native MI provider worker','Serialized local PS_BgpPeer requests\nGet / Start / Stop through MI + COM\nProvider identity stays the reduced SYSTEM token',gx[0],by[1],610);
card(g,'G4','Checked provider outcomes','Reject unknown/ambiguous connectivity\nStart/Stop require success and peer read-back\nCancellation cannot undo an executed operation',gx[1],by[1],610);
card(g,'G5','Bounded dispatcher','One admitted control manager + one queued request\nDiscard cancelled/expired work before execution\nIdle waits on request/stop events',gx[0],by[2],610);
card(g,'G6','Provider watchdog','20 s active request supervision\nCrash exit → SCM restart after 5 s\nPending failure retries; completed action not replayed',gx[1],by[2],610);
card(g,'G7','BGP control server','Authorize LocalService + BFD service SID\nAccept fixed operations for protected target\nRPC disconnect alone never changes the peer',gx[0],by[3],610);
card(g,'G8','Broker stop & diagnostics','Stop provider/telemetry supervision\nRetain unfinished native call storage\nOwn background ETW writer; 60 s stop budget',gx[1],by[3],610);
card(g,'G9','In-process telemetry worker','After Running, query BFD and validate reply\n2 s bind / 2 s call / 8 s supervision\nOne stalled worker is retained and quarantined',gx[0],by[4],610);
card(g,'G10','Checked observational cache','Validate complete record and freshness\nUnavailable/invalid/stale → no fabricated state\nCache never drives BGP; provider stays independent',gx[1],by[4],610,280,P.sage);
text('broker_note','Control retries use a dedicated BFD worker; provider and telemetry failure domains remain independent.',5170,4250,1310,55,23,P.muted,'Segoe UI',false,g.id);

const x=panel('outside','08 / Out in the world','Windows provider & observation',6670,1920,820,2450,P.sage,P.teal);
card(x,'X1','Windows RRAS / BGP','Native RemoteAccess MI provider\nWindows owns the BGP session\nThis project supplies local management',6780,2160,600,280);
card(x,'X2','Remote BGP peer','Windows-managed routing connection\nBGP wire authentication is deployed separately\nPeer state differs from BFD state',6780,2590,600,280);
card(x,'X3','Routes & service traffic','Withdraw/relearn routes when BGP changes\nAlternate path / anycast DNS can take traffic\nForwarding outcome needs lab verification',6780,3020,600,280);
card(x,'X4','Operators & monitoring','SCM state, Event Log, optional file output\nSession cache stays private inside the broker\nCorrelate BFD, provider and routing evidence',6780,3450,600,280);
card(x,'X5','Performance evidence','WPR ETW + process samples → WPA exports\nCPU, memory, context switches & ready time\nCapture matching health and source receipts',6780,3880,600,280);

const t=panel('tests','09 / Proof grows here • functional & connection harnesses','Purple dashed arrows name the boundaries checked • fixtures, sanitized tests and production artifacts have different scopes',110,4510,3740,1770,P.lilac,P.plum);
const tx=[220,1430,2640], ty=[4750,5120,5490,5860];
card(t,'T1','Portable protocol & configuration','Locked Cargo tests + optimized release tests\nRFC 5880 / 7419 / 7880; malformed/auth/replay cases\nState/timer, secrets, config and reflector invariants',tx[0],ty[0],1100,270);
card(t,'T2','Native UDP connection harness','Loopback engine + real IPv4/IPv6 sockets\nTTL, interface, ports, auth, Poll/Final and shutdown\nS-BFD anycast, multiple clients and live settings',tx[1],ty[0],1100,270);
card(t,'T3','Publication & telemetry pressure','Retain snapshots and run busy readers during UDP\nCheck freshness, invalid records, retry & quarantine\nVerify packet timing and engine progress',tx[2],ty[0],1100,270);
card(t,'T4','Token & service-entry fixtures','Process-isolated account/group/restricted tokens\nReject missing/disabled/deny-only SIDs and privileges\nSCM-only entry, malformed config, HKCU DPAPI fixtures',tx[0],ty[1],1100,270);
card(t,'T5','Dual RPC security connections','Authorized calls + anonymous/wrong identity rejection\nReplacement server, protocol/privacy & management denial\nCancellation, malformed records, native SEH, MI coexistence',tx[1],ty[1],1100,270);
card(t,'T6','BGP control/provider harness','Fake backend: flaps, supersession, timeout and cleanup\nNative MI fixtures validate provider contract\nOpt-in RRAS test reads an existing peer only',tx[2],ty[1],1100,270);
card(t,'T7','Production image evidence','Release harness inspects both normal executables\nx64 relocation/CFG/NX/ASLR, cookies, EH/CET metadata\nNo ASan imports; metadata does not prove host enforcement',tx[0],ty[2],1100,270);
card(t,'T8','PowerShell policy regressions','Version stamping, ACL and installer hardening models\nKey provisioning/read-back, rollback privileges\nRecovery isolation and native-runtime policy fixtures',tx[1],ty[2],1100,270);
card(t,'T9','ASan harness, end to end','Select compiler/runtime → compile without running\nCheck active build receipt + emitted native ASan hooks\nRun Rust/deps/std + maintained C/MIDL tests → logs',tx[2],ty[2],1100,270);
card(t,'T10','Fuzz inputs & mutation','Locked separate workspace → generate deterministic seeds\nStructured authenticated mutation + raw-byte fallback\nSynthetic public key bytes; bounded action sequences',tx[0],ty[3],1100,270);
card(t,'T11','Four ASan fuzz targets','packet • classical session • initiator • reflector\nCoverage-guided libFuzzer + explicit acceptance oracles\nIn-memory only; 5 s/input, 2 GiB, bounded run count/time',tx[1],ty[3],1100,270);
card(t,'T12','Failure → durable regression','Collect coverage/logs and preserve crash input\nReplay exact target/input → investigate → fix → regression\nKeep source receipts; rerun affected validation',tx[2],ty[3],1100,270);

const d=panel('deploy','10 / Installation & deployment harness, end to end','Sequential CI lifecycle suites • real installed state • hosted Windows runner or explicit disposable BFD-WS2025 VM',3930,4510,2660,1770,P.peach,P.orange);
const dx=[4040,4920,5800];
card(d,'D1','Isolate & prepare','Enforce disposable-host guard; admin\nCheckpoint VM; match payload/test revision\nPrebuilt tests can run without Rust in guest',dx[0],ty[0],680,270);
card(d,'D2','Inject MSI rollback','Fresh + preexisting-service fixtures\nFail after deferred policy mutation\nAbsent / empty / explicit privilege lists',dx[1],ty[0],680,270);
card(d,'D3','Check exact restoration','Accounts, dependencies, ACLs, SIDs\nPrivileges + recovery policy restored\nNo new payload, endpoint policy or firewall residue',dx[2],ty[0],680,270);
card(d,'D4','Fresh MSI installation','Inspect binaries, SCM policy & ACLs\nSecrets/Parameters/log directory ACLs\nFive executable-specific UDP firewall rules',dx[0],ty[1],680,270);
card(d,'D5','Configure & start independently','Provision DPAPI; corrupt/missing key fails\nExtra privilege startup rejection + recovery\nInspect actual SCM-issued running tokens',dx[1],ty[1],680,270);
card(d,'D6','Installed connections','Both RPC paths authenticate service identity\nUnrelated administrator caller is denied\nInstalled reflector source-port boundaries',dx[2],ty[1],680,270);
card(d,'D7','Observe & recover','Rendered ETW + file-output-off behavior\nCrash installed broker; verify SCM recovery\nBound failure diagnostics before cleanup',dx[0],ty[2],680,270);
card(d,'D8','Repair & remove','Retain config + encrypted key bytes\nRemove legacy dependency; recheck RPC/tokens\nRotate 64 MiB log; uninstall retains user logs',dx[1],ty[2],680,270);
card(d,'D9','Bundle maintenance','Runtime detect/install → repeat → repair\nRemove product; retain shared VC runtime\n3010 accepted without forced reboot',dx[2],ty[2],680,270);
card(d,'D10','Published-baseline upgrade','Download v2.0.0 setup + verify SHA-256\nInject failed upgrade → exact rollback\nThen successful upgrade + repair + key migration',dx[0],ty[3],680,270);
card(d,'D11','Preserve & restore','Compare bytes, versions, registration\nConfig, service policy, ACLs and logs\nRemove product; restore lab configuration',dx[1],ty[3],680,270);
card(d,'D12','Lifecycle receipts','Bounded service/event diagnostics on failure\nInstaller, bundle and upgrade logs/JSON\nSuccess completes production CI job',dx[2],ty[3],680,270,P.sage);

const q=panel('lab','11 / The wider trip','Separate lab work & feedback',6670,4510,820,1770,P.rose,P.plum);
card(q,'Q1','Deploy the lab','Windows RRAS + Ubuntu/BIRD peers\nMatch source, hashes, config & checkpoints\nManual/lab orchestration; separate from CI',6780,4750,600,270);
card(q,'Q2','Interoperability matrix','Authentication and protocol modes\nWindows/BIRD withdrawals + recoveries\nBGP-only controls; routes on both sides',6780,5120,600,270);
card(q,'Q3','Faults & restoration','Service/process interruption; adapter/packet faults\nLogging-disabled recovery; final route/stability checks\nRestore peers, routes, settings and lab checkpoint',6780,5490,600,270);
card(q,'Q4','Evidence → next change','Performance traces + health checks\nScenario results → docs & compatibility notes\nDefects → focused regressions → next review',6780,5860,600,270);

// Keep functional edges explicit; test relationships have one distinct line style.
edge('S2','S1','design input'); edge('S1','S3','contracts'); edge('S3','S4','change');
edge('S4','S5','build'); edge('S4','S6','impact'); edge('S5','C1','validate'); edge('S6','C1','tag version');
edge('C1','C2'); edge('C1','C3'); edge('C1','C4'); edge('C2','C5','test graph'); edge('C3','C5','fuzz graph');
edge('C2','C6','pass'); edge('C3','C6','pass'); edge('C4','P1','release graph');
edge('P2','P4','native library'); edge('P3','P4','resources'); edge('P1','P4','link');
edge('P4','P5','payload'); edge('P5','P6','inspect'); edge('P6','D1','exercise lifecycle');
edge('D12','P7','validated assets'); edge('D12','C6','build job pass'); edge('P7','P8','download');
edge('C6','P8','allow publish'); edge('P8','P9','publish'); edge('P9','L2','download & verify');
edge('L2','L3','configure'); edge('L3','L4','start'); edge('L4','L5','tokens'); edge('L5','L6','verified');
edge('L6','B8','run'); edge('L6','G1','broker ready'); edge('L7','X4','interpret');
edge('L8','B13','stop'); edge('L9','L4','recover'); edge('L3','B10','settings'); edge('L3','G2','fixed target');
edge('L1','B1','UDP','wire'); edge('B1','B2','datagram'); edge('B2','B3','validated path');
edge('B3','B4','classical'); edge('B3','B5','initiator'); edge('B3','B6','reflector');
edge('B4','B8','state'); edge('B5','B8','state'); edge('B6','B8','response'); edge('B7','B8','due work');
edge('B8','B9','send'); edge('B9','B1','datagram'); edge('B10','B7','timing'); edge('B10','B6','maintenance');
edge('B8','B11','publish'); edge('B8','B12','transitions'); edge('B8','B14','events'); edge('B8','B13','cleanup');
edge('B11','B15','immutable view'); edge('B13','B12','release own Stop');
edge('B12','R4','ncalrpc','rpc'); edge('R4','G7','initiate','rpc');
edge('G9','R5','ncalrpc','rpc'); edge('R5','B15','initiate','rpc'); edge('G9','G10','checked reply');
edge('R1','R2','authenticate'); edge('R2','R3','authorize'); edge('R3','R4','shared policy'); edge('R3','R5','shared policy');
edge('G1','G3','COM security'); edge('G2','G3','fixed target'); edge('G7','G5','admit');
edge('G5','G3','execute'); edge('G3','G4','read back'); edge('G6','G3','supervise'); edge('G6','L9','recover broker');
edge('G8','G9','stop supervisor'); edge('G8','G5','stop provider'); edge('G3','X1','COM / MI');
edge('X1','X2','BGP','wire'); edge('X2','X3','routes'); edge('B14','X4','diagnostics'); edge('G9','X4','RPC health events');
edge('X4','X5','capture'); edge('X3','Q1','verify externally'); edge('Q1','Q2','exercise'); edge('Q2','Q3','faults');
edge('Q3','Q4','record'); edge('X5','Q4','measurements'); edge('Q4','T12','regressions');
edge('T1','T2','native tests'); edge('T2','T3','load'); edge('T4','T5','identity fixtures'); edge('T5','T6','provider boundary');
edge('T7','T8','package policy'); edge('T8','T9','sanitized graph'); edge('T10','T11','mutate'); edge('T11','T12','crash / evidence');
edge('T12','S4','fix & recheck');
edge('T1','B4','RFC/state','test'); edge('T2','B1','UDP/path','test'); edge('T3','B11','publication','test');
edge('T4','L5','token policy','test'); edge('T5','R2','RPC gates','test'); edge('T6','G3','provider contract','test');
edge('T7','P4','PE metadata','test'); edge('T8','L2','installer policy','test'); edge('T9','P2','native memory','test');
edge('T11','B3','in-memory APIs','test'); edge('C2','T9','runs'); edge('C3','T10','runs'); edge('C4','T1','runs');
edge('D1','D2'); edge('D2','D3','rollback'); edge('D3','D4','fresh install'); edge('D4','D5'); edge('D5','D6');
edge('D6','D7','recovery'); edge('D7','D8'); edge('D8','D9'); edge('D9','D10','baseline'); edge('D10','D11'); edge('D11','D12','receipts');
edge('D5','L5','installed token','test'); edge('D6','R2','installed RPC','test'); edge('D8','B14','rotation','test');

for (const sec of sections) flower(sec.x+sec.w-65,sec.y+68,32,sec.color);

flower(270,6425,65,P.pink,true); flower(7325,6425,65,P.orange,true);
text('footer','ALL ONE CONNECTED GARDEN  •  design → checks → release → install → runtime → faults → evidence → next change',560,6355,6480,64,33,P.orange,'Cooper Black');
text('coverage_limits','Coverage limits: fuzz is in-memory; loopback does not establish external firewall enforcement or peer interoperability. Installer fixtures do not mutate a live RRAS peer.',560,6430,6480,40,24,P.ink);
text('proposal_limits','The proposed health/plugin agent is a design input only. Diagram shows inspected functionality and harness coverage; no validation or deployment was executed to create this artifact.',560,6480,6480,40,24,P.muted);

let xml=`<mxfile host="app.diagrams.net" agent="Codex" version="29.0.0"><diagram name="The whole software trip" id="bfd-flower-power"><mxGraphModel dx="7600" dy="6570" grid="0" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="0" page="0" pageScale="1" pageWidth="7600" pageHeight="6570" background="${P.cream}" math="0" shadow="0" adaptiveColors="auto"><root><mxCell id="0"/><mxCell id="1" parent="0"/>${cells.join('')}</root></mxGraphModel></diagram></mxfile>`;
// Required mechanical repair: trim wrappers, escape stray attribute characters, fix self-parented layers.
const match=xml.match(/<mxfile[\s\S]*?<\/mxfile>|<mxGraphModel[\s\S]*?<\/mxGraphModel>/);
if(match&&xml.trim()!==match[0])xml=match[0];
xml=xml.replace(/="([^"]*)"/g,(_,v)=>'="'+v.replace(/</g,'&lt;').replace(/&(?!(?:amp|lt|gt|quot|apos|#[0-9]+|#x[0-9a-fA-F]+);)/g,'&amp;')+'"');
xml=xml.replace(/<mxCell id="([^"]+)" parent="\1"\s*\/>/g,'<mxCell id="$1" parent="0"/>');
fs.writeFileSync(path.join(out,base+'.drawio'),xml);
fs.writeFileSync(path.join(out,'diagram-data.json'),JSON.stringify({width:W,height:H,palette:P,sections:sections.map(s=>({...s,items:s.items.map(({id,title,body,x,y,w,h})=>({id,title,body,x,y,w,h}))})),links},null,2));
let md='# BFD: the whole software trip\n\nFor maintainers and operators, this single diagram maps the implemented functionality, connection tests, test harnesses, and release/deployment lifecycle. It uses a 1960s flower-power palette, native editable shapes, and Cooper Black lettering.\n\n';
md+='Open [the editable diagram](bfd-flower-power-lifecycle.drawio) and zoom into a garden. The [SVG](bfd-flower-power-lifecycle.drawio.svg) scales without losing text detail; the [PNG](bfd-flower-power-lifecycle.drawio.png) is a poster preview.\n\n';
md+='![One connected flower-power diagram showing design, CI, packaging, services, UDP and RPC boundaries, BGP provider, functional tests, installer lifecycle tests, and separate interoperability and performance work.](bfd-flower-power-lifecycle.drawio.png)\n\n';
md+='Solid arrows show work, state, or lifecycle flow. Two-headed network arrows show exchanges. Orange RPC arrows show who initiates a call; replies use that call. Purple dashed arrows mean “verifies.” Node IDs connect the visual map to the text below.\n\n';
md+='Source scope: inspected checkout `bf3bda0`, package `6.0.1`, October 23, 2026, including local documentation. The health/plugin architecture is a proposal and has no implemented runtime path. Creating this map did not run product tests or change installed services.\n\n';
md+='Coverage limits: fuzz targets use in-memory APIs; loopback checks do not establish external firewall enforcement or peer interoperability. Installer fixtures use disposable hosts and do not mutate live RRAS peers. The Windows/BIRD interoperability and WPR/WPA flow is separate lab work, not a checked-in all-in-one CI harness.\n\n';
md+='The functional outline and complete connection list below provide the diagram content as text.\n\n';
for(const sec of sections){md+=`## ${sec.title}\n\n${sec.kicker}.\n\n`;for(const n of sec.items)md+=`- **${n.id}: ${n.title}.** ${n.body.replace(/\n/g,'. ')}.\n`;md+='\n';}
md+='## Connections\n\n| From | To | Relationship |\n| --- | --- | --- |\n';
for(const e of links)md+=`| ${e.from} | ${e.to} | ${e.kind==='test'?'Verifies: ':e.kind==='rpc'?'RPC initiation: ':''}${e.label||'Next stage'} |\n`;
md+='\n## Sources and regeneration\n\nBehavior was cross-checked against the implementation and the repository guides for [communication](../../docs/service-communication.md), [protocol](../../docs/protocol.md), [S-BFD](../../docs/seamless.md), [BGP](../../docs/bgp.md), [configuration](../../docs/configuration.md), [local RPC](../../docs/security/local-rpc.md), [build hardening](../../docs/security/build-hardening.md), [fuzzing](../../docs/security/fuzzing.md), [validation](../../docs/development/validation.md), [packaging](../../docs/development/packaging.md), [performance](../../docs/performance.md), and a separate local health integration proposal (design context only). CI sequencing comes from the checked-in workflow; installed checks come from the PowerShell lifecycle harnesses.\n\n';
md+='Run `node artifacts/bfd-flower-power-lifecycle/build-diagram.cjs` from the repository root to regenerate the diagram, content data, and this text. Then run `render-diagram.ps1` in this directory. It routes connectors without moving components, exports an embedded SVG and a PNG preview below the large-canvas raster limit, and embeds the title font once in the SVG. Retain the editable source.\n';
fs.writeFileSync(path.join(out,'README.md'),md);
console.log(JSON.stringify({diagram:path.join(out,base+'.drawio'),functionalNodes:sections.reduce((n,s)=>n+s.items.length,0),connections:links.length,width:W,height:H}));
