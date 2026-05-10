// ─── STATE ────────────────────────────────────────────────────
const STATE = {
  message: '',
  segments: [],
  currentSeg: 0,
  currentLayer: 0,
  expanded: false,
  model: 'osi',
  bitsMode: true,
  zoomSection: null,
  ipVersion: 4,
  linkMode: 'ethernet',
  transportMode: 'tcp',
};

const LAYER_NAMES = [
  'Application Layer',
  'Presentation Layer',
  'Session Layer',
  'Transport Layer',
  'Network Layer',
  'Data Link Layer (LLC)',
  'Data Link Layer (MAC)',
  'Physical Layer',
];
const TCPIP_LAYER_NAMES = [
  'Application Layer',
  'Transport Layer',
  'Internet Layer',
  'Network Access Layer',
];
const TCPIP_LAYER_COLORS = ['#4f8ef7','#3dd68c','#f5a623','#c97bf7'];
const LAYER_COLORS = ['#4f8ef7','#a78bfa','#f472b6','#3dd68c','#f5a623','#f75f5f','#c97bf7','#3dd6d6'];
const MSS = 40; // bytes per segment for demo clarity

// ─── DOM REFS ─────────────────────────────────────────────────
const inputScreen  = document.getElementById('input-screen');
const stackScreen  = document.getElementById('stack-screen');
const zoomPanel    = document.getElementById('zoom-panel');
const msgInput     = document.getElementById('msg-input');
const charCount    = document.getElementById('char-count');
const startBtn     = document.getElementById('start-btn');
const backBtn      = document.getElementById('back-btn');
const msgPreview   = document.getElementById('msg-preview');
const stackDiagram = document.getElementById('stack-diagram');
const layerNav     = document.getElementById('layer-nav');
const layerPrev    = document.getElementById('layer-prev');
const layerNext    = document.getElementById('layer-next');
const layerNameLbl = document.getElementById('layer-name-label');
const collapseBtn  = document.getElementById('collapse-btn');
const expandBtn    = document.getElementById('expand-btn');
const segNav       = document.getElementById('seg-nav');
const segPrev      = document.getElementById('seg-prev');
const segNext      = document.getElementById('seg-next');
const segLabel     = document.getElementById('seg-label');
const zoomClose    = document.getElementById('zoom-close');
const zoomTitle    = document.getElementById('zoom-title');
const zoomContent  = document.getElementById('zoom-content');

// ─── HELPERS ──────────────────────────────────────────────────
function strToBytes(s) {
  return s.split('').map(c => c.charCodeAt(0));
}
function bytesBin(bytes) {
  return bytes.map(b => b.toString(2).padStart(8,'0')).join(' ');
}
function checksum16(bytes) {
  let sum = bytes.reduce((a,b) => a+b, 0) & 0xffff;
  return '0x' + sum.toString(16).toUpperCase().padStart(4,'0');
}
function hex16(n) { return '0x' + (n & 0xffff).toString(16).toUpperCase().padStart(4,'0'); }
function hex32(n) { return '0x' + (n >>> 0).toString(16).toUpperCase().padStart(8,'0'); }
function randMac() {
  return Array.from({length:6},()=>Math.floor(Math.random()*256).toString(16).padStart(2,'0')).join(':');
}

// Segment message using MSS
function segmentMessage(msg) {
  const bytes = strToBytes(msg);
  const segs = [];
  for (let i=0; i<bytes.length; i+=MSS) {
    segs.push(bytes.slice(i,i+MSS).map(b=>String.fromCharCode(b)).join(''));
  }
  return segs.length ? segs : [''];
}

// Build packet data for a segment
function buildPacket(segText, segIndex, totalSegs) {
  const dataBytes  = strToBytes(segText);
  const dataLen    = dataBytes.length;
  // TCP header
  const srcPort    = 54321;
  const dstPort    = 80;
  const seqNum     = segIndex * MSS;
  const ackNum     = 0;
  const tcpLen     = 20; // bytes
  const tcpFlags   = segIndex === totalSegs-1 ? 'PSH|ACK' : 'ACK';
  const window     = 65535;
  const tcpCksum   = checksum16([...dataBytes, srcPort>>8, srcPort&0xff, dstPort>>8, dstPort&0xff]);
  // IP header
  const ipLen      = 20 + tcpLen + dataLen;
  const ipId       = hex16(0x1234 + segIndex);
  const ipTTL      = 64;
  const srcIp      = '192.168.1.10';
  const dstIp      = '10.0.0.1';
  const ipCksum    = checksum16([0x45,0x00,ipLen>>8,ipLen&0xff,0x12,0x34+segIndex]);
  // LLC
  const dsap       = '0xAA';
  const ssap       = '0xAA';
  const llcCtrl    = '0x03';
  const llcFcs     = checksum16([0xAA,0xAA,0x03,...dataBytes]);
  // MAC
  const srcMac     = '00:1a:2b:3c:4d:5e';
  const dstMac     = 'ff:ff:ff:ff:ff:ff';
  const etherType  = '0x0800';
  const macFcs     = checksum16([0x00,0x1a,0x2b,0x3c,...dataBytes]);
  // Physical
  const allBytes   = [0xAA,0xAA,0xAA,0xAA,0xAB, // preamble+SFD
    ...strToBytes(dstMac.replace(/:/g,'')),
    ...strToBytes(srcMac.replace(/:/g,'')),
    0x08,0x00,
    ...dataBytes,
    0x00,0x00,0x00,0x00];
  const preambleBytes = [0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAB];
    const dstMacBytes = dstMac.replace(/:/g,'').match(/.{2}/g).map(h=>parseInt(h,16));
    const srcMacBytes = srcMac.replace(/:/g,'').match(/.{2}/g).map(h=>parseInt(h,16));
    const etherTypeBytes = [0x08,0x00];
    const ipBytes = [0x45,0x00,ipLen>>8,ipLen&0xff,0x12,0x34+segIndex,0x40,0x00,ipTTL,0x06,...ipCksum.replace('0x','').match(/.{2}/g).map(h=>parseInt(h,16)),...srcIp.split('.').map(Number),...dstIp.split('.').map(Number)];
    const tcpBytes = [srcPort>>8,srcPort&0xff,dstPort>>8,dstPort&0xff,(seqNum>>>24)&0xff,(seqNum>>>16)&0xff,(seqNum>>>8)&0xff,seqNum&0xff,ackNum>>>24,(ackNum>>>16)&0xff,(ackNum>>>8)&0xff,ackNum&0xff,0x50,0x18,window>>8,window&0xff,...tcpCksum.replace('0x','').match(/.{2}/g).map(h=>parseInt(h,16)),0,0];
    const llcHeaderBytes = [0xAA,0xAA,0x03];
    const llcFcsBytes = llcFcs.replace('0x','').match(/.{2}/g).map(h=>parseInt(h,16));
    const macFcsBytes = macFcs.replace('0x','').match(/.{2}/g).map(h=>parseInt(h,16));
    const binarySegments = [
    { bytes: preambleBytes,   layer: 'mac-preamble' },
    { bytes: dstMacBytes,     layer: 'mac' },
    { bytes: srcMacBytes,     layer: 'mac' },
    { bytes: etherTypeBytes,  layer: 'mac' },
    { bytes: llcHeaderBytes,  layer: 'llc' },
    { bytes: ipBytes,         layer: 'ip' },
    { bytes: tcpBytes,        layer: 'tcp' },
    { bytes: dataBytes,       layer: 'data' },
    { bytes: llcFcsBytes,     layer: 'llc' },
    { bytes: macFcsBytes,     layer: 'mac' },
    ];
    const binaryStr = binarySegments.map(s=>s.bytes.map(b=>b.toString(2).padStart(8,'0')).join('')).join('');
    const binaryAnnotated = binarySegments;

    return {
        segText, dataBytes, dataLen, segIndex, totalSegs,
        tcp: { srcPort, dstPort, seqNum, ackNum, tcpLen, tcpFlags, window, tcpCksum },
        ip:  { ipLen, ipId, ipTTL, srcIp, dstIp, ipCksum },
        llc: { dsap, ssap, llcCtrl, llcFcs },
        mac: { srcMac, dstMac, etherType, macFcs },
        binaryStr,
        binaryAnnotated,
    };
}

// ─── SHOW / HIDE SCREENS ──────────────────────────────────────
function showScreen(id) {
  document.querySelectorAll('.screen').forEach(s => {
    s.classList.toggle('active', s.id === id);
  });
}

function openZoom(section, pkt) {
  zoomPanel.classList.add('visible');
  STATE.zoomSection = section;
  renderZoom(section, pkt);
}
function closeZoom() {
  zoomPanel.classList.remove('visible');
}

// ─── RENDER STACK ─────────────────────────────────────────────
function renderStack() {
  const pkt = buildPacket(
    STATE.segments[STATE.currentSeg],
    STATE.currentSeg,
    STATE.segments.length
  );
  stackDiagram.innerHTML = '';
  const layers = buildLayerRows(pkt);
  layers.forEach((row, i) => {
    const div = document.createElement('div');
    div.className = 'layer-row' +
      (i === STATE.currentLayer ? ' current' : '') +
      (i < STATE.currentLayer ? ' visited' : '');
    div.dataset.layer = i;
    div.innerHTML = row;
    div.addEventListener('click', (e) => {
      if (!e.target.closest('.pkt-section') && !e.target.closest('.field-val') && !e.target.closest('.row-toggle')) {
        STATE.currentLayer = i;
        renderStack();
        updateLayerUI();
      }
    });
    stackDiagram.appendChild(div);
  });

  // Attach section click handlers
  document.querySelectorAll('.pkt-section[data-section], .field-val[data-section]').forEach(el => {
    el.addEventListener('click', (e) => {
      e.stopPropagation();
      const sec = el.dataset.section;
      if (sec) openZoom(sec, pkt);
    });
  });
  document.querySelectorAll('.layer-label-btn[data-layer-info]').forEach(el => {
    el.addEventListener('click', (e) => {
      e.stopPropagation();
      const info = el.dataset.layerInfo;
      if (info.startsWith('tcpip-')) {
        openTCPIPLayerInfo(parseInt(info.split('-')[1]), pkt);
      } else {
        openLayerInfo(parseInt(info), pkt);
      }
    });
  });

  // Scroll current layer into view
  const currentRow = stackDiagram.querySelector('.layer-row.current');
  if (currentRow && !STATE.suppressScroll) currentRow.scrollIntoView({ behavior:'smooth', block:'nearest' });
  STATE.suppressScroll = false;
}

function buildLayerRows(pkt) {
  if (STATE.model === 'tcpip') return buildTCPIPLayerRows(pkt);
  const rows = [];
  rows.push(buildAppRow(pkt, 0));
  rows.push(buildAppRow(pkt, 1));
  rows.push(buildAppRow(pkt, 2));
  rows.push(buildTransportRow(pkt));
  rows.push(buildNetworkRow(pkt));
  rows.push(buildLLCRow(pkt));
  rows.push(buildMACRow(pkt));
  rows.push(buildPhysicalRow(pkt));
  return rows;
}

function buildTCPIPLayerRows(pkt) {
  const rows = [];
  // 0: Application (covers OSI App+Presentation+Session)
  const appContent = STATE.expanded
    ? dataSection(pkt.segText, true, true)
    : dataSection(pkt.segText);
  rows.push(tcpipLabelCol(0) + `<div class="layer-content-col">${appContent}</div>`);
  // 1: Transport — reuse buildTransportRow
  rows.push(tcpipLabelCol(1) + buildTransportRow(pkt).substring(buildTransportRow(pkt).indexOf('<div class="layer-content-col"')));
  // 2: Internet
  const iContent = STATE.expanded
    ? ipExpandedFields(pkt) + tcpExpandedFields(pkt) + expandedGroup('Data','#4f8ef7',`<div class="pkt-section sec-data" data-section="data-2" style="width:100%;box-sizing:border-box">${escHtml(pkt.segText)}</div>`)
    : ipHdrBlock() + tcpHdrBlock() + dataSection(pkt.segText, true, false, 'data-2');
  rows.push(tcpipLabelCol(2) + `<div class="layer-content-col" style="flex-wrap:wrap;align-items:flex-start">${iContent}</div>`);
  // 3: Network Access — reuse buildMACRow but with tcpip label
  const naRow = buildMACRow(pkt);
  // swap the OSI label col for tcpip label col
  rows.push(tcpipLabelCol(3) + naRow.substring(naRow.indexOf('<div class="layer-content-col"')));
  return rows;
}

function tcpipLabelCol(index) {
  const names    = ['Application','Transport','Internet','Network Access'];
  const protos   = ['HTTP·FTP·SMTP·DNS·DHCP·SNMP·RTP·Telnet','TCP·UDP·RTP·RTCP','IP·ICMP·IGMP·ARP·RARP','Ethernet·WiFi·PPP·SLIP'];
  const pdus     = ['Data','Segment','Packet','Frame'];
  const col      = TCPIP_LAYER_COLORS[index];
  return `<div class="layer-label-col layer-label-btn" data-layer-info="tcpip-${index}" style="border-color:${col}33;cursor:pointer" title="Click to learn about this layer">
    <span class="layer-name" style="color:${col}"><span class="ldot" style="background:${col}"></span>${names[index]}</span>
    <span class="layer-sublabel" style="color:${col}99">${protos[index]}</span>
    <span class="layer-pdu" style="color:${col}66">${pdus[index]}</span>
  </div>`;
}

function labelCol(index) {
  const layerNames = ['Application','Presentation','Session','Transport','Network','LLC','MAC','Physical'];
  const protocols  = ['HTTP · DNS · FTP','TLS · JPEG · ASCII','NetBIOS · RPC · PPTP','TCP · UDP · QUIC','IP · ICMP · OSPF','IEEE 802.2 · SNAP','IEEE 802.3 · 802.11','NRZ · Manchester · PAM4'];
  const pdus       = ['Data','Data','Data','Segment','Packet','Frame','Frame','Bits'];
  const col        = LAYER_COLORS[index];
  return `<div class="layer-label-col layer-label-btn" data-layer-info="${index}" style="border-color:${col}33;cursor:pointer" title="Click to learn about this layer">
    <span class="layer-name" style="color:${col}"><span class="ldot" style="background:${col}"></span>${layerNames[index]}</span>
    <span class="layer-sublabel" style="color:${col}99">${protocols[index]}</span>
    <span class="layer-pdu" style="color:${col}66">${pdus[index]}</span>
  </div>`;
}

function dataSection(text, clickable=true, fullWidth=false, section='data') {
  const disp = !fullWidth && text.length > 24 ? text.slice(0,22)+'…' : text;
  return `<div class="pkt-section sec-data${clickable?' clickable':''}" data-section="${section}" title="Click to inspect data" style="${fullWidth?'width:100%;box-sizing:border-box;':''}">` + escHtml(disp) + `</div>`;
}

// ── Collapsed helpers
function encapBlock(label, color, section) {
  const sec = section || '';
  return `<div class="pkt-section${sec?' clickable':''}" data-section="${sec}" style="background:${color}18;color:${color};border:1px solid ${color}33;padding:0 10px;height:100%;display:flex;align-items:center;font-family:var(--font-mono);font-size:10px;border-radius:3px;opacity:0.7">${label}</div>`;
}
function udpHdrBlock() {
  return `<div class="pkt-section sec-udp clickable" data-section="udp">UDP Header</div>`;
}
function tcpHdrBlock() {
  return `<div class="pkt-section sec-tcp clickable" data-section="tcp">TCP Header</div>`;
}
function ipHdrBlock() {
  return `<div class="pkt-section sec-ip clickable" data-section="ip">IP Header</div>`;
}
function llcHdrBlock() {
  return `<div class="pkt-section sec-llc-h clickable" data-section="llc-header">LLC Header</div>`;
}
function llcTrlBlock() {
  return `<div class="pkt-section sec-llc-t clickable" data-section="llc-trailer">LLC Trailer</div>`;
}
function macHdrBlock() {
  return `<div class="pkt-section sec-mac-h clickable" data-section="mac-header">MAC Header</div>`;
}
function macTrlBlock() {
  return `<div class="pkt-section sec-mac-t clickable" data-section="mac-trailer">MAC Trailer</div>`;
}

// ── Expanded helpers
function expandedGroup(label, color, fieldsHtml) {
  return `<div style="width:100%;margin-bottom:6px;border:1px solid ${color}33;border-radius:5px;overflow:hidden">
    <div style="background:${color}18;padding:3px 8px;font-family:var(--font-mono);font-size:9px;letter-spacing:0.1em;color:${color};text-transform:uppercase;border-bottom:1px solid ${color}22">${label}</div>
    <div style="display:flex;flex-wrap:wrap;gap:4px;padding:6px 8px;background:var(--bg3)">${fieldsHtml}</div>
  </div>`;
}

function tcpExpandedFields(pkt) {
  const t = pkt.tcp;
  const fields = [
    ['Src Port',t.srcPort,dispBits(16)],
    ['Dst Port',t.dstPort,dispBits(16)],
    ['Seq #',t.seqNum,dispBits(32)],
    ['Ack #',t.ackNum,dispBits(32)],
    ['Hdr Len','5',dispBits(4)],
    ['Flags',t.tcpFlags,'6 b'],
    ['Window',t.window,dispBits(16)],
    ['Checksum',t.tcpCksum,dispBits(16)],
    ['Urg Ptr','0x0000',dispBits(16)],
  ];
  const inner = fields.map(([n,v,b]) =>
    `<div class="field-block">
      <div class="field-name sec-tcp">${n}</div>
      <div class="field-val sec-tcp" data-section="tcp">${v}</div>
      <div class="field-bits">${b}</div>
    </div>`
  ).join('');
  return expandedGroup('TCP Header', '#3dd68c', inner);
}

function ipExpandedFields(pkt) {
  const ip = pkt.ip;
  const fields = [
    ['Version','4',dispBits(4)],
    ['IHL','5',dispBits(4)],
    ['DSCP','0x00','6 b'],
    ['Total Len',ip.ipLen,dispBits(16)],
    ['ID',ip.ipId,dispBits(16)],
    ['Flags','DF','3 b'],
    ['Frag Off','0','13 b'],
    ['TTL',ip.ipTTL,dispBits(8)],
    ['Protocol','TCP (6)',dispBits(8)],
    ['Checksum',ip.ipCksum,dispBits(16)],
    ['Src IP',ip.srcIp,dispBits(32)],
    ['Dst IP',ip.dstIp,dispBits(32)],
  ];
  const inner = fields.map(([n,v,b]) =>
    `<div class="field-block">
      <div class="field-name sec-ip">${n}</div>
      <div class="field-val sec-ip" data-section="ip">${v}</div>
      <div class="field-bits">${b}</div>
    </div>`
  ).join('');
  return expandedGroup('IP Header', '#f5a623', inner);
}

function llcExpandedFields(pkt) {
  const l = pkt.llc;
  const hdrFields = [['DSAP',l.dsap,dispBits(8)],['SSAP',l.ssap,dispBits(8)],['Control',l.llcCtrl,dispBits(8)]];
  const trlFields = [['FCS',l.llcFcs,dispBits(32)]];
  const hdrInner = hdrFields.map(([n,v,b]) =>
    `<div class="field-block"><div class="field-name sec-llc-h">${n}</div><div class="field-val sec-llc-h" data-section="llc-header">${v}</div><div class="field-bits">${b}</div></div>`
  ).join('');
  const trlInner = trlFields.map(([n,v,b]) =>
    `<div class="field-block"><div class="field-name sec-llc-t">${n}</div><div class="field-val sec-llc-t" data-section="llc-trailer">${v}</div><div class="field-bits">${b}</div></div>`
  ).join('');
  return expandedGroup('LLC Header', '#f75f5f', hdrInner) + expandedGroup('LLC Trailer', '#f75f5f', trlInner);
}

function macExpandedFields(pkt) {
  const m = pkt.mac;
  const hdrFields = [['Preamble','0xAA…AB','56+8 b'],['Dst MAC',m.dstMac,dispBits(48)],['Src MAC',m.srcMac,dispBits(48)],['EtherType',m.etherType,dispBits(16)]];
  const trlFields = [['FCS/CRC',m.macFcs,dispBits(32)]];
  const hdrInner = hdrFields.map(([n,v,b]) =>
    `<div class="field-block"><div class="field-name sec-mac-h">${n}</div><div class="field-val sec-mac-h" data-section="mac-header">${v}</div><div class="field-bits">${b}</div></div>`
  ).join('');
  const trlInner = trlFields.map(([n,v,b]) =>
    `<div class="field-block"><div class="field-name sec-mac-t">${n}</div><div class="field-val sec-mac-t" data-section="mac-trailer">${v}</div><div class="field-bits">${b}</div></div>`
  ).join('');
  return expandedGroup('MAC Header', '#c97bf7', hdrInner) + expandedGroup('MAC Trailer', '#c97bf7', trlInner);
}

// ── Layer row builders
function udpExpandedFields(pkt) {
  const udpLen = pkt.dataLen + 8;
  const udpCksum = checksum16([...pkt.dataBytes, pkt.tcp.srcPort>>8, pkt.tcp.srcPort&0xff, pkt.tcp.dstPort>>8, pkt.tcp.dstPort&0xff]);
  const fields = [
    ['Src Port', pkt.tcp.srcPort, dispBits(16)],
    ['Dst Port', pkt.tcp.dstPort, dispBits(16)],
    ['Length', udpLen, dispBits(16)],
    ['Checksum', udpCksum, dispBits(16)],
  ];
  const inner = fields.map(([n,v,b]) =>
    `<div class="field-block">
      <div class="field-name sec-udp">${n}</div>
      <div class="field-val sec-udp" data-section="udp">${v}</div>
      <div class="field-bits">${b}</div>
    </div>`
  ).join('');
  return expandedGroup('UDP Header', '#ffb432', inner);
}

function buildAppRow(pkt, layerIndex) {
  const content = STATE.expanded
    ? dataSection(pkt.segText, true, true)
    : dataSection(pkt.segText);
  return labelCol(layerIndex) + `<div class="layer-content-col">${content}</div>`;
}

function buildTransportRow(pkt) {
  const isTCP = STATE.transportMode === 'tcp';
  const toggleHtml = '';
  const content = isTCP
    ? (STATE.expanded
        ? tcpExpandedFields(pkt) + expandedGroup('Data','#4f8ef7',`<div class="pkt-section sec-data" data-section="data-1" style="width:100%;box-sizing:border-box">${escHtml(pkt.segText)}</div>`)
        : tcpHdrBlock() + dataSection(pkt.segText, true, false, 'data-1'))
    : (STATE.expanded
        ? udpExpandedFields(pkt) + expandedGroup('Data','#4f8ef7',`<div class="pkt-section sec-data" data-section="data-1" style="width:100%;box-sizing:border-box">${escHtml(pkt.segText)}</div>`)
        : udpHdrBlock() + dataSection(pkt.segText, true, false, 'data-1'));
  return labelCol(3) + `<div class="layer-content-col" style="flex-wrap:wrap;align-items:flex-start;gap:6px">${content}</div>`;
}

function buildNetworkRow(pkt) {
  const isTCP = STATE.transportMode === 'tcp';
  const content = STATE.expanded
    ? ipExpandedFields(pkt) + (isTCP ? tcpExpandedFields(pkt) : udpExpandedFields(pkt)) + expandedGroup('Data','#4f8ef7',`<div class="pkt-section sec-data" data-section="data-2" style="width:100%;box-sizing:border-box">${escHtml(pkt.segText)}</div>`)
    : ipHdrBlock() + (isTCP ? tcpHdrBlock() : udpHdrBlock()) + dataSection(pkt.segText, true, false, 'data-2');
  return labelCol(4) + `<div class="layer-content-col" style="flex-wrap:wrap;align-items:flex-start">${content}</div>`;
}

function buildLLCRow(pkt) {
  const isTCP = STATE.transportMode === 'tcp';
  const content = STATE.expanded
    ? expandedGroup('LLC Header','#f75f5f',`<div class="field-block"><div class="field-name sec-llc-h">DSAP</div><div class="field-val sec-llc-h" data-section="llc-header">${pkt.llc.dsap}</div><div class="field-bits">${dispBits(8)}</div></div><div class="field-block"><div class="field-name sec-llc-h">SSAP</div><div class="field-val sec-llc-h" data-section="llc-header">${pkt.llc.ssap}</div><div class="field-bits">${dispBits(8)}</div></div><div class="field-block"><div class="field-name sec-llc-h">Control</div><div class="field-val sec-llc-h" data-section="llc-header">${pkt.llc.llcCtrl}</div><div class="field-bits">${dispBits(8)}</div></div>`) + ipExpandedFields(pkt) + (isTCP ? tcpExpandedFields(pkt) : udpExpandedFields(pkt)) + expandedGroup('Data','#4f8ef7',`<div class="pkt-section sec-data" data-section="data-3" style="width:100%;box-sizing:border-box">${escHtml(pkt.segText)}</div>`) + expandedGroup('LLC Trailer','#f75f5f',`<div class="field-block"><div class="field-name sec-llc-t">FCS</div><div class="field-val sec-llc-t" data-section="llc-trailer">${pkt.llc.llcFcs}</div><div class="field-bits">${dispBits(32)}</div></div>`)
    : llcHdrBlock() + ipHdrBlock() + (isTCP ? tcpHdrBlock() : udpHdrBlock()) + dataSection(pkt.segText, true, false, 'data-3') + llcTrlBlock();
  return labelCol(5) + `<div class="layer-content-col" style="flex-wrap:wrap;align-items:flex-start">${content}</div>`;
}

function buildMACRow(pkt) {
  const isTCP = STATE.transportMode === 'tcp';
  const isEth = STATE.linkMode === 'ethernet';
  const isPPP = STATE.linkMode === 'ppp';
  const isSLIP = STATE.linkMode === 'slip';

  const toggleHtml = `<div class="row-toggle" style="margin-left:auto;display:flex;border:1px solid var(--border);border-radius:3px;overflow:hidden;flex-shrink:0">
    <button class="row-toggle-btn${isEth?' active':''}" data-link="ethernet">Ethernet</button>
    <button class="row-toggle-btn${isPPP?' active':''}" data-link="ppp">PPP</button>
    <button class="row-toggle-btn${isSLIP?' active':''}" data-link="slip">SLIP</button>
  </div>`;

  let content = '';

  if (isEth) {
    content = STATE.expanded
      ? expandedGroup('MAC Header','#c97bf7',`<div class="field-block"><div class="field-name sec-mac-h">Preamble</div><div class="field-val sec-mac-h" data-section="mac-header">0xAA…AB</div><div class="field-bits">56+8 b</div></div><div class="field-block"><div class="field-name sec-mac-h">Dst MAC</div><div class="field-val sec-mac-h" data-section="mac-header">${pkt.mac.dstMac}</div><div class="field-bits">${dispBits(48)}</div></div><div class="field-block"><div class="field-name sec-mac-h">Src MAC</div><div class="field-val sec-mac-h" data-section="mac-header">${pkt.mac.srcMac}</div><div class="field-bits">${dispBits(48)}</div></div><div class="field-block"><div class="field-name sec-mac-h">EtherType</div><div class="field-val sec-mac-h" data-section="mac-header">${pkt.mac.etherType}</div><div class="field-bits">${dispBits(16)}</div></div>`) + expandedGroup('LLC Header','#f75f5f',`<div class="field-block"><div class="field-name sec-llc-h">DSAP</div><div class="field-val sec-llc-h" data-section="llc-header">${pkt.llc.dsap}</div><div class="field-bits">${dispBits(8)}</div></div><div class="field-block"><div class="field-name sec-llc-h">SSAP</div><div class="field-val sec-llc-h" data-section="llc-header">${pkt.llc.ssap}</div><div class="field-bits">${dispBits(8)}</div></div><div class="field-block"><div class="field-name sec-llc-h">Control</div><div class="field-val sec-llc-h" data-section="llc-header">${pkt.llc.llcCtrl}</div><div class="field-bits">${dispBits(8)}</div></div>`) + ipExpandedFields(pkt) + (isTCP ? tcpExpandedFields(pkt) : udpExpandedFields(pkt)) + expandedGroup('Data','#4f8ef7',`<div class="pkt-section sec-data" data-section="data-4" style="width:100%;box-sizing:border-box">${escHtml(pkt.segText)}</div>`) + expandedGroup('LLC Trailer','#f75f5f',`<div class="field-block"><div class="field-name sec-llc-t">FCS</div><div class="field-val sec-llc-t" data-section="llc-trailer">${pkt.llc.llcFcs}</div><div class="field-bits">${dispBits(32)}</div></div>`) + expandedGroup('MAC Trailer','#c97bf7',`<div class="field-block"><div class="field-name sec-mac-t">FCS/CRC</div><div class="field-val sec-mac-t" data-section="mac-trailer">${pkt.mac.macFcs}</div><div class="field-bits">${dispBits(32)}</div></div>`)
      : macHdrBlock() + llcHdrBlock() + ipHdrBlock() + (isTCP ? tcpHdrBlock() : udpHdrBlock()) + dataSection(pkt.segText, true, false, 'data-4') + llcTrlBlock() + macTrlBlock();
  }

  if (isPPP) {
    content = STATE.expanded
      ? expandedGroup('PPP Frame','#a78bfa',`
          <div class="field-block"><div class="field-name" style="color:#a78bfa">Flag</div><div class="field-val" style="color:#a78bfa" data-section="ppp-frame">0x7E</div><div class="field-bits">8 b</div></div>
          <div class="field-block"><div class="field-name" style="color:#a78bfa">Address</div><div class="field-val" style="color:#a78bfa" data-section="ppp-frame">0xFF</div><div class="field-bits">8 b</div></div>
          <div class="field-block"><div class="field-name" style="color:#a78bfa">Control</div><div class="field-val" style="color:#a78bfa" data-section="ppp-frame">0x03</div><div class="field-bits">8 b</div></div>
          <div class="field-block"><div class="field-name" style="color:#a78bfa">Protocol</div><div class="field-val" style="color:#a78bfa" data-section="ppp-frame">0x0021</div><div class="field-bits">16 b</div></div>`) +
        ipExpandedFields(pkt) + (isTCP ? tcpExpandedFields(pkt) : udpExpandedFields(pkt)) +
        expandedGroup('Data','#4f8ef7',`<div class="pkt-section sec-data" data-section="data-4" style="width:100%;box-sizing:border-box">${escHtml(pkt.segText)}</div>`) +
        expandedGroup('PPP Trailer','#a78bfa',`
          <div class="field-block"><div class="field-name" style="color:#a78bfa">FCS</div><div class="field-val" style="color:#a78bfa" data-section="ppp-frame">${pkt.mac.macFcs}</div><div class="field-bits">16/32 b</div></div>
          <div class="field-block"><div class="field-name" style="color:#a78bfa">Flag</div><div class="field-val" style="color:#a78bfa" data-section="ppp-frame">0x7E</div><div class="field-bits">8 b</div></div>`)
      : `<div class="pkt-section clickable" style="background:rgba(167,139,250,0.18);color:#a78bfa" data-section="ppp-frame">PPP Header</div>
         ${encapBlock('IP Header','#f5a623','ip')}
         ${encapBlock(isTCP?'TCP Header':'UDP Header','#3dd68c',isTCP?'tcp':'udp')}
         ${dataSection(pkt.segText,true,false,'data-4')}
         <div class="pkt-section clickable" style="background:rgba(167,139,250,0.12);color:#a78bfa" data-section="ppp-frame">PPP Trailer</div>`;
  }

  if (isSLIP) {
    content = `
      <div style="font-family:var(--font-mono);font-size:10px;color:var(--text3);padding:0 8px;flex-shrink:0">No header —</div>
      ${encapBlock('IP Header','#f5a623','ip')}
      ${encapBlock(isTCP?'TCP Header':'UDP Header','#3dd68c',isTCP?'tcp':'udp')}
      ${dataSection(pkt.segText,true,false,'data-4')}
      <div class="pkt-section" style="background:rgba(61,214,214,0.15);color:#3dd6d6;flex-shrink:0">END 0xC0</div>`;
  }

  return labelCol(6) + `<div class="layer-content-col" style="flex-wrap:wrap;align-items:flex-start">${content}${toggleHtml}</div>`;
}

function buildPhysicalRow(pkt) {
  const shortBits = pkt.binaryStr.slice(0,128) + (pkt.binaryStr.length > 128 ? '…' : '');
  const content = `<div class="bits-row" style="cursor:pointer" data-section="physical" title="Click to see signal encodings">${shortBits}</div>`;
  return labelCol(7) + `<div class="layer-content-col" style="cursor:pointer" onclick="openZoom('physical', currentPkt())">${content}</div>`;
}

function currentPkt() {
  return buildPacket(STATE.segments[STATE.currentSeg], STATE.currentSeg, STATE.segments.length);
}
window.currentPkt = currentPkt;
window.openZoom = openZoom;

// ─── OPEN LAYER INFO ──────────────────────────────────────────
function openLayerInfo(layerIndex, pkt) {
  const col = LAYER_COLORS[layerIndex];

  function infoTable(cols, rows) {
    return `<table class="detail-table">
      <thead><tr>${cols.map(c=>`<th>${c}</th>`).join('')}</tr></thead>
      <tbody>${rows.map(r=>`<tr>${r.map(c=>`<td class="dt-what">${escHtml(String(c))}</td>`).join('')}</tr>`).join('')}</tbody>
    </table>`;
  }

  const LAYER_INFO = [
    {
      name: 'Application Layer', osi: 'Layer 7', col: '#4f8ef7',
      what: 'The layer humans and software interact with directly. Defines rules for how applications request and exchange data over a network.',
      problems: [
        ['No standard way for apps to communicate over a network','When two different applications on different machines need to exchange data','Different vendors built incompatible systems; a standard interface was needed','Without it, every app would need its own custom network code'],
        ['How does a browser know how to request a webpage from a server?','When user types a URL and hits enter','HTTP defines the exact format of requests and responses','Without HTTP, browsers and servers couldn\'t understand each other'],
        ['How does a hostname like google.com resolve to an IP?','Every time a connection is initiated using a domain name','DNS walks a hierarchy of servers to resolve the name','Without DNS, users would need to remember raw IP addresses'],
        ['How does email get addressed, routed, and delivered?','When a user sends an email across the internet','SMTP defines envelope addressing, routing between mail servers, and delivery handoff','Without SMTP, mail servers couldn\'t interoperate'],
      ],
      functions: [
        ['Network Virtual Terminal','Provides a standard interface so a user on one machine can log into another remotely','When remote access is needed (SSH, Telnet)','Abstracts the physical terminal into a virtual one the remote host understands','Without it, every terminal type would need a custom protocol'],
        ['File Transfer and Access','Allows files to be transferred between hosts or accessed remotely','When sharing documents, uploading content, or syncing data','FTP/SFTP define commands (GET, PUT, LIST) and data channels','Without it, file sharing would require manual byte-level transport'],
        ['Mail Services','Formats, addresses, and routes electronic messages between users on different hosts','When a user sends email','SMTP handles transfer; IMAP/POP3 handle retrieval','Without it, no interoperable email across different systems'],
        ['Directory Services','Resolves human-readable names to network addresses','Every time a connection uses a hostname','DNS queries walk root → TLD → authoritative server to return an IP','Without it, users must know exact IPs of every service they use'],
        ['Protocol Definition','Defines the exact message format, commands, and state machine for application-level exchanges','Whenever two applications begin a conversation','Each protocol (HTTP, FTP, SMTP) specifies request/response syntax, error codes, and sequencing','Without formal definitions, implementations would be incompatible'],
      ],
      design_issues: [
        ['Statelessness vs Statefulness','Should the protocol remember prior requests?','Stateless (HTTP/1.0) is simpler but requires re-authentication each request; stateful is efficient but complex to recover after failure','HTTP went stateless; sessions bolted on via cookies — best of both worlds at cost of complexity'],
        ['Pull vs Push','Should the client request data or should the server push it?','Pull is simple but wastes bandwidth with polling; push reduces latency but complicates server resource management','HTTP/2 Server Push and WebSockets add push to a pull-based web'],
        ['Text vs Binary protocols','Should messages be human-readable ASCII or compact binary?','Text is debuggable and interoperable; binary is fast and compact but opaque','HTTP/1.1 = text; HTTP/2 = binary frames; Protobuf replaces JSON for performance-critical APIs'],
        ['Versioning','How do you evolve a protocol without breaking existing clients?','Old clients must still work; new features must be adoptable','HTTP uses version negotiation (HTTP/1.1 → HTTP/2 via ALPN); REST APIs use URL versioning (/v1/, /v2/)'],
      ],
      protocols: [
        ['HTTP / HTTPS','HyperText Transfer Protocol (Secure)','Application-layer protocol for the web','Every browser request and server response','Client sends request line + headers; server responds with status + headers + body; HTTPS wraps in TLS','Without it, the web as we know it doesn\'t exist — no standard way to serve or fetch pages'],
        ['DNS','Domain Name System','Distributed hierarchical naming system','Every connection initiated by hostname','Client queries resolver → root → TLD → authoritative server; result cached per TTL','Without it, every internet user would need to memorise IP addresses'],
        ['FTP','File Transfer Protocol','Protocol for transferring files between hosts','Uploading files, accessing remote file systems','Two TCP connections: control (port 21) for commands, data (port 20) for content; commands are plain ASCII','Without it, no standard way to transfer files between different OS and vendor systems'],
        ['SMTP','Simple Mail Transfer Protocol','Protocol for sending email between mail servers','When a user sends an email','Sender opens TCP 25 to receiver\'s MX; exchanges EHLO/MAIL FROM/RCPT TO/DATA; body ends with lone dot','Without it, email servers from different vendors couldn\'t interoperate'],
        ['SSH','Secure Shell','Encrypted remote login and command execution','Remote server administration, secure file transfer','Diffie-Hellman key exchange → session keys → encrypted channel; authenticates via password or public key','Without it, remote administration would be in plaintext (Telnet) — trivially interceptable'],
        ['HTTP/2 & HTTP/3','HTTP version 2 (binary) and version 3 (QUIC-based)','High-performance successors to HTTP/1.1','Modern web browsing, APIs, streaming','HTTP/2: binary framing, multiplexed streams, header compression (HPACK); HTTP/3: runs over QUIC (UDP) eliminating TCP head-of-line blocking','Without them, modern high-concurrency web apps would be bottlenecked by HTTP/1.1 request serialisation'],
      ]
    },
    {
      name: 'Presentation Layer', osi: 'Layer 6', col: '#a78bfa',
      what: 'Translates, encodes, compresses, and encrypts data so both communicating applications understand each other regardless of internal data representations.',
      problems: [
        ['Different machines use different character encodings','When text data is exchanged between systems with different defaults (e.g. Windows ANSI vs Linux UTF-8)','Each system maps characters to byte values differently; without agreement the bytes are misinterpreted','Garbled text, mojibake, data corruption in string fields'],
        ['Data is too large to transmit efficiently','When sending large files, images, or streaming media','Raw data contains redundancy that compression algorithms can exploit','Without compression, bandwidth usage is wasteful and transmission is slow'],
        ['Data must be kept confidential in transit','When sensitive data (passwords, financial info) crosses untrusted networks','Encryption transforms plaintext to ciphertext only the intended recipient can reverse','Without encryption, any node on the path can read the data in plaintext'],
        ['Different applications represent data structures differently','When objects, trees, or typed data must cross language or OS boundaries','Each language/runtime has its own in-memory layout; serialisation converts to a neutral format','Without serialisation standards, applications couldn\'t exchange structured data'],
      ],
      functions: [
        ['Translation','Converts data between the sender\'s internal format and a common network format','When two systems with different data representations communicate','Encoding standards (ASCII, UTF-8, EBCDIC) define the mapping; sender encodes, receiver decodes','Without translation, a Windows machine and a mainframe would misinterpret each other\'s text','Solves: different character encodings'],
        ['Encryption / Decryption','Transforms data into ciphertext for transit and back to plaintext at destination','Whenever data must be kept confidential on untrusted networks','TLS: ECDHE key exchange → AES-GCM symmetric encryption; receiver decrypts with shared session key','Without encryption, any router or eavesdropper on the path can read all traffic','Solves: data must be confidential in transit'],
        ['Compression / Decompression','Reduces data size before transmission; receiver decompresses','When bandwidth is limited or data is large (web pages, images, video)','gzip: LZ77 finds repeated byte sequences and replaces with shorter codes + Huffman coding; receiver reverses','Without compression, web pages would be 2–10× larger and slower to load','Solves: data too large to transmit efficiently'],
        ['Serialisation / Deserialisation','Converts complex data structures into a flat byte stream for transmission and reassembles at receiver','Whenever structured objects (JSON, XML, Protobuf) are sent over a network','Sender walks the object graph and emits tokens (JSON) or encoded fields (Protobuf); receiver rebuilds the structure','Without serialisation, only raw bytes could be exchanged — no objects, no typed data','Solves: different data structure representations'],
        ['Format Negotiation','Allows sender and receiver to agree on encoding, compression, and media type before transfer','At the start of a session or request (HTTP Accept headers, TLS cipher negotiation)','Client advertises capabilities (Accept-Encoding: gzip, br); server selects best match and declares it in response headers','Without negotiation, sender would have to guess receiver capabilities — likely sending incompatible data','Solves: mismatched encoding and compression support'],
      ],
      design_issues: [
        ['Where does encryption belong?','Should encryption be in the Presentation layer, Transport layer, or Application layer?','Placing it in Presentation keeps apps unaware of crypto; placing it in Transport (TLS) is more practical but blurs layer boundaries','In practice TLS sits between Transport and Application — a pragmatic violation of strict layering'],
        ['Standard vs flexible serialisation','Should there be one universal serialisation format?','A universal format is interoperable but may be inefficient for all use cases; flexible formats fragment the ecosystem','No universal winner — JSON dominates web APIs, Protobuf dominates internal services, ASN.1 dominates telecom'],
        ['Compression placement','Should compression be at this layer or delegated to the application?','Layer-level compression is transparent to apps but may double-compress already-compressed data (images, video)','HTTP Content-Encoding lets apps control compression explicitly, avoiding double-compression'],
        ['Loss of the layer in TCP/IP','The TCP/IP model has no Presentation layer — its functions are scattered across application protocols','This works in practice but makes security (TLS), encoding (UTF-8), and compression (gzip) each app\'s responsibility','Results in inconsistent security: apps that forget TLS send data in plaintext; encoding bugs cause data corruption'],
      ],
      protocols: [
        ['TLS 1.3','Transport Layer Security version 1.3','Cryptographic protocol providing encryption, authentication, and integrity','Every HTTPS connection, any application needing secure transport','ClientHello → ServerHello + certificate → ECDHE key exchange → session keys derived → all data encrypted with AES-GCM or ChaCha20-Poly1305','Without it, all web traffic is readable by any network observer'],
        ['SSL','Secure Sockets Layer (deprecated predecessor to TLS)','Original encryption layer for web traffic','Legacy systems; now considered insecure','Same concept as TLS but with weaker cipher suites and broken protocol design; deprecated by RFC 7568','Historically important; understanding SSL helps understand why TLS was designed the way it was'],
        ['MIME','Multipurpose Internet Mail Extensions','Standard for encoding non-ASCII content in email and HTTP','Sending images, attachments, or binary data in email or HTTP','Content-Type header declares format; Base64 encodes binary as printable ASCII; multipart boundaries separate body parts','Without it, email could only carry 7-bit ASCII text — no attachments, no images'],
        ['ASCII / UTF-8','American Standard Code for Information Interchange / Unicode Transformation Format 8-bit','Character encoding standards','Every text transmission between systems','ASCII: 7-bit codes for 128 characters. UTF-8: variable-width (1–4 bytes); backward compatible with ASCII; encodes all 1.1M Unicode code points','Without a common encoding, text from one system is gibberish on another'],
        ['JSON / XML / Protobuf','JavaScript Object Notation / Extensible Markup Language / Protocol Buffers','Data serialisation formats','API calls, config files, inter-service communication','JSON: text key-value; human readable. XML: tag-based with schemas. Protobuf: binary, schema-defined, 3–10× smaller than JSON, requires .proto file','Without serialisation formats, structured data cannot be exchanged between different languages and platforms'],
        ['gzip / Brotli','GNU zip / Google Brotli compression','HTTP content compression','Web page delivery, API responses','gzip: DEFLATE (LZ77 + Huffman); Brotli: pre-shared dictionary + LZ77 + Huffman; 15–20% better than gzip for text','Without compression, web payloads are significantly larger, increasing latency and bandwidth cost'],
      ]
    },
    {
      name: 'Session Layer', osi: 'Layer 5', col: '#f472b6',
      what: 'Manages and controls the dialogue between two communicating applications — establishing, maintaining, synchronising, and terminating sessions.',
      problems: [
        ['A long transfer fails halfway through and must restart from the beginning','During large file transfers or long database transactions over unreliable networks','Without checkpoints, failure means starting over from byte 0','Wasted bandwidth, time, and compute — especially bad on slow or unreliable links'],
        ['Two sides transmit simultaneously causing garbled communication','In half-duplex systems where only one side can speak at a time','Without dialog control, both sides transmit simultaneously and neither is understood','Communication failure; must be restarted with coordination'],
        ['No way to resume an interrupted conversation','When a network drop kills a session mid-transaction','Without session state, reconnection starts a new conversation with no memory of prior state','Data duplication, lost transactions, broken multi-step workflows'],
        ['Multiple parallel dialogues over one connection are confused','When multiple independent conversations happen between the same two hosts','Without session IDs or tokens, the receiver can\'t tell which message belongs to which conversation','Data from one session is mixed with another — corruption or security breach'],
      ],
      functions: [
        ['Session Establishment','Creates a session between two applications, negotiating parameters and authenticating if required','At the start of an application-level conversation (login, RPC call, video call setup)','SIP sends INVITE; RPC performs binding; session token issued and stored by both sides','Without establishment, there is no shared context — each message is stateless and unrelated','Solves: no way to resume interrupted conversations'],
        ['Session Maintenance','Keeps the session alive during the conversation, handling keepalives and re-establishment after drops','Throughout the duration of an active session','Keepalive messages sent periodically; if no response, session is considered dead and may be re-established','Without maintenance, idle sessions are silently dropped by NAT or firewalls, causing mysterious failures','Solves: interrupted conversations'],
        ['Dialog Control','Coordinates which side transmits at any given moment — half-duplex (one at a time) or full-duplex (simultaneous)','During any half-duplex protocol exchange (older radio systems, some RPC patterns)','Tokens passed between sides; only the token holder may transmit; receiver signals readiness to respond','Without it, simultaneous transmission in half-duplex systems causes collisions and data loss','Solves: both sides transmitting simultaneously'],
        ['Synchronisation (Checkpointing)','Inserts synchronisation points into a data stream so that on failure, transfer resumes from the last checkpoint rather than the beginning','During long file transfers, database dumps, or streaming over unreliable links','Sender and receiver agree on checkpoint intervals; receiver ACKs each checkpoint; on failure, restart from last ACKed checkpoint','Without checkpoints, any failure restarts the entire transfer regardless of how much was completed','Solves: long transfers restarting from zero on failure'],
        ['Session Termination','Gracefully ends a session, ensuring both sides agree the conversation is over and releasing resources','When an application finishes its task (file fully transferred, call ended, transaction committed)','FIN equivalent at session level; both sides confirm completion before releasing session state','Without explicit termination, resources (memory, ports, database locks) are held until timeout','Solves: resource leaks from abandoned sessions'],
      ],
      design_issues: [
        ['Session layer vs Transport layer overlap','TCP already provides connection state — does a separate Session layer add value?','Duplicating reliability and state management across layers adds complexity without clear benefit','TCP/IP collapsed Session into Application; OSI kept it separate for modularity — TCP/IP won in practice'],
        ['Session recovery after network failure','How far back should recovery go when a session is interrupted?','Too-frequent checkpoints waste bandwidth; too-infrequent means large retransmissions on failure','Application protocols must choose checkpoint granularity based on cost of retransmission vs checkpoint overhead'],
        ['Authentication at session vs application layer','Should session establishment verify identity or should the application handle it?','Session-layer auth is transparent to apps but inflexible; app-layer auth (HTTP cookies, JWT) is flexible but repetitive across protocols','Modern systems use app-layer auth (OAuth, JWT) — session layer auth is seen only in legacy enterprise systems'],
        ['Stateful sessions vs stateless requests','Should each request carry all context or should the server maintain session state?','Stateful sessions are efficient but hard to scale horizontally; stateless (REST) is scalable but shifts state burden to client','Modern web: stateless HTTP + client-side tokens (JWT); traditional enterprise: stateful sessions with server-side storage'],
      ],
      protocols: [
        ['NetBIOS','Network Basic Input/Output System','Session service for Windows networking — name registration, session establishment, datagram service','Windows file sharing, legacy LAN applications','Name registration broadcasts NetBIOS name; session established via TCP; data exchanged via session frames; termination explicit','Without it, early Windows networks had no way to discover or connect to peers by name'],
        ['RPC','Remote Procedure Call','Mechanism allowing a program to execute a function on a remote host transparently','Distributed applications, microservices, OS internals (NFS, DCE)','Client stub marshals arguments → network call → server stub unmarshals → executes function → result returned to client','Without RPC, distributed systems would need custom network protocols for every function call'],
        ['SIP','Session Initiation Protocol','Signalling protocol for establishing multimedia sessions (VoIP, video)','Every VoIP call, video conference, instant messaging session setup','INVITE → 200 OK → ACK establishes session; SDP in body negotiates codecs and ports; BYE terminates','Without SIP, VoIP systems from different vendors couldn\'t interoperate'],
        ['PPTP','Point-to-Point Tunneling Protocol','VPN tunneling protocol encapsulating PPP over TCP','Legacy VPN connections, early remote access','Control connection on TCP 1723 manages session; GRE tunnel carries data; PPP frames encapsulated inside','Largely deprecated due to weak encryption; replaced by L2TP/IPsec, OpenVPN, WireGuard'],
        ['HTTP Cookies','HTTP Session Management via Cookies','Adds session state to stateless HTTP','Every login session, shopping cart, user preference on the web','Server sends Set-Cookie with session token; browser stores and returns it on every request; server maps token to session data','Without cookies, every HTTP request would be stateless — no logins, no persistent shopping carts'],
        ['WebSocket','WebSocket Protocol RFC 6455','Full-duplex persistent session over a single TCP connection','Real-time apps: chat, live dashboards, multiplayer games, collaborative editing','HTTP Upgrade request → 101 Switching Protocols → bidirectional frame-based messaging for duration of session','Without WebSockets, real-time apps resort to inefficient polling — a request every second just to check for updates'],
      ]
    },
    {
      name: 'Transport Layer', osi: 'Layer 4', col: '#3dd68c',
      what: 'Provides end-to-end communication between processes on different hosts — segmentation, reliability, ordering, flow control, and multiplexing.',
      problems: [
        ['Application data is too large to send in a single network packet','Whenever an application sends more data than the network MTU allows (typically 1500 bytes for Ethernet)','Application hands a large buffer to the OS; transport layer must chop it into MTU-sized pieces','Without segmentation, a 1MB file transfer would require a 1MB packet which no network could carry'],
        ['Packets can be lost, corrupted, or arrive out of order','On any real network due to congestion, bit errors, or routing changes','Network layer provides best-effort delivery only — no guarantees','Without reliability, applications would have to implement their own retransmission — every app reinventing TCP'],
        ['Receiver can be overwhelmed by a fast sender','When sender transmits faster than receiver can process','Receiver\'s buffer fills up; OS must discard incoming packets','Without flow control, fast senders cause receiver buffer overflow and data loss'],
        ['The network itself can become congested','When too many flows compete for the same bottleneck link','Packets queue up at routers, then are dropped when queues overflow','Without congestion control, all senders keep transmitting at full speed, making congestion worse (congestion collapse)'],
        ['Multiple applications share one IP address','On any host running more than one networked application simultaneously','IP delivers to a host but can\'t distinguish which application the data belongs to','Without port-based multiplexing, the OS couldn\'t tell whether incoming data is for the browser, mail client, or SSH daemon'],
      ],
      functions: [
        ['Segmentation and Reassembly','Breaks large application messages into segments sized to fit the network; receiver reassembles in order','When application data exceeds the MSS (Maximum Segment Size)','Sender divides data into MSS-sized chunks, assigns sequence numbers; receiver buffers and reorders before passing to application','Without it, the application would have to manually manage packet sizing for every network type','Solves: data too large for one packet'],
        ['Reliable Delivery','Guarantees that all segments arrive, in order, exactly once','When using TCP for any data that must not be lost (file transfer, HTTP, database queries)','Sequence numbers track position; receiver sends cumulative ACKs; sender retransmits unACKed segments after timeout or duplicate ACK','Without it, silent packet loss would corrupt files, truncate web pages, and corrupt database transactions','Solves: packets lost or arriving out of order'],
        ['Flow Control','Prevents the sender from transmitting faster than the receiver can process','Continuously during a TCP connection when receiver buffer occupancy changes','Receiver advertises its available buffer space (window size) in every ACK; sender must not have more unACKed bytes in flight than the window','Without it, fast senders fill receiver buffers, causing drops and retransmissions that hurt throughput for everyone','Solves: receiver being overwhelmed'],
        ['Congestion Control','Reduces the sender\'s transmission rate when the network is congested','When packet loss or ECN marks are detected, indicating router queue overflow','TCP slow start: begin at 1 MSS, double each RTT until loss; then AIMD (additive increase, multiplicative decrease) — increase by 1 MSS per RTT, halve on loss','Without it, all senders transmit at maximum rate during congestion, causing catastrophic throughput collapse','Solves: network congestion'],
        ['Multiplexing / Demultiplexing','Combines data from multiple application sockets into one IP stream and separates incoming data to the correct socket','On every host running multiple networked applications','Source and destination port numbers in the segment header identify the socket; OS uses the 4-tuple (src IP, src port, dst IP, dst port) to demultiplex','Without it, the OS couldn\'t tell whether incoming port-80 data is for Chrome or another application','Solves: multiple apps sharing one IP'],
        ['Error Detection','Detects corruption of segment data in transit','On every segment sent via TCP or UDP','Checksum computed over pseudo-header + segment header + data; receiver recomputes and discards if mismatch','Without it, corrupted data would be silently delivered to applications — silent data corruption','Solves: corrupted packets'],
      ],
      design_issues: [
        ['Reliability vs latency','TCP guarantees delivery but adds latency (ACK round trips, retransmissions); UDP is fast but unreliable','Real-time applications (video calls, gaming) cannot wait for retransmissions — a late packet is worse than no packet','Solution: UDP for latency-sensitive apps; QUIC reimplements selective reliability on UDP for the best of both'],
        ['End-to-end vs in-network reliability','Should reliability be in the network (every router guarantees delivery) or only at endpoints?','In-network reliability makes routers complex and slow; end-to-end keeps the network simple','TCP/IP chose end-to-end (Saltzer\'s end-to-end argument) — routers just forward; endpoints handle reliability'],
        ['Head-of-line blocking','In TCP, a lost packet blocks all subsequent data in the stream even if it arrived intact','This serialises delivery of independent streams — one lost packet stalls a whole page load','HTTP/2 tried to fix this with streams over one TCP connection but TCP itself still blocks; HTTP/3 uses QUIC over UDP to fix it properly'],
        ['Port number space exhaustion','Only 65535 ports per IP; NAT and large servers handling millions of connections hit limits','A busy server with 50k connections per IP needs careful port management','Solutions: connection pooling, multiple IPs per server, SO_REUSEPORT, QUIC connection IDs replacing the 4-tuple'],
        ['TCP complexity','TCP has grown enormously complex — SACK, timestamps, window scaling, TFO, ECN, BBR','Each extension requires careful negotiation and interop testing; buggy implementations cause subtle failures','QUIC moved TCP-like logic to userspace, enabling faster iteration without OS kernel upgrades'],
      ],
      protocols: [
        ['TCP','Transmission Control Protocol','Reliable, ordered, connection-oriented transport protocol','File transfer, web browsing, email, database queries — anything requiring guaranteed delivery','3-way handshake (SYN/SYN-ACK/ACK) → data transfer with sequence numbers and ACKs → FIN/FIN-ACK/ACK teardown','Without TCP, every application needing reliability would implement its own retransmission — guaranteed to be buggy and incompatible'],
        ['UDP','User Datagram Protocol','Connectionless, unreliable, low-overhead transport protocol','DNS, VoIP, video streaming, gaming, DHCP — latency-sensitive or loss-tolerant applications','No handshake; sender fires datagrams; no ACK, no retransmit, no ordering guarantee; minimal 8-byte header','Without UDP, latency-sensitive apps would be forced to use TCP and suffer retransmission delays that ruin real-time communication'],
        ['QUIC','Quick UDP Internet Connections','Reliable multiplexed transport built on UDP with integrated TLS 1.3','HTTP/3, Google services, modern high-performance web applications','Runs over UDP; implements streams, flow control, congestion control in userspace; 0-RTT reconnection; no head-of-line blocking between streams','Without QUIC, HTTP/2\'s stream multiplexing is undermined by TCP\'s head-of-line blocking at the byte-stream level'],
        ['SCTP','Stream Control Transmission Protocol','Multi-stream, multi-homed reliable transport protocol','VoIP signalling (SS7 over IP), WebRTC data channels, telecom infrastructure','4-way handshake (cookie mechanism prevents SYN floods); multiple independent streams; supports multiple IPs per endpoint (multi-homing) for failover','Without SCTP, telecom systems would have to use TCP (no multi-streaming) or UDP (no reliability) — neither ideal for signalling'],
        ['DCCP','Datagram Congestion Control Protocol','Unreliable transport with congestion control','Streaming media where loss is acceptable but congestion fairness is required','Like UDP but adds congestion control without retransmission; sender adapts rate to network conditions without head-of-line blocking','Without DCCP, UDP streams are congestion-unaware — they can flood the network and starve TCP flows at the same bottleneck'],
      ]
    },
    {
      name: 'Network Layer', osi: 'Layer 3', col: '#f5a623',
      what: 'Routes packets across multiple networks from source to destination using logical (IP) addresses. Handles path selection, logical addressing, and fragmentation.',
      problems: [
        ['Data must cross multiple different network technologies to reach its destination','Any time source and destination are not on the same LAN (i.e. almost all internet traffic)','WiFi, Ethernet, fiber, and cellular all use different Layer 2 framing — need a common Layer 3 to unify them','Without a network layer, there is no internet — only isolated LANs'],
        ['Every device needs a globally unique, routable address','When devices from different organisations need to communicate over the internet','MAC addresses are locally significant only; a globally unique logical address is required','Without globally unique addresses, routers can\'t determine where to send a packet'],
        ['Packets may be too large for some links along the path','When a packet crosses from a network with large MTU to one with smaller MTU','Different link technologies have different maximum frame sizes','Without fragmentation or PMTUD, packets too large for a link are simply dropped and the connection fails silently'],
        ['Routers must decide the best path for each packet','At every router hop across the internet','Network topology changes dynamically — links fail, congestion varies, new paths appear','Without routing protocols, routers would need manual static configuration for every possible destination — impossible at internet scale'],
      ],
      functions: [
        ['Logical Addressing','Assigns globally unique addresses (IP addresses) to every host and network interface','On every packet that crosses a router','32-bit (IPv4) or 128-bit (IPv6) addresses assigned hierarchically by IANA → RIRs → ISPs → organisations; routers use the network prefix to make forwarding decisions','Without globally unique logical addresses, routers have no way to identify source or destination across network boundaries','Solves: every device needs a globally unique routable address'],
        ['Routing','Determines the best path for each packet from source to destination across multiple networks','On every packet at every router','Routers maintain routing tables built by protocols (OSPF, BGP); longest-prefix match selects next hop; TTL prevents loops','Without routing, packets could only travel on a single LAN — no internet','Solves: routing across multiple different networks'],
        ['Packet Forwarding','Actually moves each packet from an incoming interface to the correct outgoing interface based on routing table lookup','At every router, for every packet','Hardware ASICs perform longest-prefix match in the FIB (Forwarding Information Base) at line rate (millions of packets per second)','Without forwarding, routing table knowledge is useless — packets still wouldn\'t move','Solves: routing across networks'],
        ['Fragmentation and Reassembly','Breaks packets too large for a link\'s MTU into smaller fragments; destination reassembles','When a packet must traverse a link with smaller MTU than the packet size','Router sets MF flag and Fragment Offset on each piece; destination collects all fragments (same ID) and reassembles; DF flag + ICMP enables Path MTU Discovery instead','Without fragmentation, large packets would be silently dropped at MTU boundaries','Solves: packets too large for some links'],
        ['Error Reporting','Reports packet delivery errors back to the source so it can react','When a packet is dropped, TTL expires, or destination is unreachable','ICMP sends Type 3 (Destination Unreachable), Type 11 (TTL Exceeded), Type 4 (Fragmentation Needed) messages back to source IP','Without error reporting, senders would never know why connections fail — only that they do','Solves: silent packet drops with no feedback'],
        ['Traffic Control and QoS Marking','Marks packets with priority information so routers can make queuing decisions','When different traffic types (VoIP vs bulk download) share the same link','DSCP field in IP header set by sender or edge router; core routers use DiffServ to prioritise marked traffic','Without QoS marking, all packets are treated equally — a bulk download can starve a VoIP call on the same link','Solves: different traffic types competing for bandwidth'],
      ],
      design_issues: [
        ['IPv4 address exhaustion','32-bit IPv4 provides only ~4 billion addresses — exhausted by 2011','Internet growth far exceeded original estimates; NAT was a band-aid, not a solution','IPv6 (128-bit) solves this permanently but adoption is slow due to dual-stack transition complexity'],
        ['Routing table scalability','The global BGP routing table has grown to over 900,000 prefixes — memory and CPU intensive for routers','Every new network added to the internet adds entries to every router\'s table','Hierarchical addressing (CIDR aggregation) slows growth; but fragmented allocations cause table bloat'],
        ['Connectionless vs connection-oriented network','Should the network layer maintain per-flow state (virtual circuits) or be stateless (datagram)?','Virtual circuits give predictable QoS but are fragile; datagrams are resilient but unpredictable','IP chose datagrams (no per-flow state); MPLS adds label-switched paths as an overlay for QoS without full connection state'],
        ['End-to-end transparency vs NAT','NAT allows address reuse but breaks end-to-end connectivity (peers can\'t initiate connections to NATted hosts)','Peer-to-peer, VoIP, and gaming all suffer from NAT traversal complexity','IPv6 restores end-to-end transparency; meanwhile STUN/TURN/ICE are used to punch through NAT for real-time applications'],
        ['Fragmentation responsibility','Should routers fragment or should senders discover MTU and pre-fragment?','Router fragmentation is expensive (stateful); sender-side PMTUD requires ICMP to not be blocked by firewalls','IPv6 removed router fragmentation entirely — senders must do PMTUD; broken ICMP firewalls cause PMTUD blackholes'],
      ],
      protocols: [
        ['IPv4','Internet Protocol version 4','Primary network-layer protocol for packet addressing and routing','Virtually all internet traffic as of today','20-byte header with src/dst IP, TTL, protocol, checksum; routers do longest-prefix match on dst IP; TTL decremented each hop','Without IPv4, there is no internet — it is the foundational addressing and routing protocol'],
        ['IPv6','Internet Protocol version 6','Successor to IPv4 with 128-bit addresses and simplified header','Modern networks, mobile, IoT — wherever IPv4 address space is insufficient','Fixed 40-byte header; no fragmentation by routers; ICMPv6 handles neighbor discovery; SLAAC for auto-configuration','Without IPv6, the internet runs out of addresses — NAT is a temporary workaround, not a permanent solution'],
        ['ICMP','Internet Control Message Protocol','Error reporting and diagnostic protocol for IP','ping, traceroute, Path MTU Discovery, router error signalling','Carried inside IP packets; Type/Code fields identify the message (Type 8 = Echo Request, Type 0 = Echo Reply, Type 11 = TTL Exceeded)','Without ICMP, network debugging is nearly impossible and Path MTU Discovery breaks — causing mysterious connection failures'],
        ['OSPF','Open Shortest Path First','Link-state interior gateway routing protocol','Routing within an organisation or ISP (intra-AS)','Each router floods Link State Advertisements to all others; every router builds identical topology graph; Dijkstra computes shortest paths; fast convergence on failure','Without OSPF (or similar IGP), enterprise networks require manual static routing — impossible to maintain at scale'],
        ['BGP','Border Gateway Protocol','Path-vector exterior gateway routing protocol — the routing protocol of the internet','Routing between autonomous systems (ISPs, CDNs, enterprises with their own IP space)','Routers exchange AS-path vectors and policy attributes; each AS applies local policy to choose best path; only selected routes propagated','Without BGP, there is no inter-domain routing — ISPs cannot exchange routes and the internet fragments into isolated islands'],
        ['MPLS','Multiprotocol Label Switching','Label-based packet forwarding overlay over IP','ISP backbones, VPNs, traffic engineering, QoS-sensitive paths','Edge router assigns a label to each packet based on FEC; core routers swap labels without IP lookup (faster); label stack enables VPNs and TE','Without MPLS, ISPs would need complex per-flow IP routing for QoS and VPNs — MPLS enables line-rate forwarding with traffic engineering'],
      ]
    },
    {
      name: 'LLC Sub-layer', osi: 'Layer 2a', col: '#f75f5f',
      what: 'Upper half of the Data Link layer. Provides a uniform interface to the Network layer, handles multiplexing of Layer 3 protocols, and optionally provides flow and error control.',
      problems: [
        ['The Network layer must talk to many different MAC technologies (Ethernet, WiFi, Token Ring)','When an IP packet needs to be handed down to whatever physical network is present','Each MAC technology has different framing and addressing; Network layer can\'t know about all of them','Without LLC, IP would need a different implementation for every MAC technology'],
        ['Multiple Layer 3 protocols (IP, IPX, AppleTalk) share the same physical network','On networks running heterogeneous protocol stacks (common in enterprise LANs in the 1990s)','MAC frames carry raw bytes with no indication of which L3 protocol the payload belongs to','Without LLC DSAP/SSAP, the receiver can\'t demultiplex incoming frames to the correct L3 handler'],
        ['Some applications need connection-oriented reliable delivery at Layer 2','In environments where upper layers don\'t provide reliability (e.g. industrial automation, SNA)','LLC Type 2 provides I-frames with sequence numbers and ACKs below the network layer','Without LLC Type 2, every application needing L2 reliability must implement it independently'],
      ],
      functions: [
        ['Multiplexing','Identifies which Layer 3 protocol the payload belongs to so the receiver can route it to the correct handler','On every received frame, to demultiplex to IP, IPX, or other L3 protocol','DSAP and SSAP fields in the LLC header carry SAP values (0x06=IP, 0xAA=SNAP); receiver uses these to select the correct L3 handler','Without multiplexing, a host receiving a frame has no way to know if the payload is IPv4, IPv6, or IPX','Solves: multiple L3 protocols sharing one physical network'],
        ['Framing','Delimits the boundaries of a frame so the receiver knows where one frame ends and the next begins','On every frame transmitted over a shared medium','LLC header placed before payload; MAC trailer (FCS) placed after; together they bracket the frame content','Without framing, the bit stream has no structure — receiver can\'t locate individual frames','Solves: no structure in the raw bit stream'],
        ['Flow Control (Type 2)','Prevents the sender from overwhelming the receiver at the data link level','In LLC Type 2 (connection-oriented) mode, when the receiver\'s buffer is filling up','RR (Receiver Ready) and RNR (Receiver Not Ready) supervisory frames signal the sender to pause or resume','Without L2 flow control, a fast sender can overflow a slow receiver\'s buffer before upper layers can react','Solves: receiver being overwhelmed at L2'],
        ['Error Control (Type 2)','Detects and requests retransmission of lost or corrupted frames at the data link level','In LLC Type 2 mode, when an I-frame is lost or the FCS fails','REJ (Reject) and SREJ (Selective Reject) supervisory frames request retransmission of specific frames','Without L2 error control, upper layers must handle all retransmission — acceptable for TCP/IP but not for all applications','Solves: frame loss and corruption'],
        ['Service Access Point (SAP) Addressing','Identifies the specific service or protocol endpoint within a host that should receive the frame','On every frame, to direct data to the correct protocol handler or service','DSAP byte in LLC header carries the destination SAP value; OS protocol stack uses it to demultiplex','Without SAP addressing, all frames go to the same handler regardless of which protocol they carry','Solves: multiple L3 protocols sharing one interface'],
      ],
      design_issues: [
        ['LLC vs EtherType','Ethernet II frames use a 2-byte EtherType field to identify L3 protocol — making LLC\'s DSAP/SSAP redundant for most uses','Two competing standards for the same function creates complexity; most modern Ethernet uses EtherType, not LLC SAPs','IEEE 802.3 with SNAP bridges both: LLC header with DSAP=0xAA followed by 5-byte SNAP header containing the EtherType value'],
        ['LLC Type 1 vs Type 2','Type 1 (connectionless) vs Type 2 (connection-oriented with ACKs) — which to use?','Type 2 adds reliability at L2 but duplicates what TCP does at L4; Type 1 is simpler but relies on upper layers for reliability','TCP/IP stacks almost always use Type 1 (UI frames); Type 2 is used in legacy SNA and some industrial protocols'],
        ['Relevance of LLC in modern networks','With Ethernet II (EtherType) dominating and TCP/IP handling reliability, is LLC still needed?','LLC adds header overhead and complexity for functions now handled by other layers','In WiFi (802.11) networks, LLC with SNAP is still used to carry EtherType values; in wired Ethernet, LLC is largely bypassed'],
      ],
      protocols: [
        ['IEEE 802.2','IEEE 802.2 Logical Link Control','Standard defining LLC framing, SAP addressing, and frame types (I/S/U)','Any 802.x network (Ethernet, WiFi, Token Ring) that uses LLC framing','DSAP + SSAP + Control fields prepended to payload; Control field identifies frame type: UI=0x03 (connectionless), I-frame (sequenced), S-frame (supervisory)','Without IEEE 802.2, there is no standard way to multiplex L3 protocols over MAC or provide L2 flow control'],
        ['SNAP','Sub-Network Access Protocol','Extension to IEEE 802.2 that allows EtherType values inside LLC framing','WiFi frames carrying IP traffic; any 802.x frame needing to specify a standard EtherType','DSAP=SSAP=0xAA, Control=0x03, followed by 5-byte SNAP header: 3-byte OUI (0x000000 for standard) + 2-byte EtherType','Without SNAP, 802.11 WiFi frames couldn\'t carry IPv4 or IPv6 using standard EtherType values — each vendor would need proprietary SAP assignments'],
      ]
    },
    {
      name: 'MAC Sub-layer', osi: 'Layer 2b', col: '#c97bf7',
      what: 'Lower half of the Data Link layer. Governs access to the physical medium, assigns hardware addresses, frames bits into structured units, and provides error detection.',
      problems: [
        ['Multiple devices share one physical medium and must not transmit simultaneously','On any shared medium: classic Ethernet (bus/hub), WiFi, cable TV upstream channels','Without coordination, simultaneous transmissions collide and corrupt each other\'s data','Without medium access control, shared networks are unusable — every transmission causes a collision'],
        ['How does a frame reach the correct device on a local network?','On any LAN where multiple devices are connected to the same switch or access point','IP addresses are logical and can change; hardware needs a stable physical identifier','Without MAC addresses, switches can\'t learn which port leads to which device — broadcast storms and confusion'],
        ['How does the receiver know if a frame was corrupted in transit?','After every frame is received — electrical interference, RF noise, and hardware faults flip bits','The physical layer transmits raw bits with no error detection','Without CRC, corrupted frames are silently accepted and corrupt data is handed to upper layers'],
        ['How does the receiver know where one frame starts and ends in the bit stream?','Every time a frame is received from the physical layer','The physical layer delivers a continuous bit stream with no inherent boundaries','Without framing (preamble + SFD + length/type + FCS), the receiver can\'t locate frame boundaries'],
      ],
      functions: [
        ['Medium Access Control','Determines when each device is allowed to transmit on the shared medium to avoid or recover from collisions','On every transmission attempt on a shared medium (classic Ethernet, WiFi)','Ethernet: CSMA/CD — listen before transmit, detect collision, jam, backoff exponentially; WiFi: CSMA/CA — random backoff before transmit, RTS/CTS for large frames','Without MAC, simultaneous transmissions destroy each other — no data can be transferred on a shared medium','Solves: multiple devices sharing one medium'],
        ['Physical Addressing','Assigns a unique 48-bit hardware address (MAC address) to each NIC for frame delivery on a LAN','On every frame sent or received, to identify sender and intended recipient','MAC address burned into NIC by manufacturer (first 24 bits = OUI, last 24 = device ID); switches learn which MAC address is reachable on which port','Without physical addresses, switches and NICs can\'t determine which frames to accept or where to forward them','Solves: delivering frames to correct device on LAN'],
        ['Framing','Wraps a payload in a structured format with preamble, addresses, type, and trailer so the receiver can locate and parse each frame','On every transmission','Ethernet frame: 7-byte preamble (10101010…) + 1-byte SFD (10101011) + dst MAC + src MAC + EtherType + payload + 4-byte CRC-32','Without framing, the physical layer delivers a continuous undifferentiated bit stream with no frame boundaries','Solves: receiver can\'t find frame boundaries in bit stream'],
        ['Error Detection','Detects frames corrupted in transit so they can be discarded rather than passed to upper layers','On every received frame','Sender computes CRC-32 over frame content and appends as FCS; receiver recomputes CRC and compares; mismatch → frame silently discarded','Without error detection, corrupted frames would be passed to upper layers and cause data corruption or security issues','Solves: corrupted frames silently accepted'],
        ['Frame Delimiting','Provides unambiguous start-of-frame and end-of-frame markers in the bit stream','At the physical/MAC boundary on every received frame','Preamble synchronises receiver clock; SFD (0xAB) marks exact start of frame; FCS at end provides implicit end-of-frame marker','Without delimiting, the receiver can\'t recover frame boundaries from the bit stream even if the bits are error-free','Solves: no frame boundaries in bit stream'],
      ],
      design_issues: [
        ['Shared vs switched Ethernet','Original Ethernet was a shared bus (all frames visible to all); switched Ethernet gives each host a dedicated segment','Shared: simple but collisions limit throughput; switched: no collisions but switches must learn topology and handle broadcast storms','Modern Ethernet is almost entirely switched; CSMA/CD is now a historical artifact — but the framing format is unchanged'],
        ['MAC address mutability','MAC addresses were designed as permanent hardware identifiers but are trivially changed in software','Spoofed MACs allow impersonation on a LAN, bypass MAC filtering, and complicate network forensics','MAC randomisation in mobile OSes (iOS, Android) adds privacy but breaks some network management tools that rely on stable MACs'],
        ['Broadcast domain scalability','All devices on the same Layer 2 network receive every broadcast frame (ARP, DHCP) — unscalable for large networks','A 10,000-device flat L2 network would be flooded with ARP broadcasts consuming significant bandwidth','VLANs (802.1Q) partition broadcast domains; routers separate Layer 2 segments; but VLAN management adds complexity'],
        ['WiFi vs Ethernet MAC','WiFi (802.11) cannot use CSMA/CD (can\'t detect collisions while transmitting on radio) — requires a different MAC','CSMA/CA adds overhead (random backoff, ACKs for every frame) making WiFi inherently less efficient than wired Ethernet','WiFi trades efficiency for wireless convenience; OFDMA in WiFi 6 (802.11ax) partially recovers efficiency through parallel subcarrier scheduling'],
      ],
      protocols: [
        ['IEEE 802.3 (Ethernet)','IEEE 802.3 Ethernet Standard','Wired LAN protocol defining framing, MAC addressing, and CSMA/CD','Virtually all wired LAN connections in offices, data centres, homes','CSMA/CD access control (now legacy); frame: preamble + SFD + dst MAC + src MAC + EtherType + payload (46–1500 bytes) + CRC-32','Without Ethernet, wired LANs would be a fragmented collection of proprietary protocols — Token Ring, ArcNet, etc.'],
        ['IEEE 802.11 (WiFi)','IEEE 802.11 Wireless LAN Standard','Wireless LAN protocol defining framing, MAC addressing, and CSMA/CA','Wireless connectivity for laptops, phones, IoT devices, smart home','CSMA/CA with random backoff; RTS/CTS for hidden node problem; ACK every frame; OFDM/OFDMA physical encoding; WPA3 for security','Without WiFi, all devices would need physical Ethernet cables — mobile computing as we know it wouldn\'t exist'],
        ['ARP','Address Resolution Protocol','Resolves IPv4 addresses to MAC addresses on a local network','Every time a host initiates a connection to an IP on the same subnet','Sender broadcasts "Who has IP x.x.x.x?"; owner replies with its MAC; sender caches result in ARP table for TTL duration','Without ARP, IP packets can\'t be wrapped in Ethernet frames for local delivery — the final hop on any LAN fails'],
        ['STP / RSTP','Spanning Tree Protocol / Rapid Spanning Tree Protocol (IEEE 802.1D/w)','Prevents Layer 2 forwarding loops in switched networks','Any network with redundant switch paths (for reliability)','Elects root bridge; each switch finds shortest path to root; redundant ports blocked; RSTP converges in <1s vs STP\'s 30–50s','Without STP, redundant switch links create broadcast storms that consume all bandwidth within seconds'],
        ['VLANs (802.1Q)','IEEE 802.1Q Virtual LAN','Logically partitions a physical network into multiple isolated broadcast domains','Enterprise networks segmenting departments, data centres separating tenants','4-byte 802.1Q tag inserted after src MAC: 3-bit PCP (priority) + 1-bit DEI + 12-bit VLAN ID; switches use VLAN ID to scope forwarding','Without VLANs, every broadcast domain requires separate physical switches — expensive and inflexible'],
      ],
      working_groups: {
        active: [['802.1','Higher Layer LAN Protocols'],['802.3','Ethernet'],['802.11','Wireless LAN'],['802.15','Wireless Personal Area Network (WPAN)'],['802.16','Broadband Wireless Access'],['802.17','Resilient Packet Ring'],['802.18','Radio Regulatory TAG'],['802.19','Coexistence TAG'],['802.20','Mobile Broadband Wireless Access'],['802.21','Media Independent Handoff'],['802.22','Wireless Regional Area Networks']],
        inactive: [['802.2','Logical Link Control'],['802.4','Token Bus'],['802.5','Token Ring'],['802.7','Broadband Area Network'],['802.8','Fiber Optic TAG'],['802.9','Integrated Service LAN'],['802.10','Security'],['802.12','Demand Priority'],['802.14','Cable Modem']],
      }
    },
    {
      name: 'Physical Layer', osi: 'Layer 1', col: '#3dd6d6',
      what: 'Converts bits into physical signals (electrical, optical, or radio) and transmits them across the medium. Defines voltages, frequencies, modulation, connector types, and bit timing.',
      problems: [
        ['How is a binary 1 or 0 represented as a physical signal?','On every bit transmitted across any medium','Digital bits must be mapped to physical phenomena (voltage levels, light pulses, radio waves) that the medium can carry','Without a defined signal encoding, there is no way to transmit binary data across any physical medium'],
        ['How does the receiver know where one bit ends and the next begins?','On every received bit, continuously during a transmission','Transmitter and receiver clocks are never perfectly synchronised; they drift over time','Without clock recovery, the receiver loses bit boundaries and misreads bits — even a 0.01% clock mismatch corrupts a long transmission'],
        ['How far can a signal travel before it degrades too much to read?','On any link longer than a few metres for copper, or tens of kilometres for fiber','Signals attenuate and accumulate noise with distance; at some point the receiver can\'t distinguish 1 from 0','Without amplifiers, repeaters, or optical regenerators, signal range is fundamentally limited'],
        ['How is the available bandwidth shared among multiple transmissions?','On any medium carrying more than one signal (wireless spectrum, WDM fiber, DSL)','Physical medium has finite bandwidth; uncoordinated transmissions interfere with each other','Without multiplexing (FDM, TDM, WDM), only one signal can use the medium at a time — extreme waste of capacity'],
      ],
      functions: [
        ['Signal Encoding','Converts binary bits into physical signals appropriate for the transmission medium','On every bit transmitted','NRZ, Manchester, PAM4 for copper; OOK, NRZ for fiber; OFDM/QAM for radio; encoding chosen to balance bandwidth efficiency vs clock recovery','Without encoding, there is no physical representation of digital data — nothing to transmit','Solves: how to represent bits as physical signals'],
        ['Bit Synchronisation','Ensures sender and receiver agree on bit timing so receiver can sample each bit at the correct moment','Continuously during every transmission','Self-clocking codes (Manchester) embed transitions; 8b/10b and 4b/5b add guaranteed transitions; CDR (Clock and Data Recovery) PLLs lock onto transitions','Without synchronisation, receiver samples at wrong times and misreads bits — entire frame corrupted','Solves: clock drift between sender and receiver'],
        ['Physical Medium Attachment','Defines the electrical, optical, or radio interface between the network device and the transmission medium','At the point of connection between NIC and cable/antenna/fiber','Specifies connector type (RJ45, LC, SFP+), voltage levels (±2.5V for 10BASE-T), optical wavelength (1310nm for SMF), or frequency band (2.4GHz, 5GHz for WiFi)','Without standardised connectors and signal levels, no two devices from different manufacturers would be compatible','Solves: physical incompatibility between devices'],
        ['Multiplexing','Combines multiple signals onto one physical medium to increase capacity','When multiple channels share the same wire, fiber strand, or radio spectrum','FDM: different frequencies for different channels (cable TV, DSL); TDM: time slots (T1/E1); WDM: different light wavelengths on one fiber (DWDM up to 160 channels)','Without multiplexing, each conversation requires a dedicated physical link — massively wasteful','Solves: sharing bandwidth among multiple transmissions'],
        ['Signal Amplification and Regeneration','Restores signal strength and quality degraded by distance or noise','At regular intervals along a long-haul link','Electrical amplifiers boost signal but also amplify noise; optical regenerators convert to electrical, retime, reshape, and retransmit clean optical signal (3R regeneration)','Without regeneration, signals decay below detectable levels within metres (copper) or hundreds of kilometres (fiber)','Solves: signal degradation over distance'],
        ['Forward Error Correction','Adds redundant bits to the transmitted data so the receiver can correct errors without retransmission','At high speeds (400G Ethernet, 5G NR) where BER is too high for retransmission to be practical','Reed-Solomon or LDPC codes add parity symbols; receiver uses algebraic decoding to correct up to t symbol errors per codeword','Without FEC at high speeds, the raw BER of the physical medium would cause too many errors for upper layers to handle','Solves: signal corruption from noise and interference'],
      ],
      design_issues: [
        ['Analog vs digital signalling','Early networks used purely analog signalling; modern networks use digital encoding over analog physical media','Analog is simple but accumulates noise; digital with regeneration resets noise at each repeater','All modern networks use digital encoding; analog only survives in legacy PSTN trunks and some RF links'],
        ['Bandwidth vs distance tradeoff','Higher frequencies carry more data but attenuate faster; lower frequencies travel further but carry less data','Cat5e supports 1Gbps to 100m; pushing to 10Gbps requires Cat6a and careful installation; fiber bypasses copper limits entirely','Solution depends on application: fiber for long haul, copper for last metre, radio for mobility — each optimised for its tradeoff'],
        ['Clock distribution','All digital systems need a shared timing reference; distributing accurate clocks across a network is hard','PLL-based clock recovery from data transitions is imprecise at high speeds; dedicated clock distribution adds cost and complexity','Solutions: SONET/SDH has synchronous clocking hierarchy; Ethernet uses SSM (Synchronisation Status Messages) and IEEE 1588 PTP for sub-microsecond accuracy'],
        ['Electromagnetic interference and crosstalk','Copper conductors radiate and receive electromagnetic noise; adjacent pairs in a cable couple energy to each other','Higher data rates require tighter noise margins; crosstalk worsens with frequency','Solutions: twisted pairs cancel external interference; shielding (STP) reduces EMI; differential signalling rejects common-mode noise; fiber is immune to EMI entirely'],
        ['Spectrum scarcity for wireless','Radio spectrum is a finite shared resource; demand for wireless bandwidth grows exponentially','More channels require more spectrum; spectrum is licensed and regulated; interference between adjacent channels degrades performance','Solutions: OFDMA (WiFi 6, 5G) allows fine-grained spectrum sharing; MIMO exploits spatial multiplexing; mmWave uses very high frequencies with short range for dense deployments'],
      ],
      protocols: [
        ['Ethernet Physical Standards',
        '10Base5, 10Base2, 10BaseT, 10BaseF',
        `<table>
            <tr><th>Cable Name</th><th>Cable Type</th><th>Transmission Rate</th><th>Max. length before repeater needed</th><th>Max. No. of Computer</th></tr>
            <tr><td>10Base5</td><td>Thick coaxial</td><td>10Mbsec</td><td>500 metres</td><td>100 per segment</td></tr>
            <tr><td>10Base2</td><td>Thin coaxial cable</td><td>10Mbsec</td><td>200 metres</td><td>30 per segment</td></tr>
            <tr><td>10BaseT</td><td>Twisted Pair</td><td>10/100 Mbsec</td><td>100 metres</td><td>1024 per segment</td></tr>
            <tr><td>10BaseF</td><td>Fiber Optic cable</td><td>100/1000 Mbsec</td><td>2000 metres</td><td>1024 per segment</td></tr>
          </table>`,
        'Wired LAN connections',
        'Defines cable type, transmission rate, max segment length, and max computers per segment',
        'Without standardised physical specs, cables and NICs from different vendors would be incompatible'],
        ['IEEE 802.11 Physical Layer','802.11a/b/g/n/ac/ax (WiFi 4/5/6)',`<table>
          <tr><th>Protocol</th><th>Release Date</th><th>Op. Frequency</th><th>Data Rate (Max)</th><th>Range (indoor)</th><th>Range (outdoor)</th></tr>
          <tr><td>Legacy</td><td>1997</td><td>2.5~2.5 GHz</td><td>2 Mbit/s</td><td>—</td><td>—</td></tr>
          <tr><td>802.11a</td><td>1999</td><td>5.15~5.35 / 5.47~5.725 / 5.725~5.875 GHz</td><td>54 Mbit/s</td><td>~25 m</td><td>~75 m</td></tr>
          <tr><td>802.11b</td><td>1999</td><td>2.4~2.5 GHz</td><td>11 Mbit/s</td><td>~35 m</td><td>~100 m</td></tr>
          <tr><td>802.11g</td><td>2003</td><td>2.4~2.5 GHz</td><td>54 Mbit/s</td><td>~25 m</td><td>~75 m</td></tr>
          <tr><td>802.11n</td><td>2007</td><td>2.4 GHz or 5 GHz</td><td>540 Mbit/s</td><td>~50 m</td><td>~125 m</td></tr>
        </table>`,'All WiFi connections','Defines frequency band (2.4GHz, 5GHz, 6GHz), channel width (20/40/80/160MHz), modulation (OFDM, OFDMA), MIMO spatial streams, and max throughput per spec','Without these standards, WiFi devices from Apple, Intel, and Qualcomm would be incompatible — no interoperable wireless networking'],
        ['SONET / SDH','Synchronous Optical Networking / Synchronous Digital Hierarchy','Synchronous optical transport standard for telco backbones','Long-haul carrier networks, submarine cables, metro rings','Defines optical wavelengths, frame structure (STS-1 = 51.84Mbps, OC-192 = 10Gbps), synchronous clocking hierarchy, and APS (Automatic Protection Switching) for sub-50ms failover','Without SONET/SDH, long-haul optical networks would have no common framing or protection switching standard'],
        ['DSL','Digital Subscriber Line (ADSL, VDSL, G.fast)','High-speed data over existing copper telephone local loops','Residential and business broadband over copper','FDM separates upstream/downstream/POTS bands; DMT (Discrete MultiTone) modulates data onto hundreds of subcarriers; adaptive modulation adjusts per-subcarrier QAM based on line quality','Without DSL, ISPs would need to lay new fiber to every home to provide broadband — DSL reused existing copper infrastructure'],
        ['5G NR Physical Layer','5G New Radio (3GPP Release 15+)','Physical layer for 5G cellular networks','Mobile broadband, IoT, industrial wireless, fixed wireless access','OFDMA with flexible numerology (subcarrier spacing 15kHz–240kHz); massive MIMO (64+ antennas); beamforming; mmWave (24–100GHz) and sub-6GHz bands; LDPC and Polar codes for FEC','Without 5G NR, mobile networks would be capacity-limited by 4G LTE — insufficient for dense deployments and ultra-low latency applications'],
        ['PAM4','Pulse Amplitude Modulation 4-level','4-level signal encoding for high-speed Ethernet and PCIe','400G/800G Ethernet, PCIe 6.0, high-speed optical interconnects','4 voltage levels encode 2 bits per symbol; doubles throughput at same baud rate as NRZ; requires DSP equalisation and RS-FEC to correct higher BER from tighter voltage margins','Without PAM4, doubling Ethernet speed would require doubling the baud rate — hitting physical limits of copper and optics at lower data rates'],
      ]
    },
  ];

  const info = LAYER_INFO[layerIndex];
  zoomPanel.classList.add('visible');
  zoomTitle.innerHTML = `<span style="color:${info.col}">${info.name}</span> <span style="font-size:12px;opacity:0.5;font-weight:400">${info.osi}</span>`;

  function layerTable(cols, rows, firstColColor) {
    return `<div style="overflow-x:auto"><table class="detail-table" style="min-width:600px">
      <thead><tr>${cols.map(c=>`<th>${escHtml(c)}</th>`).join('')}</tr></thead>
      <tbody>${rows.map(r=>`<tr>${r.map((c,i)=>`<td class="${i===0?'dt-field':'dt-what'}" style="${i===0&&firstColColor?'color:'+firstColColor+';white-space:nowrap':''}">${String(c).trimStart().startsWith('<') ? String(c) : escHtml(String(c))}</td>`).join('')}</tr>`).join('')}</tbody>
    </table></div>`;
  }

  zoomContent.innerHTML = `
    <div class="zoom-subtitle">${escHtml(info.what)}</div>

    <div class="zoom-section">
      <div class="zoom-section-title">Problems</div>
      ${layerTable(['What','When','How it manifests','Why it matters'], info.problems, null)}
    </div>

    <div class="zoom-section">
      <div class="zoom-section-title">Functions</div>
      ${layerTable(['Function','What it does','When','How','Why','Solves'], info.functions, info.col)}
    </div>

    <div class="zoom-section">
      <div class="zoom-section-title">Design Issues</div>
      ${layerTable(['Issue','What','Why it\'s hard','Tradeoff / Resolution'], info.design_issues, null)}
    </div>

    <div class="zoom-section">
      <div class="zoom-section-title">Protocols</div>
      ${layerTable(['Protocol','Full Name','What','When','How','Why'], info.protocols, info.col)}
    </div>
    ${info.working_groups ? `
    <div class="zoom-section">
      <div class="zoom-section-title">IEEE 802 Working Groups — Active</div>
      ${layerTable(['Group','Working Group Name'], info.working_groups.active, info.col)}
    </div>
    <div class="zoom-section">
      <div class="zoom-section-title">IEEE 802 Working Groups — Inactive / Disbanded</div>
      ${layerTable(['Group','Working Group Name'], info.working_groups.inactive, null)}
    </div>` : ''}`;
}
// ─── ZOOM RENDER ──────────────────────────────────────────────
function renderZoom(section, pkt) {
  const t = pkt.tcp;
  const ip = pkt.ip;
  const l = pkt.llc;
  const m = pkt.mac;

  let titleHtml = '';
  let html = '';

  // grid-based header diagram: rows of cells with proportional flex widths
  function hdrGrid(rows, color) {
    return `<div class="hdr-grid-wrap">` + rows.map(row =>
      `<div class="hdr-grid-row">` + row.map(([label, val, flex]) =>
        `<div class="hdr-grid-cell" style="flex:${flex||1};border-color:${color}40">
          <div class="hdr-gc-label" style="color:${color}">${escHtml(label)}</div>
          <div class="hdr-gc-val" style="color:${color}">${escHtml(String(val))}</div>
        </div>`
      ).join('') + `</div>`
    ).join('') + `</div>`;
  }

  function detailTable(rows) {
    return `<table class="detail-table">
      <thead><tr>
        <th>Field</th><th>Value</th><th>Bits</th><th>What</th><th>Why / Purpose</th><th>How</th><th>Cases</th>
      </tr></thead>
      <tbody>${rows.map(([name,val,bits,what,why,how,cases])=>
        `<tr>
          <td class="dt-field">${escHtml(name)}</td>
          <td class="dt-val">${escHtml(String(val))}</td>
          <td class="dt-bits">${escHtml(dispBitsLabel(bits||''))}</td>
          <td class="dt-what">${escHtml(String(what||''))}</td>
          <td class="dt-why">${escHtml(String(why||''))}</td>
          <td class="dt-how">${escHtml(String(how||''))}</td>
          <td class="dt-cases">${cases ? cases.map(([v,desc])=>`<div class="case-row"><span class="case-val">${escHtml(v)}</span><span class="case-desc">${escHtml(desc)}</span></div>`).join('') : '<span style="opacity:0.35">—</span>'}</td>
        </tr>`
      ).join('')}</tbody>
    </table>`;
  }

  if (section === 'data' || section === 'data-1' || section === 'data-2' || section === 'data-3' || section === 'data-4') {
    const layerIdx = section === 'data' ? 0 : parseInt(section.split('-')[1]);
    const pduNames = ['Application Data','TCP Segment','IP Packet','LLC Frame','MAC Frame'];
    const pduColors = ['#4f8ef7','#3dd68c','#f5a623','#f75f5f','#c97bf7'];
    const pduDescs = [
      'Raw payload — your message as seen at the application layer',
      'TCP Segment — application data wrapped with a TCP header for reliable delivery',
      'IP Packet — TCP segment wrapped with an IP header for logical addressing and routing',
      'LLC Frame — IP packet wrapped with LLC header and trailer for data link multiplexing',
      'MAC Frame — LLC frame wrapped with MAC header and trailer for physical addressing',
    ];
    titleHtml = `<span style="color:${pduColors[layerIdx]}">${pduNames[layerIdx]}</span>`;
    html = `
      <div class="zoom-subtitle">${pduDescs[layerIdx]}</div>
      <div class="zoom-section">
        <div class="zoom-section-title">Plaintext</div>
        <div style="font-family:var(--font-mono);font-size:14px;background:var(--bg3);border:1px solid var(--border);border-radius:4px;padding:16px;word-break:break-all;line-height:1.8;color:var(--text)">${escHtml(pkt.segText)}</div>
      </div>
      <div class="zoom-section">
        <div class="zoom-section-title">Bytes (decimal)</div>
        <div class="binary-display">${pkt.dataBytes.join(' ')}</div>
      </div>
      <div class="zoom-section">
        <div class="zoom-section-title">Bytes (binary)</div>
        <div class="binary-display">${bytesBin(pkt.dataBytes)}</div>
      </div>
      <div class="zoom-section">
        <div class="zoom-section-title">Segment info</div>
        ${detailTable([
          ['Segment index', pkt.segIndex, '—', 'Position in stream', 'Reassembly ordering', 'TCP seq number tracks this'],
          ['Total segments', pkt.totalSegs, '—', 'How many chunks', 'Shows fragmentation degree', 'Derived from msg length ÷ MSS'],
          ['Payload size', pkt.dataLen+' bytes', '≤'+MSS*8+' b', 'Actual bytes in this chunk', 'Bounded by MSS', 'strlen of segment text'],
          ['MSS', MSS+' bytes', '—', 'Max Segment Size', 'Prevents IP fragmentation', 'Negotiated in TCP handshake'],
        ])}
      </div>`;
  }

  else if (section === 'udp') {
    const udpLen = pkt.dataLen + 8;
    const udpCksum = checksum16([...pkt.dataBytes, pkt.tcp.srcPort>>8, pkt.tcp.srcPort&0xff, pkt.tcp.dstPort>>8, pkt.tcp.dstPort&0xff]);
    titleHtml = `<span style="color:#ffb432">UDP Header</span>`;
    html = `
      <div class="zoom-subtitle">User Datagram Protocol — Transport Layer (Layer 4). Connectionless, unreliable, low-overhead delivery.</div>
      <div class="zoom-section">
        <div class="zoom-section-title">Header structure (8 bytes fixed)</div>
        ${hdrGrid([
          [['Source Port', pkt.tcp.srcPort, 2], ['Destination Port', pkt.tcp.dstPort, 2]],
          [['Length', udpLen, 2], ['Checksum', udpCksum, 2]],
          [['Data', '(payload)', 4]],
        ], '#ffb432')}
      </div>
      <div class="zoom-section">
        <div class="zoom-section-title">Field details</div>
        ${detailTable([
          ['Source Port', pkt.tcp.srcPort, '16 bits', 'Port number of the sending process', 'Identifies which application sent this datagram; receiver uses it to send replies', 'OS assigns ephemeral port; well-known services use fixed ports', [['1–1023','Well-known ports (root-only)'],['1024–49151','Registered ports'],['49152–65535','Ephemeral — OS assigned']]],
          ['Destination Port', pkt.tcp.dstPort, '16 bits', 'Port number of the receiving process', 'OS demultiplexes incoming datagram to correct application socket', 'Set by sender to target service port', [['53','DNS'],['67/68','DHCP'],['69','TFTP'],['161','SNMP'],['123','NTP'],['5353','mDNS']]],
          ['Length', udpLen, '16 bits', 'Total length of UDP header + data in bytes', 'Receiver knows where the datagram ends', 'Minimum 8 (header only, no data); maximum 65535', [['8','Header only — no payload'],['65535','Maximum theoretical; IP limits practical size'],['512','Common DNS UDP limit before TCP fallback']]],
          ['Checksum', udpCksum, '16 bits', "One's complement checksum over pseudo-header + UDP header + data", 'Detects corruption; optional in IPv4 (0x0000 = disabled), mandatory in IPv6', 'Pseudo-header includes src IP, dst IP, protocol (17), UDP length', [['0x0000','Checksum disabled (IPv4 only) — receiver accepts without checking'],['Non-zero','Checksum enabled; receiver recomputes and discards on mismatch'],['Mandatory IPv6','IPv6 removed IP header checksum so UDP checksum is required']]],
          ['Data', '(payload)', 'variable', 'Application data carried by this datagram', 'UDP adds no overhead beyond these 8 bytes — entire payload delivered as-is', 'No segmentation; application must fit data in one datagram or segment itself', [['DNS query','~50 bytes typical'],['VoIP frame','20ms of G.711 = 160 bytes'],['Video RTP','Up to ~1400 bytes to avoid IP fragmentation'],['No data','Valid — 8-byte UDP header with empty payload used for port probing']]],
        ])}
      </div>
      <div class="zoom-section">
        <div class="zoom-section-title">UDP vs TCP</div>
        <div style="overflow-x:auto"><table class="detail-table">
          <thead><tr><th>Feature</th><th>UDP</th><th>TCP</th></tr></thead>
          <tbody>
            <tr><td class="dt-field">Header size</td><td class="dt-what">8 bytes</td><td class="dt-what">20–60 bytes</td></tr>
            <tr><td class="dt-field">Connection</td><td class="dt-what">Connectionless</td><td class="dt-what">Connection-oriented (3-way handshake)</td></tr>
            <tr><td class="dt-field">Reliability</td><td class="dt-what">None — fire and forget</td><td class="dt-what">Guaranteed delivery with retransmission</td></tr>
            <tr><td class="dt-field">Ordering</td><td class="dt-what">No — datagrams may arrive out of order</td><td class="dt-what">Yes — sequence numbers enforce order</td></tr>
            <tr><td class="dt-field">Flow control</td><td class="dt-what">None</td><td class="dt-what">Sliding window</td></tr>
            <tr><td class="dt-field">Congestion control</td><td class="dt-what">None — sender's problem</td><td class="dt-what">Slow start, AIMD, BBR</td></tr>
            <tr><td class="dt-field">Speed</td><td class="dt-what">Fast — minimal overhead</td><td class="dt-what">Slower — ACKs, handshake, retransmit</td></tr>
            <tr><td class="dt-field">Use cases</td><td class="dt-what">DNS, VoIP, video, gaming, DHCP, SNMP</td><td class="dt-what">HTTP, FTP, SMTP, SSH, database queries</td></tr>
            <tr><td class="dt-field">Broadcast/Multicast</td><td class="dt-what">Supported</td><td class="dt-what">Not supported</td></tr>
          </tbody>
        </table></div>
      </div>`;
  }

  else if (section === 'tcp') {
    titleHtml = `<span style="color:#3dd68c">TCP Header</span>`;
    html = `
      <div class="zoom-subtitle">Transmission Control Protocol — Transport Layer (Layer 4). Reliable, ordered, error-checked delivery.</div>
      <div class="zoom-section">
        <div class="zoom-section-title">Header structure (20–60 bytes)</div>
        ${hdrGrid([
          [['Source Port Address', t.srcPort, 2], ['Destination Port Address', t.dstPort, 2]],
          [['Sequence Number', t.seqNum, 4]],
          [['Acknowledgement Number', t.ackNum, 4]],
          [['HLEN','5',0.5],['Reserved','000000',0.75],['URG', t.tcpFlags.includes('URG')?'1':'0',0.25],['ACK', t.tcpFlags.includes('ACK')?'1':'0',0.25],['PSH', t.tcpFlags.includes('PSH')?'1':'0',0.25],['RST', t.tcpFlags.includes('RST')?'1':'0',0.25],['SYN', t.tcpFlags.includes('SYN')?'1':'0',0.25],['FIN', t.tcpFlags.includes('FIN')?'1':'0',0.25],['Window Size', t.window, 2]],
          [['Checksum', t.tcpCksum, 2], ['Urgent Pointer', t.tcpFlags.includes('URG') ? t.tcpCksum : '0x0000', 2]],
          [['Options and Padding (up to 40 bytes)','—',4]],
        ], '#3dd68c')}
      </div>
      <div class="zoom-section">
        <div class="zoom-section-title">Field details</div>
        ${detailTable([
          ['Source Port', t.srcPort, '16 bits', 'Port number of the sending process on the sender\'s host', 'Identifies which application or socket sent this segment; combined with src IP forms one half of the 4-tuple that uniquely identifies a connection', 'OS assigns an ephemeral port (typically 49152–65535) from its pool when a socket is created; well-known servers bind to fixed ports', [['1–1023','Well-known port: root-only on Unix. e.g. 80=HTTP, 443=HTTPS, 22=SSH'],['1024–49151','Registered port: assigned by IANA to specific services. e.g. 3306=MySQL, 5432=Postgres'],['49152–65535','Ephemeral port: OS-assigned for outgoing connections; released when socket closes']]],
          ['Destination Port', t.dstPort, '16 bits', 'Port number of the receiving process on the destination host', 'Combined with dst IP tells the receiving OS which process\'s socket queue to deliver the segment to', 'Sender sets this to the service\'s well-known port (e.g. 80 for HTTP); receiver\'s OS demultiplexes to the listening socket', [['80','HTTP — web server expects unencrypted requests'],['443','HTTPS — web server expects TLS handshake first'],['22','SSH — secure shell'],['25','SMTP — mail transfer'],['53','DNS — domain name queries (also UDP)'],['Any other','Receiver checks if a socket is bound; if not, replies RST']]],
          ['Sequence Number', t.seqNum, '32 bits', 'Byte-stream offset of the first byte in this segment\'s payload', 'Allows receiver to reassemble segments in correct order even if they arrive out of order; detects duplicates', 'Starts at a random Initial Sequence Number (ISN) chosen during SYN to prevent blind injection attacks; incremented by payload length each segment', [['ISN (SYN)','Random starting value selected by OS to prevent old duplicate segments from being accepted'],['ISN+1 (SYN-ACK)','SYN itself consumes one sequence number; data starts at ISN+1'],['Wraps at 2³²','Sequence space wraps; TCP handles this transparently'],['Duplicate seq','Receiver discards silently; duplicate detected by comparing against expected range']]],
          ['Acknowledgement #', t.ackNum, '32 bits', 'The next sequence number the sender of this ACK expects to receive — i.e. cumulative confirmation of all bytes up to (ackNum−1)', 'Tells the other side which bytes have been successfully received; drives retransmission timer reset', 'Only valid when ACK flag = 1. On the very first SYN, ACK=0 and this field is meaningless', [['0 (ACK=0)','Field is invalid; occurs only on the initial SYN before connection is established'],['Peer ISN+1','Set on SYN-ACK: confirms receipt of SYN, requests data start at this offset'],['Skips a value','Gap means missing data; sender must retransmit starting at the gap'],['Decreases','Never valid in normal operation; would indicate a protocol error or attack']]],
          ['HLEN (Data Offset)', '5 (=20 bytes)', '4 bits', 'Length of the TCP header measured in 32-bit (4-byte) words', 'Receiver needs to know where the header ends and the application data begins, especially when optional fields are present', '5 × 4 = 20 bytes is the minimum (no options). Maximum is 15 × 4 = 60 bytes', [['5 (20 bytes)','No options present; most common case'],['6–14','Options present: e.g. MSS, SACK, timestamps, window scale'],['15 (60 bytes)','Maximum; 40 bytes of options after the 20-byte base header'],['<5','Invalid; implies a malformed packet — receiver should discard']]],
          ['Reserved', '000000', '6 bits', 'Six bits reserved for future protocol extensions', 'RFC 793 requires these to be zero; allows future RFCs to define new flags without changing the header structure', 'Sender must set to 0; receiver must ignore them to maintain forward compatibility', [['000000','Normal — all reserved bits clear'],['Non-zero','Technically invalid per RFC 793; in practice most stacks ignore; could indicate a fingerprinting or covert-channel attempt']]],
          ['Flag — URG', t.tcpFlags.includes('URG')?'1':'0', '1 bit', 'Signals that the Urgent Pointer field contains a valid offset pointing to out-of-band (urgent) data', 'Allows one end to signal the other to process urgent data immediately, bypassing normal buffering — used historically for interactive applications like Telnet BREAK', 'When URG=1, receiver reads Urgent Pointer to find where urgent data ends; delivers it ahead of normal data', [['0','Normal data; Urgent Pointer field is ignored'],['1','Urgent data present; receiver passes it to application out-of-band. Rarely used in modern protocols; most stacks implement it but few apps use it']]],
          ['Flag — ACK', t.tcpFlags.includes('ACK')?'1':'0', '1 bit', 'Indicates that the Acknowledgement Number field is valid and should be processed', 'Every packet after the initial SYN must carry ACK=1 to drive the other side\'s retransmission timers and window management', 'Set to 0 only on the very first SYN. After that, always 1 for the life of the connection', [['0','Only on initial SYN; Acknowledgement Number field is meaningless'],['1','Acknowledgement Number is valid; receiver updates its send window and clears retransmission timers for ACKed bytes']]],
          ['Flag — PSH', t.tcpFlags.includes('PSH')?'1':'0', '1 bit', 'Requests the receiver to push buffered data to the application immediately rather than waiting to fill a larger buffer', 'Without PSH, a receiving OS might batch small segments before delivering to the app, increasing latency — PSH forces immediate delivery', 'Typically set on the last segment of an application write; most modern OSes set it automatically', [['0','Receiver may buffer data until it accumulates enough to pass up efficiently'],['1','Receiver must flush its buffer to the application immediately; important for interactive protocols (HTTP/1.1 headers, SSH keystrokes)']]],
          ['Flag — RST', t.tcpFlags.includes('RST')?'1':'0', '1 bit', 'Abruptly resets (aborts) the connection — no graceful teardown', 'Handles error conditions: connection to a closed port, half-open connections, invalid segments. Also used to forcibly terminate a connection', 'Receiving a RST causes the socket to close immediately; any buffered data is discarded; no FIN-WAIT states', [['0','Normal; connection continues'],['1 (in response to SYN)','Port is closed — no process is listening'],['1 (mid-connection)','Connection aborted: the sender lost state (crashed/rebooted) or detected an invalid segment'],['1 (from firewall)','Firewall is actively terminating the connection; looks like a TCP RST injection']]],
          ['Flag — SYN', t.tcpFlags.includes('SYN')?'1':'0', '1 bit', 'Synchronises sequence numbers at the start of a TCP connection — part of the 3-way handshake', 'Without a known ISN, the receiver cannot detect out-of-order or duplicate segments', 'Set only on the first two packets of a connection (SYN and SYN-ACK); never after that', [['0','Normal data segment or FIN/RST; connection already established'],['1 (no ACK)','Initial SYN: client requesting connection; server not yet contacted'],['1 (with ACK)','SYN-ACK: server accepting connection, acknowledging client SYN'],['1 mid-connection','Invalid — causes RST; could indicate a SYN flood or confused stack']]],
          ['Flag — FIN', t.tcpFlags.includes('FIN')?'1':'0', '1 bit', 'Signals that the sender has finished sending data — initiates graceful half-close', 'TCP connections are full-duplex; each side closes independently. FIN closes one direction; the other direction can still send data', 'FIN consumes one sequence number. Receiver ACKs it. When both sides have sent FIN, the connection is fully closed after TIME_WAIT', [['0','Sender still has data to send'],['1 (active close)','Sender has no more data; waiting for peer\'s FIN+ACK to fully close'],['1 + ACK','Simultaneous close: both sides sent FIN at nearly the same time'],['FIN without prior data','Valid: sender opens a connection, sends nothing, then closes — e.g. a port scanner or health check']]],
          ['Window Size', t.window, '16 bits', 'The number of bytes the sender of this segment is willing to receive before requiring an ACK — its current receive buffer space', 'Prevents the sender from overwhelming the receiver\'s buffer (flow control). Combined with congestion window, controls overall send rate', 'Receiver advertises this value; sender may not have more than this many unACKed bytes in flight. Window Scale option multiplies this for high-bandwidth links', [['0','Receiver buffer is full — sender must stop sending (zero window); sender probes periodically with 1-byte segments'],['65535 (max)','Maximum without Window Scale option; effective window up to 1GB with Window Scale'],['Increases','Receiver buffer freeing up; sender can increase its flight size'],['Decreases (shrinks)','Receiver under memory pressure; sender must immediately reduce in-flight data — "shrinking the window" is discouraged by RFC 793 but allowed']]],
          ['Checksum', t.tcpCksum, '16 bits', 'One\'s complement checksum over a pseudo-header (src IP, dst IP, protocol, TCP length) + TCP header + TCP data', 'Detects corruption of the segment in transit. The pseudo-header includes IP fields to prevent misdelivered segments from being silently accepted', 'Computed by sender; recomputed by receiver; mismatch → segment silently dropped (TCP relies on retransmit)', [['Valid','Segment accepted and processed normally'],['Invalid','Segment silently discarded; sender\'s retransmit timer will eventually fire'],['All-zeros','Optional in IPv6 UDP but NOT valid for TCP — TCP checksum is mandatory'],['Hardware offload','NIC computes/verifies checksum in hardware; OS stack never touches it — appears as 0x0000 in captures before NIC processes it']]],
          ['Urgent Pointer', t.tcpFlags.includes('URG')?'(active)':'0x0000', '16 bits', 'Byte offset from the sequence number to the last byte of urgent data — only meaningful when URG=1', 'Allows receiver to identify exactly which bytes are urgent so it can deliver them out-of-band to the application', 'RFC 793 originally said this points to the last urgent byte; RFC 1122 clarified it points one past the urgent data — implementations differ', [['0x0000 (URG=0)','Field is ignored; normal segment'],['Non-zero (URG=1)','Points to end of urgent data region; receiver passes data up to that offset to the app immediately'],['Historical use','Telnet used URG+PSH to send BREAK/Ctrl-C signals; SSH replaces this with channel requests']]],
          ['Options', '—', '0–40 bytes', 'Variable-length field for optional TCP extensions negotiated during or after the handshake', 'Enables capabilities not in the original RFC 793 spec: larger windows, selective ACK, better timestamps, faster open', 'Only present if HLEN > 5. Each option has a Kind byte, a Length byte (except Kind 0 and 1), and data. Padded to 32-bit boundary', [['MSS (Kind=2)','Maximum Segment Size: receiver announces the largest payload it will accept — typically 1460 bytes for Ethernet'],['Window Scale (Kind=3)','Multiplies window size by 2^n (up to 2^14=16384); enables windows >65535 bytes needed for high-speed/high-latency links'],['SACK (Kind=4/5)','Selective ACK: receiver reports non-contiguous received blocks so sender retransmits only truly missing segments, not everything after the gap'],['Timestamps (Kind=8)','RTT measurement and PAWS (Protection Against Wrapped Sequence numbers) for high-speed links where the 32-bit seq space wraps in under 1 minute'],['TFO (Kind=34)','TCP Fast Open: client includes a cookie to allow data in the SYN, reducing latency by one RTT for repeat connections']]],
          ['Padding', '—', '0–3 bytes', 'Zero bytes appended after Options to make the header end on a 32-bit word boundary', 'TCP header must be a multiple of 4 bytes (HLEN is in 4-byte units). Padding fills any gap after options', 'Filled with 0x00 bytes; receiver ignores them', [['0 bytes','No options, or options already aligned to 4-byte boundary'],['1–3 bytes','Options present with non-aligned total length; padding added to reach next 4-byte boundary'],['Incorrect padding','Can cause receiver to misparse option boundaries, leading to segment rejection']]],
        ])}
      </div>`;
  }

  else if (section === 'ip') {
    titleHtml = `<span style="color:#f5a623">IP Header</span> <button id="ip-ver-toggle" style="font-family:var(--font-mono);font-size:11px;padding:4px 14px;border-radius:4px;border:1px solid #f5a623;background:transparent;color:#f5a623;cursor:pointer;margin-left:12px">${STATE.ipVersion === 4 ? 'Switch to IPv6 →' : 'Switch to IPv4 →'}</button>`;
    if (STATE.ipVersion === 4) {
      html = `
        <div class="zoom-subtitle">Internet Protocol v4 — Network Layer (Layer 3). Logical addressing and packet routing.</div>
        <div class="zoom-section">
          <div class="zoom-section-title">Header structure (20–60 bytes) — 16 bits | 16 bits</div>
          ${hdrGrid([
            [['Version','4',0.5],['IHL','5 (20B)',0.5],['DSCP/TOS','0x00',1],['Total Length', ip.ipLen, 2]],
            [['Identification', ip.ipId, 2],['Rsv','0',0.2],['DF','1',0.2],['MF','0',0.2],['Frag Offset','0',1.4]],
            [['Time to Live', ip.ipTTL, 1],['Protocol','TCP (6)',1],['Header Checksum', ip.ipCksum, 2]],
            [['Source IP Address', ip.srcIp, 4]],
            [['Destination IP Address', ip.dstIp, 4]],
            [['Options (0–40 bytes)', '—', 4]],
            [['Data', '(TCP segment)', 4]],
          ], '#f5a623')}
        </div>
        <div class="zoom-section">
          <div class="zoom-section-title">Field details</div>
          ${detailTable([
            ['Version', '4', '4 bits', 'IP protocol version number embedded in every packet header', 'Routers and hosts must know how to parse the rest of the header; a different version means a completely different header format', 'Hard-coded by the sending OS/NIC to 4 for IPv4 or 6 for IPv6; cannot be changed per-packet', [['4','IPv4 — 32-bit addresses, 20-byte base header, ~4 billion addresses'],['6','IPv6 — 128-bit addresses, 40-byte fixed header, effectively unlimited addresses'],['Other','Reserved or experimental; silently dropped by most routers']]],
            ['IHL (Header Length)', '5 (=20 bytes)', '4 bits', 'Length of the IP header in 32-bit words, including any options', 'Receiver must know where the header ends and the payload begins', '5 × 4 = 20 bytes minimum; each 4-byte option block adds 1', [['5 (20 bytes)','No options — most common'],['6–14','Options present'],['15 (60 bytes)','Maximum — 40 bytes of options'],['<5','Invalid; receiver must discard']]],
            ['DSCP (TOS)', '0x00', '6 bits', 'Differentiated Services Code Point — QoS marking', 'Priority queuing at routers for latency-sensitive traffic', 'Set by sending app or OS; routers read it to select queue', [['0x00 (CS0)','Best-effort default'],['0x28 (CS5)','Voice-grade priority'],['0x2E (EF)','Expedited Forwarding — guaranteed low latency']]],
            ['ECN', '00', '2 bits', 'Explicit Congestion Notification', 'Signals congestion without dropping packets', 'Router marks ECT packets with CE; endpoint reduces send rate', [['00','Not ECN-capable'],['01 or 10','ECN-capable transport'],['11 (CE)','Congestion Experienced']]],
            ['Total Length', ip.ipLen+' bytes', '16 bits', 'Total size of entire IP packet in bytes', 'Receiver knows exactly where packet ends', 'IHL×4 + TCP segment + data', [['20 bytes','Header only'],['1500 bytes','Standard Ethernet MTU'],['65535 bytes','Maximum']]],
            ['Identification', ip.ipId, '16 bits', 'Groups all fragments of the same original datagram', 'Destination reassembles fragments with same ID', 'Sender increments counter per packet', [['Same ID, multiple packets','All fragments of one datagram'],['Unique per datagram','Normal unfragmented packet']]],
            ['Flag — DF', '1', '1 bit', "Don't Fragment — instructs routers not to fragment", 'Enables Path MTU Discovery', 'If too large, router drops and sends ICMP Type 3 Code 4', [['0','Fragmentation allowed'],['1','No fragmentation; enables PMTUD']]],
            ['Flag — MF', '0', '1 bit', 'More Fragments — set on all but last fragment', 'Receiver knows more fragments are coming', 'Set by fragmenting router; cleared on last fragment', [['0','Last or only fragment'],['1','More fragments follow']]],
            ['Fragment Offset', '0', '13 bits', "Position of fragment's data in original datagram (8-byte units)", 'Enables correct reassembly regardless of arrival order', 'byte_offset ÷ 8', [['0','First or only fragment'],['Non-zero','Middle or last fragment']]],
            ['TTL', ip.ipTTL, '8 bits', 'Maximum router hops before packet is discarded', 'Prevents routing loops from circulating packets forever', 'Each router decrements by 1; at 0 sends ICMP Type 11', [['64','Linux/macOS default'],['128','Windows default'],['255','Maximum; used by routing protocols'],['1','Dropped at next hop']]],
            ['Protocol', 'TCP (6)', '8 bits', 'Identifies transport-layer protocol in payload', 'Receiving host hands payload to correct transport handler', 'IANA protocol number registry', [['1','ICMP'],['6','TCP'],['17','UDP'],['41','IPv6-in-IPv4'],['89','OSPF']]],
            ['Header Checksum', ip.ipCksum, '16 bits', "One's complement checksum of IP header only", 'Detects header corruption; prevents misrouting', 'Recomputed at every router; IPv6 eliminated this field', [['Valid','Router forwards'],['Invalid','Router silently discards']]],
            ['Source IP', ip.srcIp, '32 bits', 'IPv4 address of originating host', 'Return path routing', 'Set by OS; rewritten by NAT; can be spoofed', [['Private (RFC 1918)','NATted before internet'],['Spoofed','Used in DDoS reflection attacks']]],
            ['Destination IP', ip.dstIp, '32 bits', 'IPv4 address of intended recipient', 'Every router does longest-prefix-match lookup on this', 'Set by application via DNS or hardcoded', [['Unicast','One host'],['Broadcast (255.255.255.255)','All hosts on LAN'],['Multicast (224.x.x.x)','Group of subscribers']]],
            ['Options', '—', '0–40 bytes', 'Optional fields for routing/diagnostic functions', 'Record Route, Source Route, Timestamp', 'IHL > 5 signals options present; rarely used in production', [['Record Route','Each router appends its IP'],['Strict Source Route','Exact path required'],['Timestamp','Routers record arrival time']]],
            ['Padding', '—', '0–3 bytes', 'Zero-fill to 32-bit boundary', 'Ensures header ends on word boundary', 'Added after options if needed'],
          ])}
        </div>`;
    } else {
      html = `
        <div class="zoom-subtitle">Internet Protocol v6 — 128-bit addressing, simplified header, mandatory IPsec support.</div>
        <div class="zoom-section">
          <div class="zoom-section-title">Header structure (40 bytes fixed)</div>
          ${hdrGrid([
            [['Version','6',0.5],['Traffic Class','0x00',1],['Flow Label','0x00000',2.5]],
            [['Payload Length','(varies)',2],['Next Header','TCP (6)',1],['Hop Limit','64',1]],
            [['Source Address (128 bits — 4 rows × 32 bits)','2001:db8::1',4]],
            [['','','4']],
            [['','','4']],
            [['','','4']],
            [['Destination Address (128 bits)','10::1',4]],
            [['','','4']],
            [['','','4']],
            [['','','4']],
          ], '#f5a623')}
        </div>
        <div class="zoom-section">
          <div class="zoom-section-title">Field details</div>
          ${detailTable([
            ['Version', '6', '4 bits', 'IP version — always 6 for IPv6', 'Router identifies header format', 'Hard-coded to 6', [['6','IPv6'],['4','IPv4 — different header entirely']]],
            ['Traffic Class', '0x00', '8 bits', 'Equivalent to IPv4 DSCP+ECN — QoS marking', 'Priority queuing; congestion notification', 'Upper 6 bits = DSCP; lower 2 bits = ECN', [['0x00','Best-effort'],['0x28','Voice priority'],['0xB8 (EF)','Expedited Forwarding']]],
            ['Flow Label', '0x00000', '20 bits', 'Identifies a flow for special handling by routers', 'Allows routers to handle packets of the same flow identically without inspecting upper-layer headers', 'Set by source; routers use it for consistent per-flow forwarding; 0 = no special handling', [['0','No flow label; generic forwarding'],['Non-zero','Flow identified; router may cache forwarding decision for efficiency']]],
            ['Payload Length', '(varies)', '16 bits', 'Length of everything after the 40-byte fixed header in bytes', 'Receiver knows where the packet ends', 'Does NOT include the 40-byte header itself (unlike IPv4 Total Length)', [['0 with Hop-by-Hop option','Jumbogram — payload length in option'],['Max 65535','Standard; larger needs Jumbogram option']]],
            ['Next Header', 'TCP (6)', '8 bits', 'Identifies the type of header immediately following the IPv6 header', 'Extension headers chain via Next Header fields; last one points to the transport layer', 'Same values as IPv4 Protocol field; extension headers use their own values', [['6','TCP'],['17','UDP'],['43','Routing extension header'],['44','Fragment extension header'],['50','ESP — IPsec encryption'],['58','ICMPv6'],['59','No next header — end of headers']]],
            ['Hop Limit', '64', '8 bits', 'Maximum hops — renamed from IPv4 TTL', 'Prevents routing loops', 'Each router decrements by 1; at 0 sends ICMPv6 Time Exceeded', [['64','Common default'],['255','Routing protocols (link-local only)'],['0','Drop immediately']]],
            ['Source Address', '128 bits', '128 bits', 'IPv6 address of originating host — 16 bytes', '340 undecillion possible addresses; no NAT needed', 'Written as 8 groups of 4 hex digits; :: compresses consecutive zero groups', [['::1','Loopback (equivalent to 127.0.0.1)'],['fe80::/10','Link-local — not routable; auto-configured'],['2001:db8::/32','Documentation/example range'],['fc00::/7','Unique local (RFC 4193) — like private IPv4'],['2000::/3','Global unicast — routable on internet']]],
            ['Destination Address', '128 bits', '128 bits', 'IPv6 address of intended recipient', 'Routers do longest-prefix match; no broadcast in IPv6', 'Anycast: same address on multiple servers — routed to nearest', [['Unicast','One interface'],['Multicast ff00::/8','Group; replaces IPv4 broadcast entirely'],['Anycast','Multiple interfaces; nearest wins'],['ff02::1','All nodes on link'],['ff02::2','All routers on link']]],
            ['Extension Headers', '—', 'Variable', 'Optional headers chained between IPv6 header and payload', 'Replaces IPv4 Options field; routers skip unrecognized extension headers instead of dropping', 'Each has Next Header + Length + Data; processed only by destination (except Hop-by-Hop)', [['Hop-by-Hop (0)','Every router must process; used for Jumbograms and router alert'],['Routing (43)','Source routing — specify intermediate nodes'],['Fragment (44)','Only source may fragment in IPv6; routers never fragment'],['ESP (50)','IPsec encryption payload'],['Authentication (51)','IPsec integrity and authentication']]],
          ])}
        </div>
        <div class="zoom-section">
          <div class="zoom-section-title">Key differences from IPv4</div>
          <div style="overflow-x:auto"><table class="detail-table">
            <thead><tr><th>Feature</th><th>IPv4</th><th>IPv6</th></tr></thead>
            <tbody>
              <tr><td class="dt-field">Address size</td><td class="dt-what">32 bits (~4B addresses)</td><td class="dt-what">128 bits (340 undecillion)</td></tr>
              <tr><td class="dt-field">Header size</td><td class="dt-what">20–60 bytes (variable)</td><td class="dt-what">40 bytes (fixed)</td></tr>
              <tr><td class="dt-field">Header checksum</td><td class="dt-what">Yes (recomputed every hop)</td><td class="dt-what">Removed (L2 and L4 handle it)</td></tr>
              <tr><td class="dt-field">Fragmentation</td><td class="dt-what">Routers and source</td><td class="dt-what">Source only (Fragment extension header)</td></tr>
              <tr><td class="dt-field">Options</td><td class="dt-what">In header (variable length)</td><td class="dt-what">Extension headers (chained, skippable)</td></tr>
              <tr><td class="dt-field">Broadcast</td><td class="dt-what">Yes (255.255.255.255)</td><td class="dt-what">No — replaced by multicast</td></tr>
              <tr><td class="dt-field">NAT</td><td class="dt-what">Required (address exhaustion)</td><td class="dt-what">Not needed; end-to-end restored</td></tr>
              <tr><td class="dt-field">Auto-config</td><td class="dt-what">DHCP</td><td class="dt-what">SLAAC (Stateless Address Autoconfiguration)</td></tr>
              <tr><td class="dt-field">IPsec</td><td class="dt-what">Optional</td><td class="dt-what">Built into spec (mandatory support)</td></tr>
              <tr><td class="dt-field">Flow identification</td><td class="dt-what">None (requires DPI)</td><td class="dt-what">Flow Label field</td></tr>
              <tr><td class="dt-field">ARP</td><td class="dt-what">ARP (broadcast)</td><td class="dt-what">NDP / ICMPv6 Neighbor Discovery</td></tr>
            </tbody>
          </table></div>
        </div>`;
    }
  }

  else if (section === 'llc-header') {
    titleHtml = `<span style="color:#f75f5f">LLC Header</span>`;
    html = `
      <div class="zoom-subtitle">IEEE 802.2 Logical Link Control — Data Link sub-layer. Multiplexes Layer 3 protocols over MAC.</div>
      <div class="zoom-section">
        <div class="zoom-section-title">Ethernet 802.3 Frame — Logical Link Control</div>
        ${hdrGrid([
          [['Dest. MAC',m.dstMac,1.5],['Source MAC',m.srcMac,1.5],['EtherType',m.etherType,0.5],['DSAP',l.dsap,0.5],['SSAP',l.ssap,0.5],['Control',l.llcCtrl,0.5]],
        ], '#f75f5f')}
      </div>
      <div class="zoom-section">
        <div class="zoom-section-title">LLC Header fields</div>
        ${detailTable([
          ['DSAP', l.dsap, '8 bits', 'Destination Service Access Point', 'Identifies upper-layer protocol at receiver', '0xAA = SNAP extension used; 0x06 = IP direct'],
          ['DSAP I/G bit', '0 (Individual)', '1 bit', 'Individual or Group address', 'LSB of DSAP — unicast vs multicast service', '0=individual, 1=group'],
          ['SSAP', l.ssap, '8 bits', 'Source Service Access Point', 'Identifies upper-layer protocol at sender', '0xAA = SNAP extension; must match DSAP for IP'],
          ['SSAP C/R bit', '0 (Command)', '1 bit', 'Command or Response frame', 'LSB of SSAP — frame direction', '0=command, 1=response'],
          ['Control', l.llcCtrl, '8 or 16 bits', 'Frame type and sequence control', 'Differentiates I/S/U frame types', '0x03 = UI (Unnumbered Info) — connectionless datagram'],
          ['Frame Type', 'U-frame', '—', 'Unnumbered frame — no sequence numbers', 'Used for connectionless LLC (Type 1)', 'UI frames carry data without ACK or flow control'],
        ])}
      </div>
      `;
  }

  else if (section === 'llc-trailer') {
    titleHtml = `<span style="color:#f75f5f">LLC Trailer — FCS</span>`;
    html = `
      <div class="zoom-subtitle">Frame Check Sequence — 4-byte error detection trailer appended by LLC/MAC.</div>
      <div class="zoom-section">
        <div class="zoom-section-title">Trailer structure</div>
        ${hdrGrid([[['FCS / CRC-32', l.llcFcs, 4]]], '#f75f5f')}
      </div>
      <div class="zoom-section">
        ${detailTable([
          ['FCS / CRC-32', l.llcFcs, '32 bits', 'Frame Check Sequence value', 'Detects bit errors in the frame', 'CRC-32 computed over entire frame excluding FCS field itself'],
          ['Algorithm', 'CRC-32', '—', 'Cyclic Redundancy Check 32-bit', 'Catches all single-bit and most burst errors', 'IEEE 802.3 generator polynomial 0x04C11DB7'],
          ['Computed over', 'LLC Header + Data', '—', 'Scope of error protection', 'Entire payload integrity guaranteed', 'Sender appends; receiver recomputes and compares'],
          ['On mismatch', 'Frame silently dropped', '—', 'No NACK sent', 'Layer 2 has no retransmit mechanism', 'TCP detects missing segment and retransmits'],
        ])}
      </div>`;
  }

  else if (section === 'mac-header') {
    titleHtml = `<span style="color:#c97bf7">MAC Frame (IEEE 802.11)</span>`;
    html = `
      <div class="zoom-subtitle">IEEE 802.3 / 802.11 MAC — Physical addressing, framing, access control.</div>
      <div class="zoom-section">
        <div class="zoom-section-title">MAC frame structure</div>
        ${hdrGrid([
          [['Preamble','7×0xAA',1],['SFD','0xAB',0.5],['Dst MAC',m.dstMac,2],['Src MAC',m.srcMac,2],['EtherType',m.etherType,1],['Data','(payload)',2],['FCS',m.macFcs,1]],
        ], '#c97bf7')}
      </div>
      <div class="zoom-section">
        <div class="zoom-section-title">Ethernet 802.3 addresses used here</div>
        ${detailTable([
          ['Preamble', '7×0xAA (10101010…)', '56 bits', 'Clock synchronisation pattern', 'Allows receiver PLL to lock onto sender clock', 'Alternating 1010 bits; gives receiver time to sync'],
          ['SFD (Start Frame Delimiter)', '0xAB (10101011)', '8 bits', 'Marks exact start of frame', 'Receiver knows next bit is frame data', 'Breaks preamble pattern with final 11 — signals frame start'],
          ['Destination MAC', m.dstMac, '48 bits', 'Target NIC hardware address', 'Switch/NIC decides whether to accept frame', m.dstMac==='ff:ff:ff:ff:ff:ff'?'Broadcast — all devices on segment receive it':'Unicast — only matching NIC accepts'],
          ['Source MAC', m.srcMac, '48 bits', 'Sender NIC hardware address', 'Return path at Layer 2; switch learns port mapping', 'First 3 bytes = OUI (manufacturer); last 3 = device ID'],
          ['EtherType', m.etherType, '16 bits', 'Identifies encapsulated protocol', 'Receiver demuxes to correct Layer 3 handler', '0x0800=IPv4, 0x0806=ARP, 0x86DD=IPv6, 0x8100=VLAN'],
          ['Data / Payload', '(LLC+IP+TCP+Data)', '368–12000 bits', 'Encapsulated upper-layer data', 'Carries the actual network payload', 'Min 46 bytes (padded if shorter); max 1500 bytes (MTU)'],
          ['Pad (if needed)', '0x00…', '0–368 bits', 'Zero-padding to meet minimum frame size', 'Ethernet minimum frame is 64 bytes total', 'Added when payload < 46 bytes'],
        ])}
      </div>`;
  }

  else if (section === 'mac-trailer') {
    titleHtml = `<span style="color:#c97bf7">MAC Trailer — FCS</span>`;
    html = `
      <div class="zoom-subtitle">4-byte CRC-32 appended by MAC layer. Checked and stripped by receiving NIC.</div>
      <div class="zoom-section">
        <div class="zoom-section-title">Trailer structure</div>
        ${hdrGrid([[['FCS / CRC-32', m.macFcs, 4]]], '#c97bf7')}
      </div>
      <div class="zoom-section">
        ${detailTable([
          ['FCS / CRC-32', m.macFcs, '32 bits', 'Frame Check Sequence — integrity value', 'Catches all bit errors introduced on the physical medium', 'CRC-32 computed over Dst MAC + Src MAC + EtherType + Data'],
          ['Coverage', 'Dst MAC → end of Data', '—', 'Excludes preamble and SFD', 'Preamble is not part of the frame proper', 'Computed after SFD; appended as last 4 bytes of frame'],
          ['Algorithm', 'CRC-32 (IEEE 802.3)', '—', 'Cyclic Redundancy Check 32-bit', 'Detects all 1-bit, 2-bit, all odd-bit, and burst errors ≤32 bits', 'Generator polynomial 0x04C11DB7; hardware in NIC'],
          ['Computed by', 'Sending NIC (hardware)', '—', 'Offloaded to hardware', 'Too fast for software at line rate', 'NIC appends automatically; CPU never touches it'],
          ['Checked by', 'Receiving NIC (hardware)', '—', 'Hardware recomputes CRC', 'Frames with bad CRC never reach the OS', 'NIC discards silently; driver never sees corrupt frame'],
          ['On mismatch', 'Frame silently discarded', '—', 'No NACK or error sent', 'Ethernet is unreliable at Layer 2 by design', 'TCP detects missing segment via timeout/SACK and retransmits'],
          ['False pass rate', '~1 in 4 billion', '—', 'Probability CRC misses an error', 'Extremely low but non-zero', 'TCP checksum provides second layer of protection'],
        ])}
      </div>`;
  }

  else if (section === 'ppp-frame') {
    titleHtml = `<span style="color:#a78bfa">PPP Frame Format</span>`;
    html = `
      <div class="zoom-subtitle">Point-to-Point Protocol — Data Link layer framing for WAN/serial/dial-up/DSL links. RFC 1661.</div>
      <div class="zoom-section">
        <div class="zoom-section-title">Frame structure</div>
        ${hdrGrid([
          [['Flag','0x7E',0.5],['Address','0xFF',0.5],['Control','0x03',0.5],['Protocol','2 bytes',1],['Data / Payload','variable',4],['FCS','2 or 4 bytes',1],['Flag','0x7E',0.5]],
        ], '#a78bfa')}
      </div>
      <div class="zoom-section">
        <div class="zoom-section-title">Field details</div>
        ${detailTable([
          ['Flag', '0x7E', '8 bits', 'Frame delimiter — marks start and end of every PPP frame', 'Receiver scans for 0x7E to find frame boundaries in the byte stream', 'Both opening and closing flags are 0x7E; back-to-back frames share one flag', [['0x7E between frames','Frame boundary'],['0x7D 0x5E inside frame','Escaped 0x7E (byte stuffing prevents false frame boundaries in payload']]],
          ['Address', '0xFF', '8 bits', 'Broadcast address — always 0xFF in PPP (point-to-point, no routing needed)', 'PPP is always a 2-node link; no addressing is needed but HDLC heritage requires the field', 'Fixed at 0xFF; can be compressed away via LCP Address-and-Control-Field-Compression (ACFC)', [['0xFF','Standard — all stations (broadcast on point-to-point = the one peer)'],['Omitted','LCP ACFC negotiated; saves 2 bytes per frame']]],
          ['Control', '0x03', '8 bits', 'HDLC Unnumbered Information (UI) frame control byte — always 0x03', 'PPP uses connectionless UI frames; no sequence numbers at this layer (reliability delegated to upper layers)', 'Fixed at 0x03; also compressible via LCP ACFC', [['0x03','UI frame — standard PPP data frame'],['Omitted','LCP ACFC negotiated along with Address field']]],
          ['Protocol', '2 bytes', '16 bits', 'Identifies the protocol encapsulated in the payload', 'Receiver demultiplexes to correct handler: IP, IPv6, LCP, NCP, etc.', 'IANA-assigned; odd first byte = data protocols, even first byte = control protocols', [['0x0021','IPv4 payload'],['0x0057','IPv6 payload'],['0xC021','LCP — Link Control Protocol (link setup/teardown)'],['0x8021','IPCP — IP Control Protocol (IP address negotiation)'],['0x0031','Bridging PDU'],['0x00FD','Compressed datagram']]],
          ['Data / Payload', '(variable)', 'variable', 'The encapsulated upper-layer protocol data unit', 'Carries IP packets, LCP messages, NCP configuration, or any other PPP-carried protocol', 'Default MTU 1500 bytes; negotiable via LCP MRU option; byte-stuffed if 0x7E or 0x7D appear in data', [['IP packet','Protocol=0x0021; standard internet traffic'],['LCP Configure-Request','Protocol=0xC021; link negotiation during setup'],['IPCP Configure-Ack','Protocol=0x8021; IP address assignment response']]],
          ['FCS', '2 or 4 bytes', '16 or 32 bits', 'Frame Check Sequence — CRC over Address+Control+Protocol+Data', 'Detects corruption on the serial link', '16-bit CRC-CCITT default; 32-bit CRC-32 negotiated via LCP for better protection on noisy links', [['CRC-16 (default)','2 bytes; detects all burst errors ≤16 bits'],['CRC-32 (negotiated)','4 bytes; stronger protection; recommended for high-error links'],['Mismatch','Frame silently discarded; upper layers handle retransmission']]],
        ])}
      </div>
      <div class="zoom-section">
        <div class="zoom-section-title">PPP sub-protocols</div>
        <div style="overflow-x:auto"><table class="detail-table">
          <thead><tr><th>Protocol</th><th>Code</th><th>Purpose</th><th>Key operations</th></tr></thead>
          <tbody>
            <tr><td class="dt-field" style="color:#a78bfa">LCP</td><td class="dt-val">0xC021</td><td class="dt-what">Link Control Protocol — establishes, configures, and terminates the PPP link</td><td class="dt-how">Configure-Request/Ack/Nak/Reject → Opened state; Echo-Request/Reply keepalives; Terminate-Request teardown</td></tr>
            <tr><td class="dt-field" style="color:#a78bfa">IPCP</td><td class="dt-val">0x8021</td><td class="dt-what">IP Control Protocol — negotiates IPv4 parameters over PPP</td><td class="dt-how">Negotiates IP addresses for both ends; Van Jacobson TCP/IP header compression; DNS server addresses</td></tr>
            <tr><td class="dt-field" style="color:#a78bfa">IPv6CP</td><td class="dt-val">0x8057</td><td class="dt-what">IPv6 Control Protocol — negotiates IPv6 parameters</td><td class="dt-how">Negotiates Interface-Identifier for link-local address formation; enables IPv6 over PPP</td></tr>
            <tr><td class="dt-field" style="color:#a78bfa">PAP</td><td class="dt-val">0xC023</td><td class="dt-what">Password Authentication Protocol — plaintext auth (insecure)</td><td class="dt-how">Authenticate-Request with username+password in plaintext; server sends Ack/Nak; deprecated</td></tr>
            <tr><td class="dt-field" style="color:#a78bfa">CHAP</td><td class="dt-val">0xC223</td><td class="dt-what">Challenge Handshake Authentication Protocol — secure auth</td><td class="dt-how">Server sends random Challenge; client responds with MD5(challenge+secret); server verifies without transmitting password</td></tr>
          </tbody>
        </table></div>
      </div>`;
  }

  else if (section === 'arp-packet') {
    titleHtml = `<span style="color:#f5a623">ARP Packet Format</span>`;
    html = `
      <div class="zoom-subtitle">Address Resolution Protocol (RFC 826) — resolves IPv4 addresses to MAC addresses on a local network.</div>
      <div class="zoom-section">
        <div class="zoom-section-title">Packet structure (28 bytes for IPv4/Ethernet)</div>
        ${hdrGrid([
          [['Hardware Type','0x0001 (Ethernet)',2],['Protocol Type','0x0800 (IPv4)',2]],
          [['HLen','6',0.5],['PLen','4',0.5],['Operation','1=Request / 2=Reply',3]],
          [['Sender Hardware Address (MAC)','00:1a:2b:3c:4d:5e',4]],
          [['Sender Protocol Address (IP)','192.168.1.10',4]],
          [['Target Hardware Address (MAC)','00:00:00:00:00:00 (request) / actual MAC (reply)',4]],
          [['Target Protocol Address (IP)','192.168.1.1',4]],
        ], '#f5a623')}
      </div>
      <div class="zoom-section">
        <div class="zoom-section-title">Field details</div>
        ${detailTable([
          ['Hardware Type', '0x0001', '16 bits', 'Type of hardware (link-layer) address being used', 'ARP is protocol-independent; this field identifies the L2 technology', 'IANA-assigned; set by sender based on network interface type', [['0x0001','Ethernet (most common)'],['0x0006','IEEE 802 networks'],['0x000F','Frame Relay'],['0x0011','Fiber Channel']]],
          ['Protocol Type', '0x0800', '16 bits', 'Type of protocol address being resolved', 'ARP can resolve any L3 address, not just IPv4', 'Same values as Ethernet EtherType field', [['0x0800','IPv4 (most common)'],['0x86DD','IPv6 (NDP replaces ARP for IPv6)']]],
          ['HLen', '6', '8 bits', 'Length of hardware (MAC) address in bytes', 'Receiver knows how many bytes to read for each MAC field', '6 for Ethernet (48-bit MAC)', [['6','Ethernet MAC — 6 bytes'],['Other','For non-Ethernet technologies']]],
          ['PLen', '4', '8 bits', 'Length of protocol (IP) address in bytes', 'Receiver knows how many bytes to read for each IP field', '4 for IPv4; 16 for IPv6', [['4','IPv4 — 4 bytes'],['16','IPv6 — 16 bytes']]],
          ['Operation', '1 or 2', '16 bits', 'Whether this is a request or a reply', 'Receiver processes differently: request triggers reply if IP matches; reply updates ARP cache', 'Set by sender; 1 for request, 2 for reply', [['1','ARP Request — "Who has IP x.x.x.x? Tell IP y.y.y.y"'],['2','ARP Reply — "IP x.x.x.x is at MAC aa:bb:cc:dd:ee:ff"'],['3','RARP Request — reverse lookup'],['4','RARP Reply']]],
          ['Sender Hardware Address', '00:1a:2b:3c:4d:5e', '48 bits', "Sender's MAC address", "Receiver caches this immediately even before processing the operation — gratuitous ARP exploits this", 'Always set to sender NIC MAC; cannot be zero in practice', [['Normal request','Sender fills its own MAC; target fills its own MAC in reply'],['Gratuitous ARP','Sender = Target IP; used to announce IP or detect conflicts; Target MAC = 00:00:00:00:00:00']]],
          ['Sender Protocol Address', '192.168.1.10', '32 bits', "Sender's IP address", 'Identifies who is asking; target uses this to send unicast reply', 'Set to sender IP; 0.0.0.0 in DHCP probe', [['Normal','Sender IP'],['0.0.0.0','DHCP client probing before IP assignment (ARP Probe)']]],
          ['Target Hardware Address', '00:00:00:00:00:00', '48 bits', "Target's MAC address — unknown in request, filled in reply", 'This is the answer ARP is looking for', 'All zeros in request (unknown); filled by target in reply', [['00:00:00:00:00:00','Request — target MAC unknown'],['Actual MAC','Reply — target fills its own MAC'],['ff:ff:ff:ff:ff:ff','Broadcast — not used in standard ARP; appears in some gratuitous ARP implementations']]],
          ['Target Protocol Address', '192.168.1.1', '32 bits', "IP address being queried", 'All devices on the LAN receive the broadcast; only the owner of this IP responds', 'Set to the IP the sender wants to resolve', [['Any IP on same subnet','Normal ARP resolution'],['Sender own IP','Gratuitous ARP — conflict detection or cache refresh']]],
        ])}
      </div>
      <div class="zoom-section">
        <div class="zoom-section-title">ARP operation flow</div>
        <div style="overflow-x:auto"><table class="detail-table">
          <thead><tr><th>Step</th><th>Action</th><th>Src MAC</th><th>Dst MAC</th><th>Operation</th><th>Notes</th></tr></thead>
          <tbody>
            <tr><td class="dt-field">1</td><td class="dt-what">Host A wants to reach 192.168.1.1</td><td class="dt-how">A's MAC</td><td class="dt-how">ff:ff:ff:ff:ff:ff</td><td class="dt-val">Request (1)</td><td class="dt-how">Broadcast; all hosts on LAN receive it</td></tr>
            <tr><td class="dt-field">2</td><td class="dt-what">Host B (192.168.1.1) receives broadcast</td><td class="dt-how">B's MAC</td><td class="dt-how">A's MAC</td><td class="dt-val">Reply (2)</td><td class="dt-how">Unicast reply directly to A; others ignore</td></tr>
            <tr><td class="dt-field">3</td><td class="dt-what">Host A caches B's MAC</td><td class="dt-how">—</td><td class="dt-how">—</td><td class="dt-val">—</td><td class="dt-how">ARP table entry created with TTL; used for subsequent frames</td></tr>
            <tr><td class="dt-field">4</td><td class="dt-what">Gratuitous ARP (optional)</td><td class="dt-how">Own MAC</td><td class="dt-how">ff:ff:ff:ff:ff:ff</td><td class="dt-val">Request (1)</td><td class="dt-how">Sender = Target IP; updates all ARP caches; detects IP conflicts</td></tr>
          </tbody>
        </table></div>
      </div>`;
  }

  else if (section === 'physical') {
    titleHtml = `<span style="color:#3dd6d6">Physical Layer — Bit Encoding</span>`;
    const bits = pkt.binaryStr.slice(0,32);
    const bitArr = bits.split('').map(Number);
    html = `
      <div class="zoom-subtitle">Converts the bit stream into physical signals on the medium.</div>
      <div style="display:flex;flex-wrap:wrap;gap:10px;margin-bottom:20px;padding:12px 16px;background:var(--bg3);border:1px solid var(--border);border-radius:6px;">
        <span style="font-family:var(--font-mono);font-size:10px;color:var(--text3);margin-right:4px;align-self:center;">LEGEND:</span>
        <span style="font-family:var(--font-mono);font-size:11px;padding:3px 10px;border-radius:3px;background:rgba(201,123,247,0.15);color:#c97bf7;">■ MAC / Preamble</span>
        <span style="font-family:var(--font-mono);font-size:11px;padding:3px 10px;border-radius:3px;background:rgba(247,95,95,0.15);color:#f75f5f;">■ LLC</span>
        <span style="font-family:var(--font-mono);font-size:11px;padding:3px 10px;border-radius:3px;background:rgba(245,166,35,0.15);color:#f5a623;">■ IP Header</span>
        <span style="font-family:var(--font-mono);font-size:11px;padding:3px 10px;border-radius:3px;background:rgba(61,214,140,0.15);color:#3dd68c;">■ TCP Header</span>
        <span style="font-family:var(--font-mono);font-size:11px;padding:3px 10px;border-radius:3px;background:rgba(79,142,247,0.15);color:#4f8ef7;">■ Data</span>
      </div>
      <div class="zoom-section">
        <div class="zoom-section-title">Binary bit stream (color coded by layer)</div>
        <div class="binary-display" style="line-height:2">${pkt.binaryAnnotated.map(seg=>{
          const colors = {'mac-preamble':'#c97bf7','mac':'#c97bf7','llc':'#f75f5f','ip':'#f5a623','tcp':'#3dd68c','data':'#4f8ef7'};
          const labels = {'mac-preamble':'PREAMBLE','mac':'MAC','llc':'LLC','ip':'IP','tcp':'TCP','data':'DATA'};
          const bits = seg.bytes.map(b=>b.toString(2).padStart(8,'0')).join('');
          return `<span title="${labels[seg.layer]}" style="color:${colors[seg.layer]};margin-right:2px">${bits}</span>`;
        }).join('')}</div>
      </div>
      <div class="zoom-section">
        <div class="zoom-section-title">Bit visualization (color coded by layer)</div>
        <div class="phys-bits-row">${pkt.binaryAnnotated.map(seg=>{
          const colors = {'mac-preamble':'#c97bf7','mac':'#c97bf7','llc':'#f75f5f','ip':'#f5a623','tcp':'#3dd68c','data':'#4f8ef7'};
          return seg.bytes.map(b=>b.toString(2).padStart(8,'0').split('').map(bit=>`<div class="bit-badge" style="background:${colors[seg.layer]}22;color:${colors[seg.layer]}">${bit}</div>`).join('')).join('');
        }).join('')}</div>
      </div>
      <div class="zoom-section">
        <div class="zoom-section-title">Signal encoding schemes (first 32 bits) — clock ticks separated by vertical lines</div>
        <div class="encoding-section">
          <div class="waveform-grid" id="waveform-grid"></div>
        </div>
      </div>`;
  }

  zoomTitle.innerHTML = titleHtml;
  zoomContent.innerHTML = html;

  if (section === 'physical') {
    requestAnimationFrame(() => drawAllWaveforms(pkt.binaryStr.slice(0,64).split('').map(Number)));
  }
  if (section === 'ip') {
    requestAnimationFrame(() => {
      const btn = document.getElementById('ip-ver-toggle');
      if (btn) btn.addEventListener('click', () => {
        STATE.ipVersion = STATE.ipVersion === 4 ? 6 : 4;
        openZoom('ip', pkt);
      });
    });
  }
}

// ─── WAVEFORM DRAWING ─────────────────────────────────────────
const ENCODINGS = [
  { name: 'NRZ-Unipolar',   color: '#4f8ef7', fn: nrzUnipolar },
  { name: 'NRZ-L (Bipolar)',color: '#3dd68c', fn: nrzBipolar },
  { name: 'NRZ-I',          color: '#f5a623', fn: nrzi },
  { name: 'RZ-Unipolar',    color: '#f75f5f', fn: rzUnipolar },
  { name: 'RZ-Bipolar',     color: '#c97bf7', fn: rzBipolar },
  { name: 'Manchester',     color: '#3dd6d6', fn: manchester },
  { name: 'Diff. Manchester',color:'#ffc055', fn: diffManchester },
  { name: 'AMI',            color: '#ff8f8f', fn: ami },
];

function drawAllWaveforms(bits) {
  const grid = document.getElementById('waveform-grid');
  if (!grid) return;
  grid.innerHTML = '';
  ENCODINGS.forEach(enc => {
    const row = document.createElement('div');
    row.className = 'waveform-row';
    const label = document.createElement('div');
    label.className = 'waveform-name';
    label.style.color = enc.color;
    label.textContent = enc.name;
    const canvas = document.createElement('canvas');
    canvas.className = 'waveform-canvas';
    const bitsLen = bits.length;
    canvas.width = Math.max(1280, bitsLen * 20);
    canvas.style.width = canvas.width + 'px';
    canvas.height = 72;
    row.appendChild(label);
    row.appendChild(canvas);
    grid.appendChild(row);
    drawWaveform(canvas, enc.fn(bits), enc.color, bits);
  });
}

function drawWaveform(canvas, levels, color, bits) {
  const ctx = canvas.getContext('2d');
  const W = canvas.width;
  const H = canvas.height;
  const pad = 8;
  const hi = pad;
  const lo = H - pad - 14; // leave room for bit labels at bottom
  const mid = (hi + lo) / 2;
  ctx.clearRect(0,0,W,H);

  if (!levels || levels.length === 0) return;
  const bw = W / levels.length;

  // Mid reference line
  ctx.strokeStyle = 'rgba(255,255,255,0.05)';
  ctx.lineWidth = 0.5;
  ctx.beginPath(); ctx.moveTo(0, mid); ctx.lineTo(W, mid); ctx.stroke();

  function yForLevel(v) {
    if (v === 1) return hi;
    if (v === -1) return lo;
    return mid;
  }

  // Draw waveform
  ctx.strokeStyle = color;
  ctx.lineWidth = 1.8;
  ctx.lineJoin = 'miter';
  ctx.beginPath();
  let started = false;
  for (let i = 0; i < levels.length; i++) {
    const segs = levels[i];
    const x0 = i * bw;
    if (Array.isArray(segs)) {
      let xc = x0;
      segs.forEach(([frac, lv]) => {
        const xe = x0 + frac * bw;
        const y = yForLevel(lv);
        if (!started) { ctx.moveTo(xc, y); started = true; }
        else ctx.lineTo(xc, y);
        ctx.lineTo(xe, y);
        xc = xe;
      });
    } else {
      const y = yForLevel(segs);
      if (!started) { ctx.moveTo(x0, y); started = true; }
      else ctx.lineTo(x0, y);
      ctx.lineTo((i+1)*bw, y);
    }
  }
  ctx.stroke();

  // Clock tick separators (vertical dashed lines between bits)
  ctx.strokeStyle = 'rgba(255,255,255,0.18)';
  ctx.lineWidth = 0.8;
  ctx.setLineDash([3, 3]);
  for (let i = 1; i < levels.length; i++) {
    const x = i * bw;
    ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, lo + 2); ctx.stroke();
  }
  ctx.setLineDash([]);

  // Bit labels at bottom of each cell
  ctx.fillStyle = 'rgba(255,255,255,0.45)';
  ctx.font = '9px monospace';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'top';
  if (bits) {
    for (let i = 0; i < levels.length; i++) {
      const x = i * bw + bw / 2;
      ctx.fillText(String(bits[i] ?? ''), x, lo + 4);
    }
  }
}

// Encoding functions — return array of levels (1, 0, -1) or sub-segments
function nrzUnipolar(bits) { return bits.map(b => b); }
function nrzBipolar(bits) { return bits.map(b => b ? 1 : -1); }
function nrzi(bits) {
  let cur = -1;
  return bits.map(b => { if (b) cur = -cur; return cur; });
}
function rzUnipolar(bits) {
  return bits.map(b => b ? [[0.5,1],[0.5,0]] : [[1,0]]);
}
function rzBipolar(bits) {
  let last = 1;
  return bits.map(b => {
    if (!b) return [[1,0]];
    last = -last;
    return [[0.5,last],[0.5,0]];
  });
}
function manchester(bits) {
  return bits.map(b => b ? [[0.5,1],[0.5,-1]] : [[0.5,-1],[0.5,1]]);
}
function diffManchester(bits) {
  let cur = 1;
  return bits.map(b => {
    const mid = -cur;
    const seg = b ? [[0.5,cur],[0.5,mid]] : [[0.5,mid],[0.5,cur]];
    if (!b) cur = mid;
    return seg;
  });
}
function ami(bits) {
  let last = 1;
  return bits.map(b => {
    if (!b) return 0;
    last = -last;
    return last;
  });
}

// ─── UI HELPERS ───────────────────────────────────────────────
function fi(name, val, bits, what, why, how) {
  return `<div class="field-item">
    <div class="fi-name">${escHtml(String(name))}</div>
    <div class="fi-val">${escHtml(String(val))}</div>
    <div class="fi-bits">${escHtml(String(bits||''))}</div>
    <div class="fi-what">${escHtml(String(what||''))}</div>
    <div class="fi-why">${escHtml(String(why||''))}</div>
    <div class="fi-how">${escHtml(String(how||''))}</div>
  </div>`;
}

function hf(name, val, bits, color) {
  return `<div class="hdr-field" style="min-width:${Math.max(80,name.length*9)}px">
    <div class="hdr-field-name" style="color:${color}">${escHtml(name)}</div>
    <div class="hdr-field-val" style="color:${color}">${escHtml(String(val))}</div>
    <div class="hdr-field-bits">${bits}</div>
  </div>`;
}

function dispBits(n) {
  if (STATE.bitsMode) return n + ' b';
  if (n % 8 === 0) return (n / 8) + ' B';
  return n + ' b';
}
function dispBitsLabel(s) {
  const str = String(s || '');
  const m = str.match(/^(\d+)\s*(?:bits?|b)$/i);
  return m ? dispBits(parseInt(m[1])) : str;
}
function escHtml(str) {
  return String(str)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;');
}

function updateLayerUI() {
  const maxLayer = STATE.model === 'tcpip' ? 3 : 7;
  const names = STATE.model === 'tcpip' ? TCPIP_LAYER_NAMES : LAYER_NAMES;
  document.querySelectorAll('.step-dot').forEach((dot, i) => {
    if (STATE.model === 'tcpip') {
      dot.classList.toggle('active', i === STATE.currentLayer);
      dot.classList.toggle('visited', i < STATE.currentLayer);
      dot.style.display = i > 3 ? 'none' : '';
      const line = dot.nextElementSibling;
      if (line && line.classList.contains('step-line')) line.style.display = i >= 3 ? 'none' : '';
    } else {
      dot.style.display = '';
      const line = dot.nextElementSibling;
      if (line && line.classList.contains('step-line')) line.style.display = '';
      dot.classList.toggle('active', i === STATE.currentLayer);
      dot.classList.toggle('visited', i < STATE.currentLayer);
    }
  });
  layerPrev.disabled = STATE.currentLayer === 0;
  layerNext.disabled = STATE.currentLayer === (STATE.model === 'tcpip' ? 3 : 7);
  layerNameLbl.textContent = names[STATE.currentLayer] || '';
}

function updateSegUI() {
  const total = STATE.segments.length;
  if (total > 1) {
    segNav.style.display = 'flex';
    segLabel.textContent = `Seg ${STATE.currentSeg+1}/${total}`;
    segPrev.disabled = STATE.currentSeg === 0;
    segNext.disabled = STATE.currentSeg === total-1;
  } else {
    segNav.style.display = 'none';
  }
}

// ─── EVENT LISTENERS ──────────────────────────────────────────
msgInput.addEventListener('input', () => {
  charCount.textContent = `${msgInput.value.length} / 512`;
});

startBtn.addEventListener('click', () => {
  const msg = msgInput.value.trim();
  if (!msg) { msgInput.focus(); return; }
  STATE.message = msg;
  STATE.segments = segmentMessage(msg);
  STATE.currentSeg = 0;
  STATE.currentLayer = 0;
  STATE.expanded = false;

  msgPreview.textContent = `"${msg.slice(0,50)}${msg.length>50?'…':''}"`;
  collapseBtn.classList.add('active');
  expandBtn.classList.remove('active');

  showScreen('stack-screen');
  renderStack();
  updateLayerUI();
  updateSegUI();
});

backBtn.addEventListener('click', () => {
  showScreen('input-screen');
});

layerPrev.addEventListener('click', () => {
  if (STATE.currentLayer > 0) {
    STATE.currentLayer--;
    renderStack();
    updateLayerUI();
  }
});
layerNext.addEventListener('click', () => {
  const max = STATE.model === 'tcpip' ? 3 : 7;
  if (STATE.currentLayer < max) {
    STATE.currentLayer++;
    renderStack();
    updateLayerUI();
  }
});

document.querySelectorAll('.step-dot').forEach(dot => {
  dot.addEventListener('click', () => {
    STATE.currentLayer = parseInt(dot.dataset.layer);
    renderStack();
    updateLayerUI();
  });
});

collapseBtn.addEventListener('click', () => {
  STATE.expanded = false;
  collapseBtn.classList.add('active');
  expandBtn.classList.remove('active');
  renderStack();
});
expandBtn.addEventListener('click', () => {
  STATE.expanded = true;
  expandBtn.classList.add('active');
  collapseBtn.classList.remove('active');
  renderStack();
});

segPrev.addEventListener('click', () => {
  if (STATE.currentSeg > 0) {
    STATE.currentSeg--;
    updateSegUI();
    renderStack();
  }
});
segNext.addEventListener('click', () => {
  if (STATE.currentSeg < STATE.segments.length-1) {
    STATE.currentSeg++;
    updateSegUI();
    renderStack();
  }
});

zoomClose.addEventListener('click', closeZoom);
zoomPanel.addEventListener('click', (e) => {
  if (e.target === zoomPanel) closeZoom();
});

document.getElementById('stack-diagram').addEventListener('click', (e) => {
  const tb = e.target.closest('[data-transport]');
  if (tb) {
    return;
  }
  const lb = e.target.closest('[data-link]');
  if (lb) {
    STATE.linkMode = lb.dataset.link;
    renderStack();
    updateLayerUI();
    return;
  }
});

document.getElementById('tcp-btn').addEventListener('click', () => {
  STATE.transportMode = 'tcp';
  document.getElementById('tcp-btn').classList.add('active');
  document.getElementById('udp-btn').classList.remove('active');
  if (document.getElementById('stack-screen').classList.contains('active')) {
    renderStack();
    updateLayerUI();
  }
});
document.getElementById('udp-btn').addEventListener('click', () => {
  STATE.transportMode = 'udp';
  document.getElementById('udp-btn').classList.add('active');
  document.getElementById('tcp-btn').classList.remove('active');
  if (document.getElementById('stack-screen').classList.contains('active')) {
    renderStack();
    updateLayerUI();
  }
});

document.getElementById('osi-btn').addEventListener('click', () => {
  STATE.model = 'osi';
  STATE.currentLayer = 0;
  document.getElementById('osi-btn').classList.add('active');
  document.getElementById('tcpip-btn').classList.remove('active');
  if (stackScreen.classList.contains('active') || document.getElementById('stack-screen').style.display !== 'none') {
    renderStack();
    updateLayerUI();
    updateSegUI();
  }
});
document.getElementById('tcpip-btn').addEventListener('click', () => {
  STATE.model = 'tcpip';
  STATE.currentLayer = 0;
  document.getElementById('tcpip-btn').classList.add('active');
  document.getElementById('osi-btn').classList.remove('active');
  if (document.getElementById('stack-screen').classList.contains('active')) {
    renderStack();
    updateLayerUI();
    updateSegUI();
  }
});

document.getElementById('bits-toggle-btn').addEventListener('click', (e) => {
  e.preventDefault();
  STATE.bitsMode = !STATE.bitsMode;
  const btn = document.getElementById('bits-toggle-btn');
  btn.textContent = STATE.bitsMode ? 'b' : 'B';
  btn.title = STATE.bitsMode ? 'Switch to bytes' : 'Switch to bits';
  btn.classList.toggle('active', STATE.bitsMode);
  STATE.suppressScroll = true;
  if (document.getElementById('stack-screen').classList.contains('active')) renderStack();
  if (zoomPanel.classList.contains('visible') && STATE.zoomSection) openZoom(STATE.zoomSection, currentPkt());
});
document.querySelectorAll('.preset').forEach(btn => {
  btn.addEventListener('click', () => {
    msgInput.value = btn.dataset.msg;
    charCount.textContent = `${msgInput.value.length} / 512`;
  });
});

// ─── TCP/IP LAYER INFO ────────────────────────────────────────
function openTCPIPLayerInfo(index, pkt) {
  const TCPIP_INFO = [
    {
      name: 'Application Layer', col: '#4f8ef7',
      what: 'Combines OSI Application, Presentation, and Session layers. Provides all application-level services: data formatting, encryption, session management, and the protocols users interact with directly.',
      protocols: [
        ['HTTP/HTTPS','HyperText Transfer Protocol','Web browsing, REST APIs','TCP 80/443; request-response; stateless; HTTPS adds TLS'],
        ['FTP','File Transfer Protocol','File upload/download','TCP 21 (control) + 20 (data); active/passive modes'],
        ['SMTP','Simple Mail Transfer Protocol','Sending email','TCP 25; EHLO handshake; MAIL FROM/RCPT TO/DATA'],
        ['DNS','Domain Name System','Name resolution','UDP/TCP 53; recursive query chain; A/AAAA/MX/CNAME records'],
        ['DHCP','Dynamic Host Configuration Protocol','IP address assignment','UDP 67/68; DORA (Discover/Offer/Request/Acknowledge)'],
        ['SNMP','Simple Network Management Protocol','Network device monitoring','UDP 161/162; GET/SET/TRAP operations; MIB database'],
        ['Telnet','Teletype Network','Remote terminal (plaintext)','TCP 23; NVT (Network Virtual Terminal); replaced by SSH'],
        ['RTP','Real-time Transport Protocol','Audio/video streaming','UDP; sequence numbers + timestamps; SSRC identifies stream'],
        ['RTCP','RTP Control Protocol','QoS feedback for RTP','UDP; SR/RR/SDES/BYE packets; 5% of RTP bandwidth'],
        ['SSH','Secure Shell','Encrypted remote access','TCP 22; Diffie-Hellman key exchange; replaces Telnet'],
        ['SLIP','Serial Line IP','IP over serial links (legacy)','No framing header; just END byte (0xC0) delimiter; no error detection'],
        ['PPP NCP','Network Control Protocol','Negotiates network-layer options over PPP link','Separate NCP per L3 protocol; IPCP negotiates IP addresses and compression'],
        ['PPP IPCP','IP Control Protocol','Configures IP over PPP','Assigns IP addresses to both ends of a PPP link; negotiates Van Jacobson compression'],
      ],
    },
    {
      name: 'Transport Layer', col: '#3dd68c',
      what: 'Same as OSI Transport layer. Provides end-to-end communication, segmentation, reliability, flow control, congestion control, and port-based multiplexing.',
      protocols: [
        ['TCP','Transmission Control Protocol','Reliable ordered delivery','3-way handshake; seq/ack numbers; sliding window; congestion control (slow start, AIMD)'],
        ['UDP','User Datagram Protocol','Fast connectionless delivery','No handshake; 8-byte header; used for DNS, VoIP, video, gaming'],
        ['RTP','Real-time Transport Protocol','Real-time media transport','Runs over UDP; PT field identifies codec; timestamp drives playout buffer'],
        ['RTCP','RTP Control Protocol','RTP session statistics','Sender/Receiver Reports; jitter, packet loss, round-trip delay'],
        ['SCTP','Stream Control Transmission Protocol','Multi-stream reliable transport','4-way handshake; multiple streams prevent HOL blocking; multi-homing'],
        ['QUIC','Quick UDP Internet Connections','Low-latency reliable transport','UDP-based; integrated TLS 1.3; 0-RTT; no HOL blocking between streams'],
      ],
    },
    {
      name: 'Internet Layer', col: '#f5a623',
      what: 'Corresponds to OSI Network layer. Handles logical addressing, routing, and packet forwarding across multiple networks. Also includes ARP, RARP, ICMP, and IGMP which OSI places differently.',
      protocols: [
        ['IPv4','Internet Protocol v4','Packet addressing and routing','32-bit addresses; 20-byte header; TTL; fragmentation; checksum'],
        ['IPv6','Internet Protocol v6','Next-gen addressing','128-bit addresses; 40-byte fixed header; no fragmentation by routers; ICMPv6'],
        ['ICMP','Internet Control Message Protocol','Error reporting and diagnostics','Ping (Type 8/0); Traceroute (TTL exceeded Type 11); Dest Unreachable (Type 3)'],
        ['IGMP','Internet Group Management Protocol','Multicast group membership','Hosts join/leave groups; routers learn which multicast traffic to forward; IGMPv3 adds source filtering'],
        ['ARP','Address Resolution Protocol','IP→MAC resolution','Broadcast "Who has IP x?"; reply with MAC; cached in ARP table'],
        ['RARP','Reverse ARP','MAC→IP resolution (legacy)','Diskless workstations used RARP to get IP; superseded by BOOTP then DHCP'],
        ['OSPF','Open Shortest Path First','Intra-domain routing','Link-state; Dijkstra SPF; fast convergence; areas reduce LSA flooding'],
        ['BGP','Border Gateway Protocol','Inter-domain routing','Path-vector; AS_PATH prevents loops; policy-based; the routing protocol of the internet'],
      ],
    },
    {
      name: 'Network Access Layer', col: '#c97bf7',
      what: 'Combines OSI Data Link and Physical layers. Handles everything needed to transmit a packet on a single physical link: framing, MAC addressing, error detection, medium access, and signal encoding.',
      protocols: [
        ['Ethernet (802.3)','Wired LAN','Most common LAN technology','CSMA/CD (legacy); frame: preamble+SFD+dst MAC+src MAC+EtherType+data+CRC32'],
        ['WiFi (802.11)','Wireless LAN','Wireless connectivity','CSMA/CA; RTS/CTS; WPA3 security; OFDM/OFDMA physical layer'],
        ['PPP','Point-to-Point Protocol','WAN links, dial-up, DSL','Flag(0x7E)+Addr+Ctrl+Protocol+Data+FCS; LCP negotiates link; NCP configures L3'],
        ['SLIP','Serial Line IP','Legacy serial IP (no framing)','Only END byte delimiter; no address/control/protocol fields; no error detection'],
        ['ARP','Address Resolution Protocol','L3→L2 address mapping','Sits between Internet and Network Access; broadcast-based; gratuitous ARP for IP conflict detection'],
        ['LLC (802.2)','Logical Link Control','L3 protocol multiplexing','DSAP/SSAP/Control; SNAP extension for EtherType values; used in 802.11 frames'],
        ['HDLC','High-level Data Link Control','Synchronous serial WAN links','Flag+Address+Control+Data+FCS; foundation for PPP framing'],
        ['DSL Physical','Digital Subscriber Line','Broadband over copper phone lines','DMT modulation; FDM separates upstream/downstream/voice; ADSL/VDSL/G.fast variants'],
      ],
    },
  ];
  const info = TCPIP_INFO[index];
  zoomPanel.classList.add('visible');
  zoomTitle.innerHTML = `<span style="color:${info.col}">${info.name}</span> <span style="font-size:12px;opacity:0.5;font-weight:400">TCP/IP Model</span>`;
  zoomContent.innerHTML = `
    <div class="zoom-subtitle">${escHtml(info.what)}</div>
    <div class="zoom-section">
      <div class="zoom-section-title">Protocols</div>
      <div style="overflow-x:auto"><table class="detail-table" style="min-width:600px">
        <thead><tr><th>Protocol</th><th>Full Name</th><th>Purpose</th><th>How it works</th></tr></thead>
        <tbody>${info.protocols.map(([p,fn,pu,hw])=>`<tr>
          <td class="dt-field" style="color:${info.col}">${escHtml(p)}</td>
          <td class="dt-what">${escHtml(fn)}</td>
          <td class="dt-what">${escHtml(pu)}</td>
          <td class="dt-how">${escHtml(hw)}</td>
        </tr>`).join('')}</tbody>
      </table></div>
    </div>`;
}

// ─── PCAP EXPORT ──────────────────────────────────────────────
document.getElementById('pcap-btn').addEventListener('click', async () => {
  const pkt = currentPkt();
  const binary = pkt.binaryStr;

  try {
    const res = await fetch('http://localhost:7432/make-pcap', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ binary }),
    });
    const data = await res.json();
    if (data.success && data.bytes) {
      const bytes = Uint8Array.from(atob(data.bytes), c => c.charCodeAt(0));
      const blob = new Blob([bytes], { type: 'application/vnd.tcpdump.pcap' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'packet.pcap';
      a.click();
      URL.revokeObjectURL(url);
      document.getElementById('pcap-modal').style.display = 'flex';
      document.getElementById('pcap-path').textContent = 'packet.pcap downloaded to your Downloads folder';
    } else {
      document.getElementById('pcap-error-msg').textContent = data.error || 'Unknown error';
      document.getElementById('pcap-error-modal').style.display = 'flex';
    }
  } catch (e) {
    document.getElementById('pcap-error-msg').textContent = 'Could not connect to server.py — is it running?';
    document.getElementById('pcap-error-modal').style.display = 'flex';
  }
});

document.getElementById('pcap-modal-close').addEventListener('click', () => {
  document.getElementById('pcap-modal').style.display = 'none';
});
document.getElementById('pcap-error-close').addEventListener('click', () => {
  document.getElementById('pcap-error-modal').style.display = 'none';
});