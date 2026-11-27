// 信道上的字节：会话密钥、密封单元、媒体包头。
//
// 与 internal/perfgw/handshake.go 的 seal/openSealed 对齐：AES-256-GCM，
// nonce 是 12 字节，前 4 字节为 0，后 8 字节是小端的计数；计数写在密封单元
// 的末尾（密文 | 16 字节标签 | u64 计数），所以每个单元自己就能解开。

export interface KeyBundle {
  control_send: string
  control_recv: string
  datagram_send: string
  datagram_recv: string
  bulk_send: string
  bulk_recv: string
  video: string[]
  control_send_counter: number
  control_recv_counter: number
  datagram_send_counter: number
  datagram_recv_counter: number
  bulk_send_counter: number
  bulk_recv_counter: number
}

export interface SessionKeys {
  controlSend: CryptoKey
  controlRecv: CryptoKey
  datagramSend: CryptoKey
  datagramRecv: CryptoKey
  /** 大块通道（剪贴板、光标图像）：常驻一条流，按顺序解密。 */
  bulkSend: CryptoKey
  bulkRecv: CryptoKey
  video: CryptoKey[]
  sendCounter: number
  datagramSendCounter: number
  bulkSendCounter: number
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2) throw new Error('密钥长度不是偶数')
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16)
  return out
}

async function importAes(hex: string): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', hexToBytes(hex), 'AES-GCM', false, ['encrypt', 'decrypt'])
}

export async function importKeyBundle(b: KeyBundle): Promise<SessionKeys> {
  const video = await Promise.all((b.video || []).map(importAes))
  return {
    controlSend: await importAes(b.control_send),
    controlRecv: await importAes(b.control_recv),
    datagramSend: await importAes(b.datagram_send),
    datagramRecv: await importAes(b.datagram_recv),
    bulkSend: await importAes(b.bulk_send),
    bulkRecv: await importAes(b.bulk_recv),
    video,
    sendCounter: b.control_send_counter,
    datagramSendCounter: b.datagram_send_counter,
    bulkSendCounter: b.bulk_send_counter || 0,
  }
}

/** 计数转成 12 字节 nonce：前 4 字节 0，后 8 字节小端。 */
function nonce(counter: number | bigint): Uint8Array {
  const iv = new Uint8Array(12)
  new DataView(iv.buffer).setBigUint64(4, BigInt(counter), true)
  return iv
}

/** 读密封单元末尾的计数。 */
export function unitCounter(unit: Uint8Array): number {
  return Number(unitCounterBig(unit))
}

function unitCounterBig(unit: Uint8Array): bigint {
  if (unit.length < 8) return 0n
  return new DataView(unit.buffer, unit.byteOffset + unit.length - 8, 8).getBigUint64(0, true)
}

/** 解开一个密封单元，返回明文。标签不对就抛错。 */
export async function openSealed(key: CryptoKey, unit: Uint8Array): Promise<Uint8Array> {
  if (unit.length < 24) throw new Error('密封单元太短')
  const body = unit.subarray(0, unit.length - 8)
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonce(unitCounterBig(unit)), tagLength: 128 },
    key,
    body,
  )
  return new Uint8Array(plain)
}

/** 封一个密封单元：密文 | 标签 | 计数。 */
export async function sealUnit(key: CryptoKey, counter: number | bigint, plain: Uint8Array): Promise<Uint8Array> {
  const body = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce(counter), tagLength: 128 },
    key,
    plain,
  ))
  const out = new Uint8Array(body.length + 8)
  out.set(body, 0)
  new DataView(out.buffer).setBigUint64(body.length, BigInt(counter), true)
  return out
}

// ---- 媒体包 ---------------------------------------------------------------

export interface MediaHeader {
  kind: number
  key: boolean
  codec: number
  seq: number
  stream: number
  width: number
  height: number
  captureUs: number
  headerLen: number
}

const HEADER_LEN = 24

/** 解析媒体包头（见 airhand-proto/src/media.rs）。头不合法时返回 null。 */
export function parseMediaHeader(packet: Uint8Array): MediaHeader | null {
  if (packet.length < HEADER_LEN) return null
  const headerLen = packet[3]
  if (headerLen < HEADER_LEN || headerLen > packet.length) return null
  const view = new DataView(packet.buffer, packet.byteOffset, packet.byteLength)
  return {
    kind: packet[0],
    key: (packet[1] & 1) !== 0,
    codec: packet[2],
    seq: view.getUint32(4, true),
    width: view.getUint16(8, true),
    height: view.getUint16(10, true),
    stream: packet[12],
    captureUs: view.getUint32(16, true) + view.getUint32(20, true) * 0x100000000,
    headerLen,
  }
}

/** H.264 Annex-B 里第一段 SPS 的三个字节拼成 `avc1.PPCCLL`。 */
export function avcCodecString(annexb: Uint8Array): string | null {
  for (let i = 0; i + 4 < annexb.length; i++) {
    let start = -1
    if (annexb[i] === 0 && annexb[i + 1] === 0 && annexb[i + 2] === 1) start = i + 3
    else if (i + 4 < annexb.length && annexb[i] === 0 && annexb[i + 1] === 0 && annexb[i + 2] === 0 && annexb[i + 3] === 1) start = i + 4
    if (start < 0) continue
    const type = annexb[start] & 0x1f
    if (type !== 7) continue
    if (start + 3 >= annexb.length) return null
    const hex = (n: number) => n.toString(16).padStart(2, '0')
    return 'avc1.' + hex(annexb[start + 1]) + hex(annexb[start + 2]) + hex(annexb[start + 3])
  }
  return null
}
