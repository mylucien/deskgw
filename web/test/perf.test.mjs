// 浏览器控制端的离线核对：加密布局、CBOR、媒体包头、SPS。
//
// 向量来源：
//   - 密封单元：用与 internal/perfgw/handshake.go 的 seal 相同的布局生成
//     （AES-256-GCM，nonce 12 字节，前 4 字节 0、后 8 字节小端计数，计数附在末尾）
//   - CBOR：airhand-proto/tests/v10.rs 的黄金字节
//
// 运行：npm run test:perf

import { importKeyBundle, openSealed, sealUnit, unitCounter, parseMediaHeader, avcCodecString } from '../src/perf/wire'
import { CborWriter } from '../src/perf/cbor'
import { decodeHostMsg, encodeAck, encodeInput, encodePing, encodeRequestKeyframe } from '../src/perf/messages'

let failed = 0
function check(name, got, want) {
  const g = JSON.stringify(got)
  const w = JSON.stringify(want)
  if (g !== w) {
    failed++
    console.log(`FAIL ${name}\n  实际 ${g}\n  期望 ${w}`)
  } else {
    console.log(`ok   ${name}`)
  }
}

const hex = (s) => Uint8Array.from(s.match(/../g) || [], (x) => parseInt(x, 16))
const toHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')

const KEY = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
const SEALED = '749d93290d0fbf21e71f9a3283920d9f2a524bd8066b783c265fbf0807060504030201'

const keys = await importKeyBundle({
  control_send: KEY, control_recv: KEY, datagram_send: KEY, datagram_recv: KEY, video: [KEY],
  control_send_counter: 1, control_recv_counter: 1,
  datagram_send_counter: 0, datagram_recv_counter: 0,
})

// ---- 密封单元 ----
const unit = hex(SEALED)
check('计数读法', unitCounter(unit), 0x0102030405060708)
const plain = await openSealed(keys.controlRecv, unit)
check('解开 Go 生成的密封单元', new TextDecoder().decode(plain), 'hello world')
const resealed = await sealUnit(keys.controlSend, 0x0102030405060708n, new TextEncoder().encode('hello world'))
check('重新加密后字节一致', toHex(resealed), SEALED)

// ---- CBOR：HostMsg ----
check('Bye(Kicked)', decodeHostMsg(hex('82098100')), { type: 'bye', reason: 0 })
check('Cursor(Hidden, None)', decodeHostMsg(hex('82078100')), { type: 'cursor', visibility: 0, slot: -1, generation: -1 })
check('Cursor(Shown, ref 2/7)', decodeHostMsg(hex('82078201820207')), { type: 'cursor', visibility: 1, slot: 2, generation: 7 })
check('Cursor(InFrame)', decodeHostMsg(hex('82078102')), { type: 'cursor', visibility: 2, slot: -1, generation: -1 })
check('CursorImage', decodeHostMsg(hex('820a8282020785010100004401020304')), { type: 'other', variant: 10 })
check('Mic(Ready)', decodeHostMsg(hex('820c8102')), { type: 'other', variant: 12 })

// HostHello：hostname, os, version, displays[], current, codecs[], platform, touch, actions[], shown[], streams
const hw = new CborWriter()
hw.array(2).uint(1).array(1).array(11)
  .text('HOST').text('OS!').text('0.4')
  .array(1).array(7).uint(0).text('Dis').int(1).int(2).uint(1920).uint(1080).bool(true)
  .uint(0)
  .array(1).uint(0)
  .uint(0).bool(false).array(0).array(0).uint(1)
const helloEv = decodeHostMsg(hw.take())
check('Hello 基本字段', [helloEv.hostname, helloEv.os, helloEv.version, helloEv.platform, helloEv.streams], ['HOST', 'OS!', '0.4', 0, 1])
check('Hello 显示器', helloEv.displays, [{ index: 0, name: 'Dis', x: 1, y: 2, width: 1920, height: 1080, primary: true }])

// ---- CBOR：ControllerMsg / 数据报 ----
check('RequestKeyframe(5)', toHex(encodeRequestKeyframe(5)), '82048105')
check('Ping(5)', toHex(encodePing(5)), '82008105')
check('Ack(99,1000)', toHex(encodeAck(99, 1000)), '82018218631903e8')
check('Input(ReleaseAll)', toHex(encodeInput(5, [{ kind: 'releaseAll' }])), '8201820581820680')
// InputEvent::Text：变体 5，字段是单个字符串；被控端按 Unicode 注入，中文、emoji 都走这条。
check('Input(Text 你好)', toHex(encodeInput(5, [{ kind: 'text', text: '你好' }])), '820182058182058166e4bda0e5a5bd')
check('Input(Text abc)', toHex(encodeInput(5, [{ kind: 'text', text: 'abc' }])), '820182058182058163616263')

// ---- 媒体包头 ----
const pkt = new Uint8Array(30)
pkt[0] = 1
pkt[1] = 1
pkt[2] = 0
pkt[3] = 24
new DataView(pkt.buffer).setUint32(4, 42, true)
new DataView(pkt.buffer).setUint16(8, 1920, true)
new DataView(pkt.buffer).setUint16(10, 1080, true)
pkt[12] = 0
new DataView(pkt.buffer).setUint32(16, 123456, true)
const mh = parseMediaHeader(pkt)
check('画面包头', [mh.kind, mh.key, mh.codec, mh.seq, mh.width, mh.height, mh.stream, mh.captureUs, mh.headerLen],
  [1, true, 0, 42, 1920, 1080, 0, 123456, 24])

// SPS：00 00 00 01 67 42 C0 1E ...
const sps = hex('000000016742c01e0000000168ce3c80')
check('SPS 转 codec 字符串', avcCodecString(sps), 'avc1.42c01e')

console.log(failed ? `\n${failed} 项失败` : '\n全部通过')
process.exit(failed ? 1 : 0)
