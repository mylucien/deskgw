// 最小的 CBOR 读写。
//
// 只覆盖 airhand 会话消息用到的类型：整数、字节串、文本、数组、映射、布尔、
// null 与 f32。被控端用 minicbor 派生编码，枚举是 `[变体号, [字段…]]`，尾部
// 的 Option::None 与 skip_if 字段整个不写，所以读的时候不能假定数组长度。

export type CborValue =
  | number
  | string
  | Uint8Array
  | boolean
  | null
  | CborValue[]
  | Map<CborValue, CborValue>

const textDecoder = new TextDecoder()
const textEncoder = new TextEncoder()

export class CborReader {
  private pos = 0
  private view: DataView

  constructor(private buf: Uint8Array) {
    this.view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength)
  }

  get offset(): number {
    return this.pos
  }

  get remaining(): number {
    return this.buf.length - this.pos
  }

  /** 读一个头，返回主类型、附加信息编号，以及附加信息里的数值（不定长返回 -1）。 */
  private head(): { major: number; info: number; value: number } {
    if (this.pos >= this.buf.length) throw new Error('CBOR 数据不够')
    const b = this.buf[this.pos++]
    const major = b >> 5
    const info = b & 0x1f
    if (info < 24) return { major, info, value: info }
    if (info === 24) return { major, info, value: this.uintN(1) }
    if (info === 25) return { major, info, value: this.uintN(2) }
    if (info === 26) return { major, info, value: this.uintN(4) }
    if (info === 27) return { major, info, value: this.uintN(8) }
    if (info === 31) return { major, info, value: -1 }
    throw new Error('CBOR 头的附加信息不认识: ' + info)
  }

  private uintN(n: number): number {
    if (this.pos + n > this.buf.length) throw new Error('CBOR 数据不够')
    // CBOR 的附加信息是大端。
    let v = 0
    for (let i = 0; i < n; i++) v = v * 256 + this.buf[this.pos + i]
    this.pos += n
    return v
  }

  value(): CborValue {
    const { major, info, value } = this.head()
    switch (major) {
      case 0:
        return value
      case 1:
        return -1 - value
      case 2: {
        if (value < 0) throw new Error('不支持不定长字节串')
        const out = this.buf.subarray(this.pos, this.pos + value)
        this.pos += value
        return out
      }
      case 3: {
        if (value < 0) throw new Error('不支持不定长文本')
        const out = textDecoder.decode(this.buf.subarray(this.pos, this.pos + value))
        this.pos += value
        return out
      }
      case 4: {
        if (value < 0) {
          const arr: CborValue[] = []
          while (this.buf[this.pos] !== 0xff) arr.push(this.value())
          this.pos++
          return arr
        }
        const arr: CborValue[] = new Array(value)
        for (let i = 0; i < value; i++) arr[i] = this.value()
        return arr
      }
      case 5: {
        const map = new Map<CborValue, CborValue>()
        const n = value < 0 ? Infinity : value
        for (let i = 0; i < n; i++) {
          if (value < 0 && this.buf[this.pos] === 0xff) {
            this.pos++
            break
          }
          map.set(this.value(), this.value())
        }
        return map
      }
      case 6:
        // 标签只是包一层，内容照读。
        return this.value()
      case 7: {
        if (info === 20) return false
        if (info === 21) return true
        if (info === 22) return null
        if (info === 23) return null
        if (info === 25) return half(this.uintN(2))
        if (info === 26) {
          if (this.pos + 4 > this.buf.length) throw new Error('CBOR 数据不够')
          const v = this.view.getFloat32(this.pos, false)
          this.pos += 4
          return v
        }
        if (info === 27) {
          if (this.pos + 8 > this.buf.length) throw new Error('CBOR 数据不够')
          const v = this.view.getFloat64(this.pos, false)
          this.pos += 8
          return v
        }
        throw new Error('CBOR 简单值不认识: ' + info)
      }
      default:
        throw new Error('CBOR 主类型不认识: ' + major)
    }
  }
}

/** 半精度浮点（Canvas 里没用，但 f16 也是合法 CBOR）。 */
function half(u: number): number {
  const sign = u & 0x8000 ? -1 : 1
  const exp = (u >> 10) & 0x1f
  const frac = u & 0x3ff
  if (exp === 0) return sign * frac * 2 ** -24
  if (exp === 31) return frac ? NaN : sign * Infinity
  return sign * (1 + frac / 1024) * 2 ** (exp - 15)
}

export function cborValue(buf: Uint8Array): CborValue {
  return new CborReader(buf).value()
}

/** 只写消息用，字节数不大，用数组攒着就行。 */
export class CborWriter {
  private out: number[] = []

  private head(major: number, n: number): void {
    const m = major << 5
    if (n < 24) {
      this.out.push(m | n)
    } else if (n < 0x100) {
      this.out.push(m | 24, n)
    } else if (n < 0x10000) {
      this.out.push(m | 25, (n >> 8) & 0xff, n & 0xff)
    } else if (n < 0x100000000) {
      this.out.push(m | 26, (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff)
    } else {
      const hi = Math.floor(n / 0x100000000)
      const lo = n >>> 0
      this.out.push(m | 27,
        (hi >>> 24) & 0xff, (hi >>> 16) & 0xff, (hi >>> 8) & 0xff, hi & 0xff,
        (lo >>> 24) & 0xff, (lo >>> 16) & 0xff, (lo >>> 8) & 0xff, lo & 0xff)
    }
  }

  uint(n: number): this {
    this.head(0, n)
    return this
  }

  int(n: number): this {
    if (n >= 0) return this.uint(n)
    this.head(1, -1 - n)
    return this
  }

  bytes(b: Uint8Array): this {
    this.head(2, b.length)
    for (let i = 0; i < b.length; i++) this.out.push(b[i])
    return this
  }

  text(s: string): this {
    const b = textEncoder.encode(s)
    this.head(3, b.length)
    for (let i = 0; i < b.length; i++) this.out.push(b[i])
    return this
  }

  array(n: number): this {
    this.head(4, n)
    return this
  }

  bool(v: boolean): this {
    this.out.push(v ? 0xf5 : 0xf4)
    return this
  }

  null(): this {
    this.out.push(0xf6)
    return this
  }

  float32(v: number): this {
    this.out.push(0xfa)
    const b = new Uint8Array(4)
    new DataView(b.buffer).setFloat32(0, v, false)
    for (let i = 0; i < 4; i++) this.out.push(b[i])
    return this
  }

  take(): Uint8Array {
    return Uint8Array.from(this.out)
  }
}
