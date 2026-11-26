package perfgw

// 黄金向量：固定了 static 与 ephemeral 私钥，整条握手可复现。由 Rust 侧
// （snow 0.10 + airhand_proto/airhand_link 的同一套调用）生成，生成方式见
// docs/perf-protocol.md。改 noise.go 时先跑这一组，字节对不上就说明跟被控端不通。
const (
	// vecCtrlStaticPriv 控制端的 static 私钥
	vecCtrlStaticPriv = "1111111111111111111111111111111111111111111111111111111111111111"
	// vecCtrlStaticPub 控制端的 static 公钥
	vecCtrlStaticPub = "7b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f13"
	// vecHostStaticPriv 被控端的 static 私钥
	vecHostStaticPriv = "2222222222222222222222222222222222222222222222222222222222222222"
	// vecHostStaticPub 被控端的 static 公钥
	vecHostStaticPub = "0faa684ed28867b97f4a6a2dee5df8ce974e76b7018e3f22a1c4cf2678570f20"
	// vecCtrlEphPriv 控制端这次的临时私钥
	vecCtrlEphPriv = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
	// vecXXPrologue XX 的 prologue（模式码 1）
	vecXXPrologue = "61697268616e6420653265203901000000"
	// vecXXMsg1 XX 第 1 条
	vecXXMsg1 = "c306fb0ef2bf8b7f93bad98155fa37daec74db0c4cbeda6c6f1dba9d36558252"
	// vecXXMsg2 XX 第 2 条（被控端发出）
	vecXXMsg2 = "db48257e1237976a74ad8cfedca00213408fe89ac6251f1b930245f242b5c31a7dba3a3922f6562b64b5f5cbb484aa988549a417ea9ac91e21fb55a2cb14e21e4667d2616d9815721e2debef314021c61f776720df21717c23591f3858562216"
	// vecXXMsg3 XX 第 3 条（负载是 vecIntro）
	vecXXMsg3 = "e9c008c5eaff4b7fc3311dab7727d3840e63126353812ecf6f30bef33c12919e0e6abefa445477ef43d09a8a93ce7a0312e0a00c9e10e7f8c3b8fe61051c6940121eb835"
	// vecXXHash XX 的握手哈希
	vecXXHash = "8cc9f51c45591d48902d0152d4771126ac693a8a438cc9a3fc2adc5c85d2ddd0"
	// vecXXI2R XX 控制端→被控端
	vecXXI2R = "80cea13f62aa08eefbecd1ca814726f1064e6b693ae1106800b709736373a80b"
	// vecXXR2I XX 被控端→控制端
	vecXXR2I = "567b175dc7312dce57e877cef1294b6c4fd79ba19eac819f9a56c8029b6991e6"
	// vecXXSafety XX 的安全码
	vecXXSafety = "403-310"
	// vecIKPrologue IK 的 prologue（模式码 0）
	vecIKPrologue = "61697268616e6420653265203900000000"
	// vecIKMsg1 IK 第 1 条（负载为空）
	vecIKMsg1 = "c306fb0ef2bf8b7f93bad98155fa37daec74db0c4cbeda6c6f1dba9d36558252f2013c7cdad891db1120e2b342d59855b3d359842c949ea67d840134ade38826edaa89dc2dae3aab06daaced1566f251a2f68722426e4dad563a49a2095893ff"
	// vecIKMsg2 IK 第 2 条（被控端发出）
	vecIKMsg2 = "db48257e1237976a74ad8cfedca00213408fe89ac6251f1b930245f242b5c31a4375e14fdcea5838a3773d804b1f4646"
	// vecIKHash IK 的握手哈希
	vecIKHash = "8579c4d75dda07b677e028e9221238585fa863a74a79945998cdc9964790f149"
	// vecIKI2R IK 控制端→被控端
	vecIKI2R = "38b0017736119a8d0ddeec7dea5cf00045945f450d0dd85cf394fbe2255e0554"
	// vecIKR2I IK 被控端→控制端
	vecIKR2I = "61ed70f85a76639af17a107c8c4bdce923a6f3bf4990cd2342357d997f4ed67c"
	// vecIKSafety IK 的安全码
	vecIKSafety = "904-311"
)

// vecIntro 是 XX 第 3 条消息的负载，随便一段确定的字节。
var vecIntro = []byte{0x83, 0x0a, 0xf5, 0x80}
