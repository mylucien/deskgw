package perfgw

// 黄金向量：固定了 static 与 ephemeral 私钥，整条握手可复现。由 Rust 侧
// （snow 0.10 + airhand_proto/airhand_link 的同一套调用）生成，生成方式见
// docs/perf-protocol.md。改 noise.go 或 handshake.go 时先跑这一组。
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
	// vecIntro ControllerIntro 的真实编码（名字 deskgw、系统 OpenWrt、默认画质）
	vecIntro = "8601666465736b6777674f70656e57727485181e190fa0190438f500f480"
	// vecXXPrologue XX 的 prologue（模式码 1）
	vecXXPrologue = "61697268616e6420653265203901000000"
	// vecXXMsg1 XX 第 1 条
	vecXXMsg1 = "c306fb0ef2bf8b7f93bad98155fa37daec74db0c4cbeda6c6f1dba9d36558252"
	// vecXXMsg2 XX 第 2 条（被控端发出）
	vecXXMsg2 = "db48257e1237976a74ad8cfedca00213408fe89ac6251f1b930245f242b5c31a7dba3a3922f6562b64b5f5cbb484aa988549a417ea9ac91e21fb55a2cb14e21e4667d2616d9815721e2debef314021c61f776720df21717c23591f3858562216"
	// vecXXMsg3 XX 第 3 条（负载是 vecIntro）
	vecXXMsg3 = "e9c008c5eaff4b7fc3311dab7727d3840e63126353812ecf6f30bef33c12919e0e6abefa445477ef43d09a8a93ce7a0317eb33e89026765baff2dd29f116792b5589aaccfeb3afa918f75e745cacde8b7390da70b7f84c7b827a39280861"
	// vecXXHash XX 的握手哈希
	vecXXHash = "f8126c1c1dc0ba98fb594fc22d4f72bb016bbc236ec0479a486fbf3412242757"
	// vecXXI2R XX 控制端→被控端
	vecXXI2R = "80cea13f62aa08eefbecd1ca814726f1064e6b693ae1106800b709736373a80b"
	// vecXXR2I XX 被控端→控制端
	vecXXR2I = "567b175dc7312dce57e877cef1294b6c4fd79ba19eac819f9a56c8029b6991e6"
	// vecXXSafety XX 的安全码
	vecXXSafety = "584-799"
	// vecIKPrologue IK 的 prologue（模式码 0）
	vecIKPrologue = "61697268616e6420653265203900000000"
	// vecIKMsg1 IK 第 1 条（负载是 vecIntro）
	vecIKMsg1 = "c306fb0ef2bf8b7f93bad98155fa37daec74db0c4cbeda6c6f1dba9d36558252f2013c7cdad891db1120e2b342d59855b3d359842c949ea67d840134ade38826edaa89dc2dae3aab06daaced1566f2513df9ac1a6558f2a608b621f5ceb294c752681400fe46f23d19285e5ed2bb4533506d4869b26c56424514b0a67590"
	// vecIKMsg2 IK 第 2 条（被控端发出）
	vecIKMsg2 = "db48257e1237976a74ad8cfedca00213408fe89ac6251f1b930245f242b5c31a3f7dcf84da511d4b53c8dff6d60bdac0"
	// vecIKHash IK 的握手哈希
	vecIKHash = "283004bff39f5a4e244eaf0022a07283d45cb4cfab4487fbb62972163a486587"
	// vecIKI2R IK 控制端→被控端
	vecIKI2R = "38b0017736119a8d0ddeec7dea5cf00045945f450d0dd85cf394fbe2255e0554"
	// vecIKR2I IK 被控端→控制端
	vecIKR2I = "61ed70f85a76639af17a107c8c4bdce923a6f3bf4990cd2342357d997f4ed67c"
	// vecIKSafety IK 的安全码
	vecIKSafety = "649-788"
	// vecIKVerdictSealed IK 里被控端加密的决定：明文 8101，控制通道收方向、计数 0
	vecIKVerdictSealed = "e52aae2a46f546c7db6a25fe59f8d6cdd1670000000000000000"
)
