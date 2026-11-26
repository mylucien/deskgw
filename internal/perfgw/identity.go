package perfgw

// 路由器作为控制端的长期 X25519 身份密钥。
//
// 被控端放行控制端只看「这把公钥在不在 [[paired]] 里」，所以它是整个性能模式
// 的信任根：丢了它，每台被控端都要重新预置配对；泄露了，任何拿到它的人都能冒充
// 路由器连上所有被控端。文件权限 0600，必须纳入备份。

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

// identityFileMode 是私钥文件的权限：只有网关进程自己能读。
const identityFileMode = 0o600

// loadOrCreateIdentity 读取（不存在时生成）控制端身份密钥。
//
// 文件内容是 64 位小写十六进制的 32 字节种子，与后台显示的公钥同一种写法，
// 方便管理员直接抄、也方便备份时肉眼比对。
func loadOrCreateIdentity(path string) (*ecdh.PrivateKey, error) {
	if path == "" {
		return nil, errors.New("没有配置性能模式的控制端密钥路径")
	}
	text, err := os.ReadFile(path)
	if err == nil {
		key, perr := parseIdentity(string(text))
		if perr != nil {
			return nil, fmt.Errorf("控制端密钥 %s 不可用（删掉它会生成新密钥，但每台被控端都要重新预置配对）: %w", path, perr)
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("读取控制端密钥 %s: %w", path, err)
	}

	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	// 先写临时文件再改名：中途断电不会留下半个密钥文件，那比没有更糟 ——
	// 服务会以为密钥坏了，而备份里的旧密钥其实还能用。
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(hex.EncodeToString(key.Bytes())+"\n"), identityFileMode); err != nil {
		return nil, fmt.Errorf("写入控制端密钥 %s: %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return nil, fmt.Errorf("写入控制端密钥 %s: %w", path, err)
	}
	return key, nil
}

// parseIdentity 读 64 位十六进制（允许首尾空白和换行，方便手工粘贴）。
func parseIdentity(s string) (*ecdh.PrivateKey, error) {
	s = strings.TrimSpace(s)
	raw, err := hex.DecodeString(s)
	if err != nil {
		return nil, errors.New("不是十六进制")
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("应当是 32 字节（64 位十六进制），实际 %d 字节", len(raw))
	}
	return ecdh.X25519().NewPrivateKey(raw)
}

// identityPublic 返回公钥的 64 位小写十六进制，直接填进被控端 config.toml 的
// [[paired]].key（被控端就是这么读的）。
func identityPublic(key *ecdh.PrivateKey) string {
	if key == nil {
		return ""
	}
	return hex.EncodeToString(key.PublicKey().Bytes())
}
