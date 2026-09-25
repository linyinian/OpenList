package op

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/OpenListTeam/OpenList/v4/internal/db"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
)

// ⚠️ 本地定制（fork）：token 白名单从「内存」改为「落库」。
// 上游实现见 server/common/auth.go 的 validTokenCache，进程一重启全部会话失效。
// 这里的语义与内存版保持一致：签发时登记、登出时删除、校验时查询；
// 差别只在于**重启后不丢**。
//
// 失效判定仍然由三条互相独立的链路共同保证，本文件只负责第三条：
//  1. JWT 自身 exp（默认 48h）—— 由 jwt 库校验
//  2. 改密码 —— 由 PwdTS 比对校验（middlewares/auth.go）
//  3. 登出 / 主动作废 —— 由本白名单承担

// HashToken 返回 token 的 SHA-256 十六进制摘要。
// 白名单只存摘要不存明文，数据库泄露也无法直接拿去冒充会话。
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// RegisterValidToken 登记一个新签发的 token（持久化，重启不丢）。
// 顺手清理已过期行；清理失败不影响登记。
func RegisterValidToken(token, username string, expiresAt int64) error {
	if token == "" {
		return nil
	}
	if n, err := db.DeleteExpiredValidTokens(time.Now().Unix()); err != nil {
		utils.Log.Warnf("failed to clean expired valid tokens: %v", err)
	} else if n > 0 {
		utils.Log.Debugf("cleaned %d expired valid token(s)", n)
	}
	return db.CreateValidToken(&model.ValidToken{
		TokenHash: HashToken(token),
		Username:  username,
		ExpiresAt: expiresAt,
	})
}

// InvalidateValidToken 作废一个 token（登出）。
func InvalidateValidToken(token string) error {
	if token == "" {
		return nil
	}
	return db.DeleteValidTokenByHash(HashToken(token))
}

// IsValidToken 查询 token 是否仍在白名单中。
// ⚠️ 查询出错时按「失效」处理（fail closed）：宁可要求重新登录，
// 也不在数据库异常时放行一个来历不明的 token。
func IsValidToken(token string) bool {
	if token == "" {
		return false
	}
	ok, err := db.IsValidTokenExists(HashToken(token))
	if err != nil {
		utils.Log.Errorf("failed to check valid token: %v", err)
		return false
	}
	return ok
}
