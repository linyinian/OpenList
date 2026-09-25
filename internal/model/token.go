package model

// ValidToken 是「有效 token 白名单」的持久化记录。
//
// ⚠️ 本地定制（fork）：上游把这个白名单放在**内存**里（`server/common/auth.go` 的
// `validTokenCache`），导致**核心进程一重启，所有已登录会话立刻失效**，前端会弹
// 「Token is invalidated」。这里改为落库，重启后仍有效。
//
// 安全设计：**只存 token 的 SHA-256 摘要，不存明文**——
// 这样即便数据库文件泄露，也无法从中直接取出可用的 token 去冒充会话。
type ValidToken struct {
	TokenHash string `json:"token_hash" gorm:"primaryKey;size:64"`
	// 便于排查「谁还有活跃会话」；不作为鉴权依据
	Username string `json:"username" gorm:"index;size:255"`
	// token 自身的 JWT exp（Unix 秒），用于清理过期行
	ExpiresAt int64 `json:"expires_at" gorm:"index"`
}
