package db

import (
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/pkg/errors"
	"gorm.io/gorm/clause"
)

// CreateValidToken 登记一个 token 摘要。
// 用 upsert 保证幂等：同一秒内重复登录会生成**完全相同**的 JWT（iat/exp 都只到秒），
// 直接 Create 会撞主键；upsert 让这种重复提交也安全。
func CreateValidToken(t *model.ValidToken) error {
	return errors.WithStack(
		db.Clauses(clause.OnConflict{UpdateAll: true}).Create(t).Error,
	)
}

// DeleteValidTokenByHash 按摘要删除（登出时调用）。
func DeleteValidTokenByHash(hash string) error {
	return errors.WithStack(
		db.Where("token_hash = ?", hash).Delete(&model.ValidToken{}).Error,
	)
}

// IsValidTokenExists 摘要是否仍在白名单中。
func IsValidTokenExists(hash string) (bool, error) {
	var count int64
	if err := db.Model(&model.ValidToken{}).Where("token_hash = ?", hash).Count(&count).Error; err != nil {
		return false, errors.WithStack(err)
	}
	return count > 0, nil
}

// DeleteExpiredValidTokens 清理已过期的记录，返回删除行数。
func DeleteExpiredValidTokens(now int64) (int64, error) {
	res := db.Where("expires_at < ?", now).Delete(&model.ValidToken{})
	return res.RowsAffected, errors.WithStack(res.Error)
}
