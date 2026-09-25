package common

import (
	"time"

	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
	"github.com/golang-jwt/jwt/v4"
	"github.com/pkg/errors"
)

var SecretKey []byte

type UserClaims struct {
	Username string `json:"username"`
	PwdTS    int64  `json:"pwd_ts"`
	jwt.RegisteredClaims
}

// ⚠️ 本地定制（fork，2026-09-25）：原实现在这里放了一个**内存**白名单
// `var validTokenCache = cache.NewMemCache[bool]()`，签发时 Set、登出时 Del、
// 校验时 Get。它不落盘，所以**核心进程一重启，所有已登录会话立刻被判失效**，
// 前端会弹「Token is invalidated」，用户被迫重新登录。
// 现改为走 `internal/op` 的持久化白名单（表 valid_tokens，只存 SHA-256 摘要）。
// 语义保持不变：签发登记 / 登出删除 / 校验查询，只是重启后不再丢。

func GenerateToken(user *model.User) (tokenString string, err error) {
	expiresAt := time.Now().Add(time.Duration(conf.Conf.TokenExpiresIn) * time.Hour)
	claim := UserClaims{
		Username: user.Username,
		PwdTS:    user.PwdTS,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		}}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claim)
	tokenString, err = token.SignedString(SecretKey)
	if err != nil {
		return "", err
	}
	// 登记到持久化白名单。登记失败必须让登录失败——否则会返回一个「查不到、立刻失效」的
	// token，用户表现为刚登录就被踢出去，比直接报错更难排查。
	if err = op.RegisterValidToken(tokenString, user.Username, expiresAt.Unix()); err != nil {
		return "", errors.Wrap(err, "failed to register token")
	}
	return tokenString, nil
}

func ParseToken(tokenString string) (*UserClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &UserClaims{}, func(token *jwt.Token) (interface{}, error) {
		return SecretKey, nil
	})
	if IsTokenInvalidated(tokenString) {
		return nil, errors.New("token is invalidated")
	}
	if err != nil {
		if ve, ok := err.(*jwt.ValidationError); ok {
			if ve.Errors&jwt.ValidationErrorMalformed != 0 {
				return nil, errors.New("that's not even a token")
			} else if ve.Errors&jwt.ValidationErrorExpired != 0 {
				return nil, errors.New("token is expired")
			} else if ve.Errors&jwt.ValidationErrorNotValidYet != 0 {
				return nil, errors.New("token not active yet")
			} else {
				return nil, errors.New("couldn't handle this token")
			}
		}
	}
	if claims, ok := token.Claims.(*UserClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, errors.New("couldn't handle this token")
}

func InvalidateToken(tokenString string) error {
	if tokenString == "" {
		return nil // don't invalidate empty guest token
	}
	return op.InvalidateValidToken(tokenString)
}

func IsTokenInvalidated(tokenString string) bool {
	return !op.IsValidToken(tokenString)
}
