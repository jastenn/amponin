package pgstore

import (
	"context"
	"database/sql"
	"strings"

	"github.com/jastenn/amponin/internal/usecase"
)

const (
	userPKeyConstraintKey     = "pkey_user"
	accountsPKeyConstraintKey = "pkey_account"
)

func NewUserStore(db *sql.DB) *UserStore {
	return &UserStore{db}
}

type UserStore struct {
	db *sql.DB
}

func (u *UserStore) Create(ctx context.Context, user usecase.User) error {
	tx, err := u.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	_, err = tx.Exec(
		`INSERT INTO users (
            username, email, verified,
            created_at, updated_at
        ) VALUES (
            $1, $2, $3,
            $4, $5
        )`,
		user.Username, user.Email, user.Verified,
		user.CreatedAt, user.UpdatedAt,
	)
	if err != nil {
		if err := tx.Rollback(); err != nil {
			return err
		}
		if strings.Contains(err.Error(), userPKeyConstraintKey) {
			return usecase.ErrAccountAlreadyUsed
		}
		return err
	}

	if user.Picture != nil {
		_, err = tx.Exec(
			`INSERT INTO avatars (
                username, raw, thumbnail
            ) VALUES (
                $1, $2, $3
            )`,
			user.Username, user.Picture.Raw, user.Picture.Thumbnail,
		)
		if err != nil {
			if err := tx.Rollback(); err != nil {
				return err
			}
			return err
		}
	}

	_, err = tx.Exec(
		`INSERT INTO accounts (
            username, account_id, provider,
            created_at, updated_at
        ) VALUES (
            $1, $2, $3,
            $4, $5
        )`,
		user.Username, user.Account.ID, user.Account.Provider,
		user.Account.CreatedAt, user.Account.UpdatedAt,
	)
	if err != nil {
		if err := tx.Rollback(); err != nil {
			return err
		}
		if strings.Contains(err.Error(), accountsPKeyConstraintKey) {
            return usecase.ErrAccountAlreadyUsed
		}
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}
