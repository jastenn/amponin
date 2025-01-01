package main

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

type PGStore struct {
	db *sql.DB
}

func (p *PGStore) CreateLocalAccount(ctx context.Context, data NewLocalAccount) (*LocalAccount, *User, error) {
	tx, err := p.db.Begin()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	row := tx.QueryRowContext(ctx,
		`INSERT INTO users (display_name, email)
		 VALUES ($1, $2)
		 RETURNING
			user_id, display_name, email, avatar_url,
			created_at, updated_at`,
		data.DisplayName, data.Email,
	)
	user := &User{}
	err = row.Scan(
		&user.ID, &user.DisplayName, &user.Email, &user.AvatarURL,
		&user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		if strings.Contains(err.Error(), "unique_user_email") {
			return nil, nil, ErrEmailInUse
		}

		return nil, nil, fmt.Errorf("failed to insert into users table: %w", err)
	}

	row = tx.QueryRowContext(ctx,
		`INSERT INTO local_accounts (user_id, password_hash) 
		 VALUES ($1, $2)
		 RETURNING
			user_id, password_hash, created_at,
			updated_at`,
		user.ID, data.PasswordHash,
	)
	localAccount := &LocalAccount{}
	err = row.Scan(
		&localAccount.UserID, &localAccount.PasswordHash, &localAccount.CreatedAt,
		&localAccount.UpdatedAt,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to insert into local_accounts table: %w", err)
	}

	err = tx.Commit()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to commit transactin: %w", err)
	}

	return localAccount, user, nil
}
