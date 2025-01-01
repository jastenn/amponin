package main

import (
	"context"
	"database/sql"
	"errors"
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

func (p *PGStore) GetLocalAccount(ctx context.Context, email string) (*LocalAccount, *User, error) {
	user := &User{}
	err := p.db.QueryRowContext(ctx,
		`SELECT user_id, email, display_name, avatar_url,
			created_at, updated_at
		 FROM users
		 WHERE email = $1`,
		email,
	).Scan(
		&user.ID, &user.Email, &user.DisplayName, &user.AvatarURL,
		&user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil, ErrNoLocalAccount
		}
		return nil, nil, fmt.Errorf("unable to query user by email: %w", err)
	}

	localAccount := &LocalAccount{}
	err = p.db.QueryRowContext(ctx,
		`SELECT password_hash, created_at, updated_at
		 FROM local_accounts
		 WHERE user_id = $1`,
		user.ID,
	).Scan(&localAccount.PasswordHash, &localAccount.CreatedAt, &localAccount.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil, ErrNoLocalAccount
		}
		return nil, nil, fmt.Errorf("unable to query user's local account: %w", err)
	}

	return localAccount, user, nil
}
