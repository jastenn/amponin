package main

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

type PGStore struct {
	DB *sql.DB
}

func (c *PGStore) CreateLocalAccount(ctx context.Context, data NewLocalAccount) (*LocalAccount, *User, error) {
	tx, err := c.DB.Begin()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to begin transaction: %w", err)
	}
	defer tx.Rollback()

	user := &User{}
	row := tx.QueryRowContext(ctx,
		`INSERT INTO users (name, email)
		 VALUES ($1, $2)
		 RETURNING
			user_id, name, email, avatar_url,
			created_at, updated_at`,
		data.Name, data.Email,
	)
	err = row.Scan(
		&user.ID, &user.Name, &user.Email, &user.AvatarURL,
		&user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		if strings.Contains(err.Error(), "unique_user_email") {
			return nil, nil, ErrUserEmailInUse
		}
		return nil, nil, fmt.Errorf("unable to insert into users: %w", err)
	}

	localAccount := &LocalAccount{}
	row = tx.QueryRowContext(ctx,
		`INSERT INTO local_accounts (user_id, password_hash)
		 VALUES ($1, $2)
		 RETURNING 
			local_account_id, password_hash, created_at, updated_at`,
		user.ID, data.PasswordHash,
	)
	err = row.Scan(&localAccount.ID, &localAccount.PasswordHash, &localAccount.CreatedAt, &localAccount.UpdatedAt)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to insert into local_accounts: %w", err)
	}

	err = tx.Commit()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to commit transaction: %w", err)
	}

	return localAccount, user, nil
}

func (c *PGStore) CreateForeignAccount(ctx context.Context, data NewForeignAccount) (*ForeignAccount, *User, error) {
	tx, err := c.DB.Begin()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to begin transaction: %w", err)
	}
	defer tx.Rollback()

	user := &User{}
	row := tx.QueryRowContext(ctx,
		`INSERT INTO users (name, email, avatar_url)
		 VALUES ($1, $2, $3)
		 RETURNING
			user_id, name, email, avatar_url,
			created_at, updated_at`,
		data.Name, data.Email, data.AvatarURL,
	)
	err = row.Scan(
		&user.ID, &user.Name, &user.Email, &user.AvatarURL,
		&user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		if strings.Contains(err.Error(), "unique_user_email") {
			return nil, nil, ErrUserEmailInUse
		}
		return nil, nil, fmt.Errorf("unable to insert into users: %w", err)
	}

	foreignAccount := &ForeignAccount{}
	row = tx.QueryRowContext(ctx,
		`INSERT INTO foreign_account (user_id, provider, provider_id)
		 VALUES ($1, $2, $3)
		 RETURNING 
			provider, provider_id, created_at`,
		user.ID, data.ProviderID, data.Provider,
	)
	err = row.Scan(&foreignAccount.Provider, &foreignAccount.ProviderID, &foreignAccount.CreatedAt)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to insert into local_accounts: %w", err)
	}

	err = tx.Commit()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to commit transaction: %w", err)
	}

	return foreignAccount, user, nil
}
