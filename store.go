package main

import (
	"context"
	"database/sql"
	"errors"
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
		`INSERT INTO foreign_accounts (user_id, provider, provider_id)
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

func (p *PGStore) GetForeignAccount(ctx context.Context, provider, providerID string) (*ForeignAccount, *User, error) {
	var userID string
	account := &ForeignAccount{}
	row := p.DB.QueryRowContext(ctx,
		`SELECT user_id, provider, provider_id, created_at
		 FROM foreign_accounts
		 WHERE provider = $1 AND provider_id = $2`,
		provider, providerID,
	)
	err := row.Scan(&userID, &account.Provider, &account.ProviderID, &account.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil, ErrNoAccount
		}
		return nil, nil, fmt.Errorf("failed to query foreign accounts table: %w", err)
	}

	user := &User{}
	row = p.DB.QueryRowContext(ctx,
		`SELECT
			user_id, name, email, avatar_url,
			created_at, updated_at
		 FROM users
		 WHERE user_id = $1`,
		userID,
	)
	err = row.Scan(
		&user.ID, &user.Name, &user.Email, &user.AvatarURL,
		&user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to query users table: %w", err)
	}

	return account, user, nil
}

func (p *PGStore) GetLocalAccount(ctx context.Context, email string) (*LocalAccount, *User, error) {
	user := &User{}
	row := p.DB.QueryRowContext(ctx,
		`SELECT
			user_id, name, email, avatar_url,
			created_at, updated_at
		 FROM users
		 WHERE email = $1`,
		email,
	)
	err := row.Scan(
		&user.ID, &user.Name, &user.Email, &user.AvatarURL,
		&user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil, ErrNoUser
		}

		return nil, nil, fmt.Errorf("unable to query users table: %w", err)
	}

	account := &LocalAccount{}
	row = p.DB.QueryRowContext(ctx,
		`SELECT local_account_id, password_hash, created_at, updated_at
		 FROM local_accounts
		 WHERE user_id = $1`,
		user.ID,
	)
	err = row.Scan(&account.ID, &account.PasswordHash, &account.CreatedAt, &account.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil, ErrNoAccount
		}
		return nil, nil, fmt.Errorf("unable to query local_accounts table: %w", err)
	}

	return account, user, nil
}

func (p *PGStore) RegisterShelter(ctx context.Context, userID string, data NewShelter) (*Shelter, error) {
	tx, err := p.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to begin transaction: %w", err)
	}
	defer tx.Rollback()

	row := tx.QueryRowContext(
		ctx,
		`INSERT INTO shelters (
			name, address, coordinates, description
		) VALUES (
			$1, $2, ST_SetSRID(ST_MakePoint($3, $4), 4326), $5
		) RETURNING
			shelter_id, name, address,
			ST_X(coordinates), ST_Y(coordinates), description,
			created_at, updated_at`,
		data.Name, data.Address, data.Coordinates.Longtude, data.Coordinates.Latitude, data.Description,
	)

	shelter := &Shelter{}
	err = row.Scan(
		&shelter.ID, &shelter.Name, &shelter.Address,
		&shelter.Coordinates.Longtude, &shelter.Coordinates.Latitude, &shelter.Description,
		&shelter.CreatedAt, &shelter.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to insert data to shelters table: %w", err)
	}

	_, err = tx.ExecContext(
		ctx,
		`INSERT INTO shelter_roles (user_id, role, shelter_id)
		 VALUES ($1, $2, $3)`,
		userID, ShelterRoleAdmin, shelter.ID,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to insert data to shelter roles table: %w", err)
	}

	err = tx.Commit()
	if err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w:", err)
	}

	return shelter, nil
}

func (p *PGStore) GetShelterByID(ctx context.Context, shelterID string) (*Shelter, error) {
	row := p.DB.QueryRowContext(ctx,
		`SELECT
			shelter_id, name, address,
			ST_Y(coordinates), ST_X(coordinates), description,
			created_at, updated_at
		 FROM shelters
		 WHERE shelter_id = $1`,
		shelterID,
	)

	result := &Shelter{}
	err := row.Scan(
		&result.ID, &result.Name, &result.Address,
		&result.Coordinates.Latitude, &result.Coordinates.Longtude, &result.Description,
		&result.CreatedAt, &result.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNoShelter
		}

		return nil, fmt.Errorf("unable to query shelters table: %w", err)
	}

	return result, nil
}
