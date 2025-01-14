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

func (p *PGStore) CreateShelter(ctx context.Context, userID string, data NewShelter) (*Shelter, error) {
	tx, err := p.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: " + err.Error())
	}
	defer tx.Rollback()

	row := tx.QueryRowContext(ctx,
		`INSERT INTO shelters (name, coordinates, address, description)
		 VALUES ($1, ST_SetSRID(ST_MakePoint($2, $3), 4326), $4, $5)
		 RETURNING
			shelter_id, name, address, avatar_url,
			description, created_at, updated_at`,
		data.Name, data.Coordinates.Longitude, data.Coordinates.Latitude, data.Address, data.Description,
	)

	shelter := &Shelter{}
	err = row.Scan(
		&shelter.ID, &shelter.Name, &shelter.Address, &shelter.AvatarURL,
		&shelter.Description, &shelter.CreatedAt, &shelter.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to insert into shelters table: %w", err)
	}

	_, err = tx.ExecContext(ctx,
		`INSERT INTO shelter_roles (shelter_id, user_id, role)
		 VALUES ($1, $2, $3)`,
		shelter.ID, userID, ShelterRoleSuperAdmin,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to insert into shelter_roles table: %w", err)
	}

	err = tx.Commit()
	if err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return shelter, nil
}

func (p *PGStore) FindSheltersByUserID(ctx context.Context, userID string) ([]*Shelter, error) {
	rows, err := p.db.QueryContext(ctx,
		`SELECT
			shelter_id, name, avatar_url, address,
			description, shelters.created_at, shelters.updated_at
		 FROM shelters
		 JOIN shelter_roles USING(shelter_id)
		 WHERE user_id = $1`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to query shelters table: %w", err)
	}
	defer rows.Close()

	var result []*Shelter
	for rows.Next() {
		shelter := &Shelter{}
		err := rows.Scan(
			&shelter.ID, &shelter.Name, &shelter.AvatarURL, &shelter.Address,
			&shelter.Description, &shelter.CreatedAt, &shelter.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to scan shelters table query: %w", err)
		}

		result = append(result, shelter)
	}

	return result, nil
}
