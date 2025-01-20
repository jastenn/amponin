package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/lib/pq"
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

func (p *PGStore) FindSheltersByUserID(ctx context.Context, userID string) ([]*ShelterWithRole, error) {
	rows, err := p.db.QueryContext(ctx,
		`SELECT
			shelter_id, name, avatar_url, address,
			description, shelters.created_at, shelters.updated_at,
			role
		 FROM shelters
		 JOIN shelter_roles USING(shelter_id)
		 WHERE user_id = $1`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to query shelters table: %w", err)
	}
	defer rows.Close()

	var result []*ShelterWithRole
	for rows.Next() {
		shelter := &ShelterWithRole{}
		err := rows.Scan(
			&shelter.Shelter.ID, &shelter.Shelter.Name, &shelter.Shelter.AvatarURL, &shelter.Shelter.Address,
			&shelter.Shelter.Description, &shelter.Shelter.CreatedAt, &shelter.Shelter.UpdatedAt,
			&shelter.Role,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to scan shelters table query: %w", err)
		}

		result = append(result, shelter)
	}

	return result, nil
}

func (p *PGStore) GetShelterByID(ctx context.Context, shelterID string) (*Shelter, error) {
	row := p.db.QueryRowContext(
		ctx,
		`SELECT
			shelter_id, name, avatar_url, address,
			description, created_at, updated_at
		 FROM shelters
		 WHERE shelter_id = $1`,
		shelterID,
	)

	shelter := &Shelter{}
	err := row.Scan(
		&shelter.ID, &shelter.Name, &shelter.AvatarURL, &shelter.Address,
		&shelter.Description, &shelter.CreatedAt, &shelter.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNoShelter
		}
		return nil, fmt.Errorf("unable to query shelter table: %w", err)
	}

	return shelter, nil
}

func (p *PGStore) GetShelterRoleByID(ctx context.Context, shelterID, userID string) (ShelterRole, error) {
	row := p.db.QueryRowContext(
		ctx,
		`SELECT role FROM shelter_roles
		 WHERE shelter_id = $1 AND user_id = $2`,
		shelterID, userID,
	)

	var role string
	err := row.Scan(&role)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrNoShelterRole
		}

		return "", fmt.Errorf("failed to query shelter roles table: %w", err)
	}

	return ShelterRole(role), nil
}

func (p *PGStore) RegisterPet(ctx context.Context, data NewPet) (*Pet, error) {
	row := p.db.QueryRowContext(ctx,
		`INSERT INTO pets (
			shelter_id, name, pet_type, gender,
			birth_date, is_birth_date_approx, description, image_urls
		) VALUES (
			$1, $2, $3, $4,
			$5, $6, $7, $8
		) RETURNING
			pet_id, name, pet_type, gender,
			birth_date, is_birth_date_approx, description, image_urls,
			registered_at, updated_at`,
		data.ShelterID, data.Name, data.Type, data.Gender,
		data.BirthDate, data.IsBirthDateApprox, data.Description, pq.Array(data.ImageURLs),
	)

	pet := &Pet{}
	err := row.Scan(
		&pet.ID, &pet.Name, &pet.Type, &pet.Gender,
		&pet.BirthDate, &pet.IsBirthDateApprox, &pet.Description, pq.Array(&pet.ImageURLs),
		&pet.RegisteredAt, &pet.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to insert into pets table: %w", err)
	}

	return pet, nil
}
