package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"
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
		userID, ShelterRoleSuperAdmin, shelter.ID,
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
			shelter_id, name, avatar_url, address, 
			ST_Y(coordinates), ST_X(coordinates), description, created_at,
			updated_at
		 FROM shelters
		 WHERE shelter_id = $1`,
		shelterID,
	)

	result := &Shelter{}
	err := row.Scan(
		&result.ID, &result.Name, &result.AvatarURL, &result.Address,
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

func (p *PGStore) FindManagedShelter(ctx context.Context, userID string) ([]*ManagedShelterResult, error) {
	rows, err := p.DB.QueryContext(ctx,
		`SELECT
			s.shelter_id, name, avatar_url, address, 
			ST_Y(coordinates), ST_X(coordinates), description, created_at,
			updated_at, role
		 FROM shelters as s
		 JOIN shelter_roles as r USING(shelter_id)	
		 WHERE r.user_id = $1`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query shelter with roles: %w", err)
	}
	defer rows.Close()

	var result []*ManagedShelterResult
	for rows.Next() {
		shelter := &Shelter{}
		var role string
		err := rows.Scan(
			&shelter.ID, &shelter.Name, &shelter.AvatarURL, &shelter.Address,
			&shelter.Coordinates.Latitude, &shelter.Coordinates.Longtude, &shelter.Description, &shelter.CreatedAt,
			&shelter.UpdatedAt, &role,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan result item: %w", err)
		}

		result = append(result, &ManagedShelterResult{
			Role:    ShelterRole(role),
			Shelter: shelter,
		})
	}

	err = rows.Err()
	if err != nil {
		return nil, fmt.Errorf("failed to scan result: %w", err)
	}

	return result, nil
}

func (p *PGStore) GetShelterRole(ctx context.Context, shelterID, userID string) (ShelterRole, error) {
	row := p.DB.QueryRowContext(ctx,
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

func (p *PGStore) RegisterPet(ctx context.Context, shelterID string, data NewPet) (*Pet, error) {
	images := ConvertImagesToPGImages(data.Images)

	row := p.DB.QueryRowContext(
		ctx,
		`INSERT INTO pets (
			name, gender, type, images,
			description	
		) VALUES (
			$1, $2, $3, $4,
			$5
		) RETURNING 
			pet_id, name, gender, type,
			images, description, registered_at, updated_at`,
		data.Name, data.Gender, data.Type, pq.Array(images),
		data.Description,
	)
	var result struct {
		ID           string
		Name         string
		Gender       string
		Type         string
		Images       []pgImage
		Description  string
		RegisteredAt time.Time
		UpdatedAt    time.Time
	}
	err := row.Scan(
		&result.ID, &result.Name, &result.Gender, &result.Type,
		pq.Array(&result.Images), &result.Description, &result.RegisteredAt, &result.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to insert into pets table: %w", err)
	}

	return &Pet{
		ID:           result.ID,
		Name:         result.Name,
		Gender:       Gender(result.Gender),
		Type:         PetType(result.Type),
		Images:       ConvertPGImagesToImages(result.Images),
		Description:  result.Description,
		RegisteredAt: result.RegisteredAt,
		UpdatedAt:    result.UpdatedAt,
	}, nil
}

type pgImage struct {
	Provider ImageProvider
	URL      string
}

func (p pgImage) Value() (driver.Value, error) {
	return fmt.Sprintf("(%s,%s)", p.Provider, p.URL), nil
}

func (p *pgImage) Scan(src any) error {
	s := string(src.([]byte))
	s = s[1 : len(s)-1]
	results := strings.Split(s, ",")
	if l := len(results); l != 2 {
		return fmt.Errorf("invalid scan function: expects 2 values, received %v", l)
	}

	p.Provider = ImageProvider(results[0])
	p.URL = results[1]

	return nil
}

func ConvertPGImagesToImages(pgImages []pgImage) []Image {
	var result []Image
	for _, pgImage := range pgImages {
		result = append(result, Image{
			Provider: pgImage.Provider,
			URL:      pgImage.URL,
		})
	}

	return result
}

func ConvertImagesToPGImages(images []Image) []pgImage {
	var result []pgImage
	for _, image := range images {
		result = append(result, pgImage{
			Provider: image.Provider,
			URL:      image.URL,
		})
	}

	return result
}
