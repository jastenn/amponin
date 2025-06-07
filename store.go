package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"strings"

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
			user_id, name, email, avatar,
			created_at, updated_at`,
		data.Name, data.Email,
	)
	err = row.Scan(
		&user.ID, &user.Name, &user.Email, &user.Avatar,
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
		`INSERT INTO users (name, email, avatar)
		 VALUES ($1, $2, $3)
		 RETURNING
			user_id, name, email, avatar,
			created_at, updated_at`,
		data.Name, data.Email, data.Avatar,
	)
	err = row.Scan(
		&user.ID, &user.Name, &user.Email, &user.Avatar,
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

func (p *PGStore) GetLocalAccount(ctx context.Context, email string) (*LocalAccount, *User, error) {
	user := &User{}
	row := p.DB.QueryRowContext(ctx,
		`SELECT
			user_id, name, email, avatar,
			created_at, updated_at
		 FROM users
		 WHERE email = $1`,
		email,
	)
	err := row.Scan(
		&user.ID, &user.Name, &user.Email, &user.Avatar,
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

func (p *PGStore) UpdateLocalAccountPassword(ctx context.Context, accountID string, passwordHash []byte) (*LocalAccount, error) {
	row := p.DB.QueryRowContext(ctx,
		`UPDATE local_accounts SET password_hash = $1, updated_at = now()
		 WHERE local_account_id = $2
		 RETURNING 
			local_account_id, password_hash, updated_at, created_at`,
		passwordHash, accountID,
	)

	account := &LocalAccount{}
	err := row.Scan(&account.ID, &account.PasswordHash, &account.UpdatedAt, &account.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNoAccount
		}

		return nil, fmt.Errorf("failed to update local_account password: %w", err)
	}

	return account, nil
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
			user_id, name, email, avatar,
			created_at, updated_at
		 FROM users
		 WHERE user_id = $1`,
		userID,
	)
	err = row.Scan(
		&user.ID, &user.Name, &user.Email, &user.Avatar,
		&user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to query users table: %w", err)
	}

	return account, user, nil
}

func (p *PGStore) UpdateUser(ctx context.Context, userID string, data UserUpdateData) (*User, error) {
	row := p.DB.QueryRowContext(ctx,
		`UPDATE users SET
			name = COALESCE($1, name),
			email = COALESCE($2, email),
			avatar = COALESCE($3, avatar),
			updated_at = now()
		WHERE user_id = $4
		RETURNING 
			user_id, name, email, avatar,
			created_at, updated_at`,
		data.Name, data.Email, data.Avatar, userID,
	)

	user := &User{}
	err := row.Scan(
		&user.ID, &user.Name, &user.Email, &user.Avatar,
		&user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		if strings.Contains(err.Error(), "unique_user_email") {
			return nil, ErrUserEmailInUse
		}
		return nil, fmt.Errorf("unable to update user info: %w", err)
	}

	return user, nil
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
			shelter_id, name, avatar, address, 
			ST_Y(coordinates), ST_X(coordinates), description, created_at,
			updated_at
		 FROM shelters
		 WHERE shelter_id = $1`,
		shelterID,
	)

	result := &Shelter{}
	err := row.Scan(
		&result.ID, &result.Name, &result.Avatar, &result.Address,
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

func (p *PGStore) GetShelterWithRole(ctx context.Context, shelterID, userID string) (*Shelter, ShelterRole, error) {
	row := p.DB.QueryRowContext(ctx,
		`SELECT
			s.shelter_id, s.name, s.avatar, s.address, 
			ST_Y(s.coordinates), ST_X(s.coordinates), s.description, s.created_at,
			s.updated_at, r.role
		 FROM shelters s
		 LEFT JOIN shelter_roles r ON s.shelter_id = r.shelter_id AND r.user_id = $1
		 WHERE s.shelter_id = $2`,
		userID, shelterID,
	)

	var result struct {
		Shelter
		Role sql.NullString
	}
	err := row.Scan(
		&result.ID, &result.Name, &result.Avatar, &result.Address,
		&result.Coordinates.Latitude, &result.Coordinates.Longtude, &result.Description,
		&result.CreatedAt, &result.UpdatedAt,
		&result.Role,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ShelterNoRole, ErrNoShelter
		}

		return nil, ShelterNoRole, fmt.Errorf("unable to query shelters table: %w", err)
	}

	return &result.Shelter, ShelterRole(result.Role.String), nil
}

func (p *PGStore) UpdateShelter(ctx context.Context, shelterID string, data UpdateShelterData) (*Shelter, error) {
	var longitude *float64
	var latitude *float64
	if data.Coordinates != nil {
		latitude = &data.Coordinates.Latitude
		longitude = &data.Coordinates.Longtude
	}

	row := p.DB.QueryRowContext(ctx,
		`UPDATE shelters SET
			name = COALESCE($1, name),
			avatar = COALESCE($2, avatar),
			address = COALESCE($3, address),
			coordinates = COALESCE(ST_SETSRID(ST_MAKEPOINT($4, $5), 4326), coordinates),
			description = COALESCE($6, description),
			updated_at = now()
		 WHERE shelter_id = $7
		 RETURNING
			shelter_id, name, avatar, address,
			ST_X(coordinates), ST_Y(coordinates), description, created_at,
			updated_at`,
		data.Name, data.Avatar, data.Address,
		longitude, latitude, data.Description,
		shelterID,
	)

	shelter := &Shelter{}
	err := row.Scan(
		&shelter.ID, &shelter.Name, &shelter.Avatar, &shelter.Address,
		&shelter.Coordinates.Longtude, &shelter.Coordinates.Latitude, &shelter.Description, &shelter.CreatedAt,
		&shelter.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNoShelter
		}

		return nil, fmt.Errorf("unable to update shelters table: %w", err)
	}

	return shelter, nil
}

func (p *PGStore) FindManagedShelter(ctx context.Context, userID string) ([]*ManagedShelterResult, error) {
	rows, err := p.DB.QueryContext(ctx,
		`SELECT
			s.shelter_id, name, avatar, address, 
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
			&shelter.ID, &shelter.Name, &shelter.Avatar, &shelter.Address,
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
	row := p.DB.QueryRowContext(
		ctx,
		`INSERT INTO pets (
			shelter_id, name, gender, type,
			birth_date, is_birth_date_approx, images, description
		) VALUES (
			$1, $2, $3, $4,
			$5, $6, $7, $8
		) RETURNING 
			pet_id, name, gender, type,
			birth_date, is_birth_date_approx, images, description,
			registered_at, updated_at`,
		shelterID, data.Name, data.Gender, data.Type,
		data.BirthDate, data.IsBirthDateApprox, pq.Array(data.Images), data.Description,
	)

	pet := &Pet{}
	err := row.Scan(
		&pet.ID, &pet.Name, &pet.Gender, &pet.Type,
		&pet.BirthDate, &pet.IsBirthDateApprox, pq.Array(&pet.Images), &pet.Description,
		&pet.RegisteredAt, &pet.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to insert into pets table: %w", err)
	}

	return pet, nil
}

func (p *PGStore) GetPetByID(ctx context.Context, id string) (*Pet, *Shelter, error) {
	row := p.DB.QueryRowContext(ctx,
		`SELECT 
			pet_id, p.name, gender, type,
			birth_date, is_birth_date_approx, images, p.description,
			registered_at, p.updated_at,
			s.shelter_id, s.name, avatar, address, 
			ST_Y(coordinates), ST_X(coordinates), s.description, s.created_at,
			s.updated_at
		 FROM pets p
		 JOIN shelters s USING(shelter_id)
		 WHERE pet_id = $1`,
		id,
	)

	pet := &Pet{}
	shelter := &Shelter{}
	err := row.Scan(
		&pet.ID, &pet.Name, &pet.Gender, &pet.Type,
		&pet.BirthDate, &pet.IsBirthDateApprox, pq.Array(&pet.Images), &pet.Description,
		&pet.RegisteredAt, &pet.UpdatedAt,
		&shelter.ID, &shelter.Name, &shelter.Avatar, &shelter.Address,
		&shelter.Coordinates.Latitude, &shelter.Coordinates.Longtude, &shelter.Description, &shelter.CreatedAt,
		&shelter.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil, ErrNoPet
		}

		return nil, nil, fmt.Errorf("unable to query pets table: %w", err)
	}

	return pet, shelter, nil
}

func (p *PGStore) FindPet(ctx context.Context, filter FindQueryFilter) ([]*FindQueryResult, error) {
	if filter.MaxDistance == nil {
		maxDistance := 15_000
		filter.MaxDistance = &maxDistance
	}
	if filter.Type != nil && *filter.Type != PetTypeDog && *filter.Type != PetTypeCat {
		filter.Type = nil
	}

	row, err := p.DB.QueryContext(ctx,
		`SELECT
			p.pet_id, p.name, p.gender, p.type,
			p.birth_date, p.is_birth_date_approx, p.images, p.description,
			p.registered_at, p.updated_at,
			s.address, Round(ST_Distance(s.coordinates, ST_SetSRID(ST_MakePoint($1, $2), 4326)))
		 FROM pets p
		 JOIN shelters s USING(shelter_id)
		 WHERE
			ST_Distance(s.coordinates, ST_SetSRID(ST_MakePoint($1, $2), 4326)) <= $3 AND
			$4::PET_TYPE IS NULL OR type = $4::PET_TYPE`,
		filter.Location.Latitude, filter.Location.Longtude, filter.MaxDistance, filter.Type,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to query pet by location: %w", err)
	}
	defer row.Close()

	var results []*FindQueryResult
	for row.Next() {
		pet := &Pet{}
		var distance int
		var address string
		err := row.Scan(
			&pet.ID, &pet.Name, &pet.Gender, &pet.Type,
			&pet.BirthDate, &pet.IsBirthDateApprox, pq.Array(&pet.Images), &pet.Description,
			&pet.RegisteredAt, &pet.UpdatedAt,
			&address, &distance,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to scan pet by location query result: %w", err)
		}

		results = append(results, &FindQueryResult{
			Pet:      pet,
			Distance: distance,
			Address:  address,
		})
	}

	err = row.Err()
	if err != nil {
		return nil, fmt.Errorf("something went wrong while looping through pet by location query result: %w", err)
	}

	return results, nil
}

func (i Image) Value() (driver.Value, error) {
	return fmt.Sprintf("(%s,%s)", i.Provider, i.URL), nil
}

func (i *Image) Scan(src any) error {
	s := string(src.([]byte))
	s = s[1 : len(s)-1]
	results := strings.Split(s, ",")
	if l := len(results); l != 2 {
		return fmt.Errorf("invalid scan function: expects 2 values, received %v", l)
	}

	i.Provider = ImageProvider(results[0])
	i.URL = results[1]

	return nil
}
