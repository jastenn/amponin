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

func (p *PGStore) UpdateLocalAccountPassword(ctx context.Context, userID string, passwordHash []byte) (*LocalAccount, error) {
	row := p.db.QueryRowContext(ctx,
		`UPDATE local_accounts
			SET password_hash = $2,
			updated_at = now()
		 WHERE user_id = $1
		 RETURNING user_id, password_hash, created_at, updated_at`,
		userID, passwordHash,
	)

	localAccount := &LocalAccount{}
	err := row.Scan(&localAccount.UserID, &localAccount.PasswordHash, &localAccount.CreatedAt, &localAccount.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNoLocalAccount
		}

		return nil, fmt.Errorf("unable to update local_accounts password: %w", err)
	}

	return localAccount, nil
}

func (p *PGStore) GetLocalAccountByEmail(ctx context.Context, email string) (*LocalAccount, *User, error) {
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

func (p *PGStore) GetLocalAccount(ctx context.Context, userID string) (*LocalAccount, error) {
	localAccount := &LocalAccount{}
	err := p.db.QueryRowContext(ctx,
		`SELECT password_hash, created_at, updated_at
		 FROM local_accounts
		 WHERE user_id = $1`,
		userID,
	).Scan(&localAccount.PasswordHash, &localAccount.CreatedAt, &localAccount.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNoLocalAccount
		}
		return nil, fmt.Errorf("unable to query user's local account: %w", err)
	}

	return localAccount, nil
}

func (p *PGStore) GetUserByID(ctx context.Context, userID string) (*User, error) {
	user := &User{}
	err := p.db.QueryRowContext(ctx,
		`SELECT user_id, email, display_name, avatar_url,
			created_at, updated_at
		 FROM users
		 WHERE user_id = $1`,
		userID,
	).Scan(
		&user.ID, &user.Email, &user.DisplayName, &user.AvatarURL,
		&user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNoUser
		}
		return nil, fmt.Errorf("unable to query user by user_id: %w", err)
	}

	return user, nil
}

func (p *PGStore) UpdateUserInfo(ctx context.Context, userID string, data UserInfoUpdate) (*User, error) {
	row := p.db.QueryRowContext(
		ctx,
		`UPDATE users
			SET display_name = COALESCE($2, display_name),
			email = COALESCE($3, email),
			avatar_url = COALESCE($4, avatar_url),
			updated_at = now()
		 WHERE user_id = $1
		 RETURNING 
			user_id, display_name, email, avatar_url,
			created_at, updated_at`,
		userID,
		data.DisplayName, data.Email, data.Avatar,
	)

	user := &User{}
	err := row.Scan(
		&user.ID, &user.DisplayName, &user.Email, &user.AvatarURL,
		&user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNoUser
		}

		return nil, fmt.Errorf("unable to update user: %w", err)
	}

	return user, nil
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
			description, created_at, updated_at,
			ST_X(coordinates::geometry), ST_Y(coordinates::geometry)
		 FROM shelters
		 WHERE shelter_id = $1`,
		shelterID,
	)

	shelter := &Shelter{}
	err := row.Scan(
		&shelter.ID, &shelter.Name, &shelter.AvatarURL, &shelter.Address,
		&shelter.Description, &shelter.CreatedAt, &shelter.UpdatedAt,
		&shelter.Coordinates.Longitude, &shelter.Coordinates.Latitude,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNoShelter
		}
		return nil, fmt.Errorf("unable to query shelter table: %w", err)
	}

	return shelter, nil
}

func (p *PGStore) UpdateShelter(ctx context.Context, shelterID string, data ShelterUpdate) (*Shelter, error) {
	var lat *float64
	var lng *float64
	if data.Coordinates != nil {
		lng = &data.Coordinates.Longitude
		lat = &data.Coordinates.Latitude
	}
	row := p.db.QueryRowContext(ctx,
		`UPDATE shelters
			SET avatar_url = COALESCE($2, avatar_url),
			name = COALESCE($3, name),
			coordinates = COALESCE(ST_MakePoint($4, $5), coordinates),
			address = COALESCE($6, address),
			description = COALESCE($7, description),
			updated_at = now()
		 WHERE shelter_id = $1
		 RETURNING 
			shelter_id, avatar_url, name, address,
			description, created_at, updated_at,
			ST_X(coordinates::geometry), ST_Y(coordinates::geometry)`,
		shelterID, data.Avatar, data.Name, lng, lat,
		data.Address, data.Description,
	)

	shelter := &Shelter{}
	err := row.Scan(
		&shelter.ID, &shelter.AvatarURL, &shelter.Name, &shelter.Address,
		&shelter.Description, &shelter.CreatedAt, &shelter.UpdatedAt,
		&shelter.Coordinates.Longitude, &shelter.Coordinates.Latitude,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNoShelter
		}

		return nil, fmt.Errorf("failed to update shelter: %w", err)
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

func (p *PGStore) GetShelterRoleByEmail(ctx context.Context, shelterID, userEmail string) (ShelterRole, error) {
	row := p.db.QueryRowContext(
		ctx,
		`SELECT role FROM shelter_roles
		 JOIN users USING (user_id)
		 WHERE shelter_id = $1 AND users.email = $2`,
		shelterID, userEmail,
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

func (p *PGStore) GetPetByID(ctx context.Context, id string) (*Pet, error) {
	row := p.db.QueryRowContext(ctx,
		`SELECT 
			pet_id, name, pet_type, gender,
			birth_date, image_urls, is_birth_date_approx, description,
			shelter_id, registered_at, updated_at
		 FROM pets
		 WHERE pet_id = $1`,
		id,
	)

	result := &Pet{}
	err := row.Scan(
		&result.ID, &result.Name, &result.Type, &result.Gender,
		&result.BirthDate, pq.Array(&result.ImageURLs), &result.IsBirthDateApprox, &result.Description,
		&result.ShelterID, &result.RegisteredAt, &result.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNoPet
		}

		return nil, fmt.Errorf("unable to query pets table: %w", err)
	}

	return result, nil
}

func (p *PGStore) FindPetByLocation(ctx context.Context, location Coordinates, filter FindPetByLocationFilter) ([]FindPetByLocationResult, error) {
	if filter.MaxDistance == nil {
		maxDistance := 15_000
		filter.MaxDistance = &maxDistance
	}
	row, err := p.db.QueryContext(ctx,
		`SELECT
			p.pet_id, p.name, p.pet_type, p.gender,
			p.birth_date, p.image_urls, p.is_birth_date_approx, p.description,
			p.shelter_id, p.registered_at, p.updated_at,
			Round(ST_Distance(s.coordinates, ST_SetSRID(ST_MakePoint($1, $2), 4326))),
			s.address
		 FROM pets p
		 JOIN shelters s USING(shelter_id)
		 WHERE
			ST_Distance(s.coordinates, ST_SetSRID(ST_MakePoint($1, $2), 4326)) <= $3 AND
			$4::PET_TYPE IS NULL OR pet_type = $4::PET_TYPE`,
		location.Longitude, location.Latitude, filter.MaxDistance, filter.Type,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to query pet by location: %w", err)
	}
	defer row.Close()

	var results []FindPetByLocationResult
	for row.Next() {
		pet := &Pet{}
		var distance int
		var address string
		err := row.Scan(
			&pet.ID, &pet.Name, &pet.Type, &pet.Gender,
			&pet.BirthDate, pq.Array(&pet.ImageURLs), &pet.IsBirthDateApprox, &pet.Description,
			&pet.ShelterID, &pet.RegisteredAt, &pet.UpdatedAt,
			&distance,
			&address,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to scan pet by location query result: %w", err)
		}

		results = append(results, FindPetByLocationResult{
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

func (p *PGStore) CreateEmailUpdateRequest(ctx context.Context, data NewEmailUpdateRequest) (*EmailUpdateRequest, error) {
	row := p.db.QueryRowContext(ctx,
		`INSERT INTO email_change_request (user_id, current_email, expires_at)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (user_id)
		 DO UPDATE 
			SET code = nanoid(12),
			current_email = $2,
			expires_at = $3,
			created_at = now()
		 RETURNING 
			code, user_id, current_email, expires_at, created_at`,
		data.UserID, data.CurrentEmail, data.ExpiresAt,
	)

	result := &EmailUpdateRequest{}
	err := row.Scan(&result.Code, &result.UserID, &result.CurrentEmail, &result.ExpiresAt, &result.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("unable to insert into email change request table: %w", err)
	}

	return result, nil

}

func (p *PGStore) GetEmailUpdateRequest(ctx context.Context, code string) (*EmailUpdateRequest, error) {
	row := p.db.QueryRowContext(ctx,
		`SELECT code, user_id, current_email, expires_at, created_at
		 FROM email_change_request
		 WHERE code = $1`,
		code,
	)

	result := &EmailUpdateRequest{}
	err := row.Scan(&result.Code, &result.UserID, &result.CurrentEmail, &result.ExpiresAt, &result.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNoEmailUpdateRequest
		}
		return nil, fmt.Errorf("unable to query for email_change_request using user_id: %w", err)
	}

	return result, nil
}

func (p *PGStore) RemoveEmailUpdateRequest(ctx context.Context, code string) (*EmailUpdateRequest, error) {
	row := p.db.QueryRowContext(ctx,
		`DELETE FROM email_change_request
		 WHERE code = $1
		 RETURNING 
			code, user_id, current_email, expires_at, created_at`,
		code,
	)

	result := &EmailUpdateRequest{}
	err := row.Scan(&result.Code, &result.UserID, &result.CurrentEmail, &result.ExpiresAt, &result.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("unable to delete from email_change_request table: %w", err)
	}

	return result, nil
}

func (p *PGStore) FindShelterRoles(ctx context.Context, shelterID string) ([]*FindShelterRolesResult, error) {
	rows, err := p.db.QueryContext(ctx,
		`SELECT
			role.user_id, display_name, email, role,
			role.created_at, role.updated_at
		 FROM shelter_roles role
		 JOIN shelters USING(shelter_id)
		 JOIN users USING(user_id)
		 WHERE role.shelter_id = $1`,
		shelterID,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to shelter shelter_roles by shelter_id: %w", err)
	}
	defer rows.Close()

	var result []*FindShelterRolesResult
	for rows.Next() {
		resultItem := &FindShelterRolesResult{}
		err := rows.Scan(
			&resultItem.UserID, &resultItem.DisplayName, &resultItem.Email, &resultItem.Role,
			&resultItem.CreatedAt, &resultItem.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to scan find shelter result: %w", err)
		}
		result = append(result, resultItem)
	}

	return result, nil
}

func (p *PGStore) CreateShelterRole(ctx context.Context, data NewShelterRole) error {
	tx, err := p.db.Begin()
	if err != nil {
		return fmt.Errorf("unable to begin transaction: %w", err)
	}
	defer tx.Rollback()

	var userID string
	err = tx.QueryRowContext(ctx,
		`SELECT user_id FROM users WHERE email = $1`,
		data.UserEmail,
	).Scan(&userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNoUser
		}

		return fmt.Errorf("unable to query users by email: " + err.Error())
	}

	_, err = tx.ExecContext(ctx,
		`INSERT INTO shelter_roles (shelter_id, user_id, role)
		 VALUES ($1, $2, $3)`,
		data.ShelterID, userID, data.Role,
	)
	if err != nil {
		if strings.Contains(err.Error(), "unique_shelter_role_user") {
			return ErrUserHasRole
		}
		return fmt.Errorf("unable to query insert into shelter_roles: %w", err)
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("unable to commit transaction: %w", err)
	}

	return nil
}

func (p *PGStore) DeleteShelterRole(ctx context.Context, shelterID, email string) error {
	tx, err := p.db.Begin()
	if err != nil {
		return fmt.Errorf("unable to begin transaction: %w", err)
	}
	defer tx.Rollback()

	var userID string
	err = tx.QueryRowContext(
		ctx,
		`SELECT user_id FROM users WHERE email = $1`,
		email,
	).Scan(&userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNoUser
		}

		return fmt.Errorf("unable to query users by email: " + err.Error())
	}

	_, err = tx.ExecContext(ctx,
		`DELETE FROM shelter_roles
		 WHERE shelter_id = $1 AND user_id = $2 `,
		shelterID, userID,
	)
	if err != nil {
		return fmt.Errorf("unable to delete from shelter_roles: %w", err)
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("unable to commit transaction: %w", err)
	}

	return nil
}
