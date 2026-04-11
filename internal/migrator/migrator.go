package migrator

import (
	"context"
	"fmt"

	"github.com/jmoiron/sqlx"
	"github.com/pressly/goose/v3"
)

const (
	gooseTableName  = "goose_db_version"
	dialectPostgres = "postgres"
)

func Up(ctx context.Context, db *sqlx.DB, dir string) error {
	if err := goose.SetDialect(dialectPostgres); err != nil {
		return fmt.Errorf("set goose dialect: %w", err)
	}

	goose.SetTableName(gooseTableName)

	if err := goose.UpContext(ctx, db.DB, dir); err != nil {
		return fmt.Errorf("apply goose migrations: %w", err)
	}

	return nil
}
