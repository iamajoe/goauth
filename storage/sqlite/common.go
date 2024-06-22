package sqlite

import (
	"database/sql"

	"github.com/iamajoe/goauth/storage/sqlite/dbgen"
)

const (
	timestampFormat = "2006-01-02 15:04:05"
)

type dbWithTx interface {
	dbgen.DBTX
	Begin() (*sql.Tx, error)
}
