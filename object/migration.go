package object

import (
	"errors"
	"fmt"
	"github.com/casbin/casdoor/cred"
	"xorm.io/xorm"
	"xorm.io/xorm/migrate"
)

var migration *Migration

type Migration struct {

}

var migrateOption = migrate.Options{
	TableName:    "migration",
	IDColumnName: "id",
}

var migrations = []*migrate.Migration{
	{
		ID: "202111101410",
		Migrate: func(engine *xorm.Engine) error {
			isTableExists, err := engine.IsTableExist(&User{})
			if err != nil {
				return err
			}
			if !isTableExists { // new install, skip
				return nil
			}

			userTable := engine.TableName(&User{})
			userTableBackup := userTable + "_bak"

			// backup table
			_, err = engine.Exec(fmt.Sprintf("CREATE TABLE %s SELECT * FROM %s", userTableBackup, userTable))
			if err != nil {
				return err
			}

			err = engine.Sync2(&User{})
			if err != nil {
				return err
			}

			length, err := engine.Table(userTable).Count()
			length32 := int(length)
			if err != nil {
				return err
			}

			var orgs []*Organization
			err = engine.Find(&orgs)
			if err != nil {
				return err
			}
			orgMap := make(map[string]*Organization)
			for _, org := range orgs {
				// update password algo
				switch org.PasswordType {
				case "salt":
					org.PasswordType = "sha256-salt"
				}
				_, err = engine.Where("owner = ? AND name = ?", org.Owner, org.Name).Cols("password_type").Update(org)
				if err != nil {
					return err
				}

				orgMap[org.Name] = org
			}

			limit := 2000
			var users []map[string]interface{}
			for offset := 0; offset < length32; offset += limit {
				err := engine.Table(userTable).Limit(limit, offset).Find(&users)
				if err != nil {
					return err
				}

				for _, user := range users {
					if _, ok := user["password_salt"]; !ok { // already migrated
						return nil
					}

					userOwnerByte, userOwnerOk := user["owner"].([]uint8)
					userNameByte, userNameOk := user["name"].([]uint8)
					userPasswordByte, userPasswordOk := user["password"].([]uint8)
					userPasswordSaltByte, userPasswordSaltOk := user["password_salt"].([]uint8)

					userOwner := ""
					userName := ""
					userPassword := ""
					userPasswordSalt := ""

					if !userOwnerOk || !userNameOk {
						return errors.New("cannot parse user record")
					} else {
						userOwner = string(userOwnerByte)
						userName = string(userNameByte)
					}
					if userPasswordOk {
						userPassword = string(userPasswordByte)
					}
					if userPasswordSaltOk {
						userPasswordSalt = string(userPasswordSaltByte)
					}

					currentOrg := orgMap[userOwner]
					if currentOrg != nil {
						// migrate password
						if userPassword[0:1] != "$" { // is old format
							password := new(cred.StandardPassword)
							password.Type = currentOrg.PasswordType
							password.OrganizationSalt = currentOrg.PasswordSalt
							password.UserSalt = userPasswordSalt
							password.PasswordHash = userPassword

							userPassword = password.String()

							_, err = engine.Table(userTable).Where("owner = ? AND name = ?", userOwner, userName).Update(map[string]interface{}{
								"password": userPassword,
							})
							if err != nil {
								return err
							}
						}
					}
				}
			}

			_, _ = engine.Exec(fmt.Sprintf("ALTER TABLE %s DROP COLUMN password_salt", engine.TableName(&User{})))
			return nil
		},
		Rollback: func(engine *xorm.Engine) error {
			userTable := engine.TableName(&User{})
			userTableBackup := userTable + "_bak"
			isTableExists, err := engine.IsTableExist(userTableBackup)
			if err != nil {
				return err
			}

			if !isTableExists { // not need rollback
				return nil
			}

			// rollback
			_, err = engine.Exec(fmt.Sprintf("TRUNCATE %s", userTable))
			if err != nil {
				return err
			}

			_, err = engine.Exec(fmt.Sprintf("INSERT INTO %s SELECT * FROM %s", userTable, userTableBackup))
			if err != nil {
				return err
			}

			_, err = engine.Exec(fmt.Sprintf("DROP TABLE %s", userTableBackup))
			if err != nil {
				return err
			}

			return nil
		},
	},
}

func (mig *Migration) migrationDidRun(migration *migrate.Migration) (bool, error) {
	count, err := adapter.Engine.SQL(fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE %s = ?", migrateOption.TableName, migrateOption.IDColumnName), migration.ID).Count()
	return count > 0, err
}

func (mig *Migration) rollback() error {
	for _, migration := range migrations {
		run, err := mig.migrationDidRun(migration)
		if err != nil {
			return err
		} else if !run {
			rollbackErr := migration.Rollback(adapter.Engine)
			if rollbackErr != nil {
				return rollbackErr
			} else {
				return nil
			}
		}
	}
	return nil
}

func (mig *Migration) Migrate() error {
	m := migrate.New(adapter.Engine, &migrateOption, migrations)

	migrateErr := m.Migrate()
	if migrateErr != nil {
		rollbackErr := mig.rollback()
		if rollbackErr != nil {
			return rollbackErr
		}
	}

	return migrateErr
}
