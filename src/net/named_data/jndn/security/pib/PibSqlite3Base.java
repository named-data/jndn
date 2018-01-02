/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU Lesser General Public License is in the file COPYING.
 */

package net.named_data.jndn.security.pib;

/**
 * PibSqlite3Base is an abstract base class used by PibSqlite3, etc. to
 * provide protected SQL strings and helpers so the subclasses can work with
 * similar tables using their own SQLite libraries.
 */
public abstract class PibSqlite3Base extends PibImpl {
  protected static final String INITIALIZATION1 =
"CREATE TABLE IF NOT EXISTS                         \n" +
"  tpmInfo(                                         \n" +
"    tpm_locator           BLOB                     \n" +
"  );                                               \n";
  protected static final String INITIALIZATION2 =
"CREATE TABLE IF NOT EXISTS                         \n" +
"  identities(                                      \n" +
"    id                    INTEGER PRIMARY KEY,     \n" +
"    identity              BLOB NOT NULL,           \n" +
"    is_default            INTEGER DEFAULT 0        \n" +
"  );                                               \n";
  protected static final String INITIALIZATION3 =
"CREATE UNIQUE INDEX IF NOT EXISTS                  \n" +
"  identityIndex ON identities(identity);           \n";
  protected static final String INITIALIZATION4 =
"CREATE TABLE IF NOT EXISTS                         \n" +
"  keys(                                            \n" +
"    id                    INTEGER PRIMARY KEY,     \n" +
"    identity_id           INTEGER NOT NULL,        \n" +
"    key_name              BLOB NOT NULL,           \n" +
"    key_bits              BLOB NOT NULL,           \n" +
"    is_default            INTEGER DEFAULT 0        \n" +
"  );                                               \n";
  protected static final String INITIALIZATION5 =
"CREATE UNIQUE INDEX IF NOT EXISTS                  \n" +
"  keyIndex ON keys(key_name);                      \n";
  protected static final String INITIALIZATION6 =
"CREATE TABLE IF NOT EXISTS                         \n" +
"  certificates(                                    \n" +
"    id                    INTEGER PRIMARY KEY,     \n" +
"    key_id                INTEGER NOT NULL,        \n" +
"    certificate_name      BLOB NOT NULL,           \n" +
"    certificate_data      BLOB NOT NULL,           \n" +
"    is_default            INTEGER DEFAULT 0        \n" +
"  );                                               \n";
  protected static final String INITIALIZATION7 =
"CREATE UNIQUE INDEX IF NOT EXISTS                  \n" +
"  certIndex ON certificates(certificate_name);     \n";

  protected static final String SELECT_getTpmLocator =
    "SELECT tpm_locator FROM TpmInfo";

  protected static final String SELECT_hasIdentity =
    "SELECT id FROM identities WHERE identity=?";
  protected static final String SELECT_removeIdentity =
    "SELECT keys.id " +
    "FROM keys JOIN identities ON keys.identity_id=identities.id " +
    "WHERE identities.identity=?";
  protected static final String DELETE_removeIdentity_certificates =
    "DELETE FROM certificates WHERE key_id=?";
  protected static final String DELETE_removeIdentity_keys =
    "DELETE FROM keys WHERE id=?";
  protected static final String DELETE_removeIdentity_identity =
    "DELETE FROM identities WHERE identity=?";
  protected static final String DELETE_clearIdentities_certificates =
    "DELETE FROM certificates";
  protected static final String DELETE_clearIdentities_keys =
    "DELETE FROM keys";
  protected static final String DELETE_clearIdentities_identities =
    "DELETE FROM identities";
  protected static final String SELECT_getIdentities =
    "SELECT identity FROM identities";
  protected static final String UPDATE_setDefaultIdentity_reset =
    "UPDATE identities SET is_default=0 WHERE is_default=1";
  protected static final String UPDATE_setDefaultIdentity_set =
    "UPDATE identities SET is_default=1 WHERE identity=?";
  protected static final String SELECT_getDefaultIdentity =
    "SELECT identity FROM identities WHERE is_default=1";

  protected static final String SELECT_hasKey =
    "SELECT id FROM keys WHERE key_name=?";
  protected static final String INSERT_addKey =
    "INSERT INTO keys (identity_id, key_name, key_bits) " +
    "VALUES ((SELECT id FROM identities WHERE identity=?), ?, ?)";
  protected static final String UPDATE_addKey =
    "UPDATE keys SET key_bits=? WHERE key_name=?";
  protected static final String DELETE_removeKey_certificates =
    "DELETE FROM certificates WHERE key_id=(SELECT id FROM keys WHERE key_name=?)";
  protected static final String DELETE_removeKey_keys =
    "DELETE FROM keys WHERE key_name=?";
  protected static final String FROM_WHERE_getKeyBits =
    "FROM keys WHERE key_name=?";
  protected static final String SELECT_getKeysOfIdentity =
    "SELECT key_name " +
    "FROM keys JOIN identities ON keys.identity_id=identities.id " +
    "WHERE identities.identity=?";
  protected static final String UPDATE_setDefaultKeyOfIdentity_reset =
    "UPDATE keys SET is_default=0 WHERE is_default=1";
  protected static final String UPDATE_setDefaultKeyOfIdentity_set =
    "UPDATE keys SET is_default=1 WHERE key_name=?";
  protected static final String FROM_WHERE_getDefaultKeyOfIdentity =
    "FROM keys JOIN identities ON keys.identity_id=identities.id " +
    "WHERE identities.identity=? AND keys.is_default=1";

  protected static final String SELECT_hasCertificate =
    "SELECT id FROM certificates WHERE certificate_name=?";
  protected static final String INSERT_addCertificate =
    "INSERT INTO certificates " +
    "(key_id, certificate_name, certificate_data) " +
    "VALUES ((SELECT id FROM keys WHERE key_name=?), ?, ?)";
  protected static final String UPDATE_addCertificate =
    "UPDATE certificates SET certificate_data=? WHERE certificate_name=?";
  protected static final String DELETE_removeCertificate =
    "DELETE FROM certificates WHERE certificate_name=?";
  protected static final String SELECT_getCertificatesOfKey =
    "SELECT certificate_name " +
    "FROM certificates JOIN keys ON certificates.key_id=keys.id " +
    "WHERE keys.key_name=?";
  protected static final String UPDATE_setDefaultCertificateOfKey_reset =
    "UPDATE certificates SET is_default=0 WHERE is_default=1";
  protected static final String UPDATE_setDefaultCertificateOfKey_set =
    "UPDATE certificates SET is_default=1 WHERE certificate_name=?";
  protected static final String FROM_WHERE_getDefaultCertificateOfKey =
    "FROM certificates JOIN keys ON certificates.key_id=keys.id " +
    "WHERE certificates.is_default=1 AND keys.key_name=?";

  protected static final String SELECT_hasDefaultIdentity =
    "SELECT id FROM identities WHERE is_default=1";
  protected static final String SELECT_hasDefaultKeyOfIdentity =
    "SELECT keys.id " +
    "FROM keys JOIN identities ON keys.identity_id=identities.id " +
    "WHERE identities.identity=? AND keys.is_default=1";
  protected static final String SELECT_hasDefaultCertificateOfKey =
    "SELECT certificates.id " +
    "FROM certificates JOIN keys ON certificates.key_id=keys.id " +
    "WHERE certificates.is_default=1 AND keys.key_name=?";
}
