/**
 * Copyright (C) 2015 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From code in ndn-cxx by Yingdi Yu <yingdi@cs.ucla.edu>
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

package net.named_data.jndn.security.identity;

/**
 * SqliteIdentityStorageBase is an abstract base class for the storage of
 * identity, public keys and certificates using SQLite. This base class has
 * protected SQL strings and helpers so the subclasses can work with similar
 * tables using their own SQLite libraries.
 */
public abstract class Sqlite3IdentityStorageBase extends IdentityStorage {
  protected static final String SELECT_MASTER_ID_TABLE =
    "SELECT name FROM sqlite_master WHERE type='table' And name='Identity'";
  protected static final String SELECT_MASTER_KEY_TABLE =
    "SELECT name FROM sqlite_master WHERE type='table' And name='Key'";
  protected static final String SELECT_MASTER_CERT_TABLE =
    "SELECT name FROM sqlite_master WHERE type='table' And name='Certificate'";

  protected static final String INIT_ID_TABLE =
"CREATE TABLE IF NOT EXISTS                                           \n" +
"  Identity(                                                          \n" +
"      identity_name     BLOB NOT NULL,                               \n" +
"      default_identity  INTEGER DEFAULT 0,                           \n" +
"                                                                     \n" +
"      PRIMARY KEY (identity_name)                                    \n" +
"  );                                                                 \n" +
"                                                                     \n" +
"CREATE INDEX identity_index ON Identity(identity_name);              \n";

  protected static final String INIT_KEY_TABLE =
"CREATE TABLE IF NOT EXISTS                                           \n" +
"  Key(                                                               \n" +
"      identity_name     BLOB NOT NULL,                               \n" +
"      key_identifier    BLOB NOT NULL,                               \n" +
"      key_type          INTEGER,                                     \n" +
"      public_key        BLOB,                                        \n" +
"      default_key       INTEGER DEFAULT 0,                           \n" +
"      active            INTEGER DEFAULT 0,                           \n" +
"                                                                     \n" +
"      PRIMARY KEY (identity_name, key_identifier)                    \n" +
"  );                                                                 \n" +
"                                                                     \n" +
"CREATE INDEX key_index ON Key(identity_name);                        \n";

  protected static final String INIT_CERT_TABLE =
"CREATE TABLE IF NOT EXISTS                                           \n" +
"  Certificate(                                                       \n" +
"      cert_name         BLOB NOT NULL,                               \n" +
"      cert_issuer       BLOB NOT NULL,                               \n" +
"      identity_name     BLOB NOT NULL,                               \n" +
"      key_identifier    BLOB NOT NULL,                               \n" +
"      not_before        TIMESTAMP,                                   \n" +
"      not_after         TIMESTAMP,                                   \n" +
"      certificate_data  BLOB NOT NULL,                               \n" +
"      valid_flag        INTEGER DEFAULT 1,                           \n" +
"      default_cert      INTEGER DEFAULT 0,                           \n" +
"                                                                     \n" +
"      PRIMARY KEY (cert_name)                                        \n" +
"  );                                                                 \n" +
"                                                                     \n" +
"CREATE INDEX cert_index ON Certificate(cert_name);           \n" +
"CREATE INDEX subject ON Certificate(identity_name);          \n";

}
