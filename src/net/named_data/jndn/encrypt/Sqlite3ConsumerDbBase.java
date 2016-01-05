/**
 * Copyright (C) 2015-2016 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt src/consumer-db https://github.com/named-data/ndn-group-encrypt
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

package net.named_data.jndn.encrypt;

/**
 * Sqlite3ConsumerDbBase is a base class the storage of decryption keys for the
 * consumer. A subclass must implement the methods. For example, see
 * Sqlite3ConsumerDb. This base class has protected SQL strings and helpers so
 * the subclasses can work with similar tables using their own SQLite libraries.
 * @note This class is an experimental feature. The API may change.
 */
public abstract class Sqlite3ConsumerDbBase extends ConsumerDb {
  protected static final String INITIALIZATION1 =
    "CREATE TABLE IF NOT EXISTS                         \n" +
    "  decryptionkeys(                                  \n" +
    "    key_id              INTEGER PRIMARY KEY,       \n" +
    "    key_name            BLOB NOT NULL,             \n" +
    "    key_buf             BLOB NOT NULL              \n" +
    "  );                                               \n";
  protected static final String INITIALIZATION2 =
    "CREATE UNIQUE INDEX IF NOT EXISTS                  \n" +
    "   KeyNameIndex ON decryptionkeys(key_name);       \n";

  protected static final String SELECT_getKey =
    "SELECT key_buf FROM decryptionkeys WHERE key_name=?";
  protected static final String INSERT_addKey =
    "INSERT INTO decryptionkeys(key_name, key_buf) values (?, ?)";
  protected static final String DELETE_deleteKey =
    "DELETE FROM decryptionkeys WHERE key_name=?";
}
