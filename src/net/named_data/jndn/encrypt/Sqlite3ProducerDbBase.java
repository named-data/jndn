/**
 * Copyright (C) 2015-2016 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt src/producer-db https://github.com/named-data/ndn-group-encrypt
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
 * Sqlite3ProducerDbBase is an abstract base class the storage of keys for the
 * producer. It contains one table that maps time slots (to the nearest hour) to
 * the content key created for that time slot. A subclass must implement the
 * methods. For example, see Sqlite3ProducerDb. This base class has protected
 * SQL strings and helpers so the subclasses can work with similar tables using
 * their own SQLite libraries.
 * @note This class is an experimental feature. The API may change.
 */
public abstract class Sqlite3ProducerDbBase extends ProducerDb {
  protected static final String INITIALIZATION1 =
  "CREATE TABLE IF NOT EXISTS                         \n" +
  "  contentkeys(                                     \n" +
  "    rowId            INTEGER PRIMARY KEY,          \n" +
  "    timeslot         INTEGER,                      \n" +
  "    key              BLOB NOT NULL                 \n" +
  "  );                                               \n";
  protected static final String INITIALIZATION2 =
  "CREATE UNIQUE INDEX IF NOT EXISTS                  \n" +
  "   timeslotIndex ON contentkeys(timeslot);         \n";

  protected static final String SELECT_hasContentKey =
    "SELECT key FROM contentkeys where timeslot=?";
  protected static final String SELECT_getContentKey =
    "SELECT key FROM contentkeys where timeslot=?";
  protected static final String INSERT_addContentKey =
    "INSERT INTO contentkeys (timeslot, key) values (?, ?)";
  protected static final String DELETE_deleteContentKey =
    "DELETE FROM contentkeys WHERE timeslot=?";
}
