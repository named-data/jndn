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

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.named_data.jndn.util.Blob;

/**
 * Sqlite3ProducerDb extends ProducerDb to implement storage of keys for the
 * producer using SQLite3. It contains one table that maps time slots (to the
 * nearest hour) to the content key created for that time slot.
 * @note This class is an experimental feature. The API may change.
 */
public class Sqlite3ProducerDb extends Sqlite3ProducerDbBase {
  /**
   * Create an Sqlite3ProducerDb to use the given SQLite3 file.
   * @param databaseFilePath The path of the SQLite file.
   * @throws ProducerDb.Error for a database error.
   */
  public Sqlite3ProducerDb(String databaseFilePath) throws ProducerDb.Error
  {
    try {
      Class.forName("org.sqlite.JDBC");
    } catch (ClassNotFoundException ex) {
      // We don't expect this to happen.
      Logger.getLogger(Sqlite3ProducerDb.class.getName()).log
        (Level.SEVERE, null, ex);
      return;
    }

    try {
      database_ = DriverManager.getConnection("jdbc:sqlite:" + databaseFilePath);

      Statement statement = database_.createStatement();
      // Use "try/finally instead of "try-with-resources" or "using" which are
      // not supported before Java 7.
      try {
        // Initialize database specific tables.
        statement.executeUpdate(INITIALIZATION1);
        statement.executeUpdate(INITIALIZATION2);
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new ProducerDb.Error("Sqlite3ProducerDb: SQLite error: " + exception);
    }
  }

  /**
   * Check if a content key exists for the hour covering timeSlot.
   * @param timeSlot The time slot as milliseconds since Jan 1, 1970 UTC.
   * @return True if there is a content key for timeSlot.
   * @throws ProducerDb.Error for a database error.
   */
  public boolean
  hasContentKey(double timeSlot) throws ProducerDb.Error
  {
    int fixedTimeSlot = getFixedTimeSlot(timeSlot);

    try {
      PreparedStatement statement = database_.prepareStatement
        (SELECT_hasContentKey);
      statement.setInt(1, fixedTimeSlot);

      try {
        ResultSet result = statement.executeQuery();

        if (result.next())
          return true;
        else
          return false;
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new ProducerDb.Error("Sqlite3ProducerDb.hasContentKey: SQLite error: " + exception);
    }
  }

  /**
   * Get the content key for the hour covering timeSlot.
   * @param timeSlot The time slot as milliseconds since Jan 1, 1970 UTC.
   * @return A Blob with the encoded key.
   * @throws ProducerDb.Error if there is no key covering timeSlot or other
   * database error.
   */
  public Blob
  getContentKey(double timeSlot) throws ProducerDb.Error
  {
    int fixedTimeSlot = getFixedTimeSlot(timeSlot);

    try {
      PreparedStatement statement = database_.prepareStatement
        (SELECT_getContentKey);
      statement.setInt(1, fixedTimeSlot);

      try {
        ResultSet result = statement.executeQuery();

        if (result.next())
          return new Blob(result.getBytes(1), false);
        else
          throw new ProducerDb.Error
            ("Sqlite3ProducerDb.getContentKey: Cannot get the key from the database");
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new ProducerDb.Error
        ("Sqlite3ProducerDb.getContentKey: SQLite error: " + exception);
    }
  }

  /**
   * Add key as the content key for the hour covering timeSlot.
   * @param timeSlot The time slot as milliseconds since Jan 1, 1970 UTC.
   * @param key The encoded key.
   * @throws ProducerDb.Error if a key for the same hour already exists in the
   * database, or other database error.
   */
  public void
  addContentKey(double timeSlot, Blob key) throws ProducerDb.Error
  {
    int fixedTimeSlot = getFixedTimeSlot(timeSlot);

    try {
      PreparedStatement statement = database_.prepareStatement
        (INSERT_addContentKey);
      statement.setInt(1, fixedTimeSlot);
      statement.setBytes(2, key.getImmutableArray());

      try {
        statement.executeUpdate();
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new ProducerDb.Error
        ("Sqlite3ProducerDb.addContentKey: SQLite error: " + exception);
    }
  }

  /**
   * Delete the content key for the hour covering timeSlot. If there is no key
   * for the time slot, do nothing.
   * @param timeSlot The time slot as milliseconds since Jan 1, 1970 UTC.
   * @throws ProducerDb.Error for a database error.
   */
  public void
  deleteContentKey(double timeSlot) throws ProducerDb.Error
  {
    int fixedTimeSlot = getFixedTimeSlot(timeSlot);

    try {
      PreparedStatement statement = database_.prepareStatement
        (DELETE_deleteContentKey);
      statement.setInt(1, fixedTimeSlot);

      try {
        statement.executeUpdate();
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new ProducerDb.Error
        ("Sqlite3ProducerDb.deleteContentKey: SQLite error: " + exception);
    }
  }

  Connection database_ = null;
}
