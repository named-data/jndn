/**
 * Copyright (C) 2015 Regents of the University of California.
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
 * ProducerDbSqlite3 extends ProducerDb to implement storage of keys for the
 * producer using SQLite3. It contains one table that maps time slots (to the
 * nearest hour) to the content key created for that time slot.
 */
public class ProducerDbSqlite3 extends ProducerDb {
  /**
   * Create a ProducerDbSqlite3 to use the given SQLite3 file.
   * @param databaseFilePath The path of the SQLite file.
   * @throws ProducerDb.Error for a database error.
   */
  public ProducerDbSqlite3(String databaseFilePath) throws ProducerDb.Error
  {
    try {
      Class.forName("org.sqlite.JDBC");
    } catch (ClassNotFoundException ex) {
      // We don't expect this to happen.
      Logger.getLogger(ProducerDbSqlite3.class.getName()).log
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
        statement.executeUpdate(INITIALIZATION);
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new ProducerDb.Error("ProducerDbSqlite3: SQLite error: " + exception);
    }
  }

  /**
   * Check if a content key exists for the hour covering timeSlot.
   * @param timeSlot The time slot as milliseconds since Jan 1, 1970 GMT.
   * @return True if there is a content key for timeSlot.
   * @throws ProducerDb.Error for a database error.
   */
  public boolean
  hasContentKey(double timeSlot) throws ProducerDb.Error
  {
    int fixedTimeslot = getFixedTimeSlot(timeSlot);

    try {
      PreparedStatement statement = database_.prepareStatement
        ("SELECT key FROM contentkeys where timeslot=?");
      statement.setInt(1, fixedTimeslot);

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
      throw new ProducerDb.Error("ProducerDbSqlite3.hasContentKey: SQLite error: " + exception);
    }
  }

  /**
   * Get the content key for the hour covering timeSlot.
   * @param timeSlot The time slot as milliseconds since Jan 1, 1970 GMT.
   * @return A Blob with the encoded key.
   * @throws ProducerDb.Error if there is no key covering timeSlot or other
   * database error.
   */
  public Blob
  getContentKey(double timeSlot) throws ProducerDb.Error
  {
    int fixedTimeslot = getFixedTimeSlot(timeSlot);

    try {
      PreparedStatement statement = database_.prepareStatement
        ("SELECT key FROM contentkeys where timeslot=?");
      statement.setInt(1, fixedTimeslot);

      try {
        ResultSet result = statement.executeQuery();

        if (result.next())
          return new Blob(result.getBytes(1));
        else
          throw new ProducerDb.Error
            ("ProducerDbSqlite3.getContentKey: Cannot get the key from the database");
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new ProducerDb.Error
        ("ProducerDbSqlite3.getContentKey: SQLite error: " + exception);
    }
  }

  /**
   * Add key as the content key for the hour covering timeSlot.
   * @param timeSlot The time slot as milliseconds since Jan 1, 1970 GMT.
   * @param key The encoded key.
   * @throws ProducerDb.Error if a key for the same hour already exists in the
   * database, or other database error.
   */
  public void
  addContentKey(double timeSlot, Blob key) throws ProducerDb.Error
  {
    int fixedTimeslot = getFixedTimeSlot(timeSlot);

    try {
      PreparedStatement statement = database_.prepareStatement
        ( "INSERT INTO contentkeys (timeslot, key) values (?, ?)");
      statement.setInt(1, fixedTimeslot);
      statement.setBytes(2, key.getImmutableArray());

      try {
        statement.executeUpdate();
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new ProducerDb.Error
        ("ProducerDbSqlite3.addContentKey: SQLite error: " + exception);
    }
  }

  /**
   * Delete the content key for the hour covering timeSlot. If there is no key
   * for the time slot, do nothing.
   * @param timeSlot The time slot as milliseconds since Jan 1, 1970 GMT.
   * @throws ProducerDb.Error for a database error.
   */
  public void
  deleteContentKey(double timeSlot) throws ProducerDb.Error
  {
    int fixedTimeslot = getFixedTimeSlot(timeSlot);

    try {
      PreparedStatement statement = database_.prepareStatement
        ("DELETE FROM contentkeys WHERE timeslot=?");
      statement.setInt(1, fixedTimeslot);

      try {
        statement.executeUpdate();
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new ProducerDb.Error
        ("ProducerDbSqlite3.deleteContentKey: SQLite error: " + exception);
    }
  }

  /**
   * Get the hour-based time slot.
   * @param timeSlot The time slot as milliseconds since Jan 1, 1970 GMT.
   * @return The hour-based time slot as hours since Jan 1, 1970 GMT.
   */
  private static int
  getFixedTimeSlot(double timeSlot)
  {
    return (int)Math.floor(Math.round(timeSlot) / 3600000.0);
  }
  
  private static final String INITIALIZATION =
  "CREATE TABLE IF NOT EXISTS                         \n" +
  "  contentkeys(                                     \n" +
  "    rowId            INTEGER PRIMARY KEY,          \n" +
  "    timeslot         INTEGER,                      \n" +
  "    key              BLOB NOT NULL                 \n" +
  "  );                                               \n" +
  "CREATE UNIQUE INDEX IF NOT EXISTS                  \n" +
  "   timeslotIndex ON contentkeys(timeslot);         \n";

  Connection database_ = null;
}
