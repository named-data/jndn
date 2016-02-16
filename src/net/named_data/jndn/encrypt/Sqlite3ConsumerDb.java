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

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.named_data.jndn.Name;
import net.named_data.jndn.encoding.TlvWireFormat;
import net.named_data.jndn.util.Blob;

/**
 * Sqlite3ConsumerDb extends ConsumerDb to implement the storage of decryption
 * keys for the consumer using SQLite3.
 * @note This class is an experimental feature. The API may change.
 */
public class Sqlite3ConsumerDb extends Sqlite3ConsumerDbBase {
  /**
   * Create an Sqlite3ConsumerDb to use the given SQLite3 file.
   * @param databaseFilePath The path of the SQLite file.
   * @throws ConsumerDb.Error for a database error.
   */
  public Sqlite3ConsumerDb(String databaseFilePath) throws ConsumerDb.Error
  {
    try {
      Class.forName("org.sqlite.JDBC");
    } catch (ClassNotFoundException ex) {
      // We don't expect this to happen.
      Logger.getLogger(Sqlite3ConsumerDb.class.getName()).log
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
      throw new ConsumerDb.Error("Sqlite3ConsumerDb: SQLite error: " + exception);
    }
  }

  /**
   * Get the key with keyName from the database.
   * @param keyName The key name.
   * @return A Blob with the encoded key, or an isNull Blob if cannot find the
   * key with keyName.
   * @throws ConsumerDb.Error for a database error.
   */
  public Blob
  getKey(Name keyName) throws ConsumerDb.Error
  {
    try {
      PreparedStatement statement = database_.prepareStatement(SELECT_getKey);
      statement.setBytes
        (1, keyName.wireEncode(TlvWireFormat.get()).getImmutableArray());

      Blob key = new Blob();
      try {
        ResultSet result = statement.executeQuery();

        if (result.next())
          key = new Blob(result.getBytes(1), false);
      } finally {
        statement.close();
      }

      return key;
    } catch (SQLException exception) {
      throw new ConsumerDb.Error
        ("Sqlite3ConsumerDb.getKey: SQLite error: " + exception);
    }
  }

  /**
   * Add the key with keyName and keyBlob to the database.
   * @param keyName The key name.
   * @param keyBlob The encoded key.
   * @throws ConsumerDb.Error if a key with the same keyName already exists in
   * the database, or other database error.
   */
  public void
  addKey(Name keyName, Blob keyBlob) throws ConsumerDb.Error
  {
    try {
      PreparedStatement statement = database_.prepareStatement(INSERT_addKey);
      statement.setBytes
        (1, keyName.wireEncode(TlvWireFormat.get()).getImmutableArray());
      statement.setBytes(2, keyBlob.getImmutableArray());

      try {
        statement.executeUpdate();
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new ConsumerDb.Error
        ("Sqlite3ConsumerDb.addKey: SQLite error: " + exception);
    }
  }

  /**
   * Delete the key with keyName from the database. If there is no key with
   * keyName, do nothing.
   * @param keyName The key name.
   * @throws ConsumerDb.Error for a database error.
   */
  public void
  deleteKey(Name keyName) throws ConsumerDb.Error
  {
    try {
      PreparedStatement statement = database_.prepareStatement(DELETE_deleteKey);
      statement.setBytes
        (1, keyName.wireEncode(TlvWireFormat.get()).getImmutableArray());

      try {
        statement.executeUpdate();
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new ConsumerDb.Error
        ("Sqlite3ConsumerDb.deleteKey: SQLite error: " + exception);
    }
  }

  Connection database_ = null;
}
