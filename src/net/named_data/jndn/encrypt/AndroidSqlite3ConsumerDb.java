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

import android.database.sqlite.SQLiteDatabase;
import android.database.Cursor;
import android.content.ContentValues;
import android.database.sqlite.SQLiteStatement;
import android.database.sqlite.SQLiteDoneException;
import net.named_data.jndn.Name;
import net.named_data.jndn.encoding.TlvWireFormat;
import net.named_data.jndn.util.Blob;

/**
 * AndroidSqlite3ConsumerDb extends ConsumerDb to implement the storage of
 * decryption keys for the consumer using the android.database.sqlite API.
 * @note This class is an experimental feature. The API may change.
 */
public class AndroidSqlite3ConsumerDb extends Sqlite3ConsumerDbBase {
  /**
   * Create an AndroidSqlite3ConsumerDb to use the given SQLite3 file.
   * @param databaseFilePath The full path of the SQLite file.
   */
  public AndroidSqlite3ConsumerDb(String databaseFilePath)
  {
    database_ = SQLiteDatabase.openDatabase
      (databaseFilePath, null,
       SQLiteDatabase.OPEN_READWRITE | SQLiteDatabase.CREATE_IF_NECESSARY);

    database_.execSQL(INITIALIZATION1);
    database_.execSQL(INITIALIZATION2);
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
    // First use a statement to get the key ID because the statement allows
    // binding a blob for the query.
    long keyId;
    SQLiteStatement statement = database_.compileStatement
      ("SELECT key_id FROM decryptionkeys WHERE key_name=?");
    try {
      statement.bindBlob
        (1, keyName.wireEncode(TlvWireFormat.get()).getImmutableArray());
      try {
        keyId = statement.simpleQueryForLong();
      } catch (SQLiteDoneException ex) {
        // No match.
        return new Blob();
      }
    } finally {
      statement.close();
    }

    // Now use the keyId to get the key.
    Cursor cursor = database_.rawQuery
      ("SELECT key_buf FROM decryptionkeys WHERE key_id=?",
       new String[] { Long.toString(keyId) });
    try {
      if (cursor.moveToNext())
        return new Blob(cursor.getBlob(0));
      else
        // We don't expect this since we got the keyId.
        return new Blob();
    } finally {
      cursor.close();
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
    ContentValues values = new ContentValues();
    values.put
      ("key_name", keyName.wireEncode(TlvWireFormat.get()).getImmutableArray());
    values.put("key_buf", keyBlob.getImmutableArray());
    if (database_.insert("decryptionkeys", null, values) < 0)
      throw new ConsumerDb.Error
        ("AndroidSqlite3ConsumerDb.addKey: SQLite error");
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
    database_.execSQL
      (DELETE_deleteKey,
       new Object[] { keyName.wireEncode(TlvWireFormat.get()).getImmutableArray() });
  }

  private final SQLiteDatabase database_;
}
