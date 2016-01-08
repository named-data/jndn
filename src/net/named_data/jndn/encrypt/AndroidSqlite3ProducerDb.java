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

import android.database.sqlite.SQLiteDatabase;
import android.database.Cursor;
import android.content.ContentValues;
import net.named_data.jndn.util.Blob;

/**
 * AndroidSqlite3ProducerDb extends ProducerDb to implement storage of keys for
 * the producer using the android.database.sqlite API. It contains one table
 * that maps time slots (to the nearest hour) to the content key created for
 * that time slot.
 * @note This class is an experimental feature. The API may change.
 */
public class AndroidSqlite3ProducerDb extends Sqlite3ProducerDbBase {
  /**
   * Create an AndroidSqlite3ProducerDb to use the given SQLite3 file.
   * @param databaseFilePath The full path of the SQLite file.
   */
  public AndroidSqlite3ProducerDb(String databaseFilePath)
  {
    database_ = SQLiteDatabase.openDatabase
      (databaseFilePath, null,
       SQLiteDatabase.OPEN_READWRITE | SQLiteDatabase.CREATE_IF_NECESSARY);

    database_.execSQL(INITIALIZATION1);
    database_.execSQL(INITIALIZATION2);
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

    Cursor cursor = database_.rawQuery
      (SELECT_hasContentKey, new String[] { Integer.toString(fixedTimeSlot) });

    try {
      if (cursor.moveToNext())
        return true;
      else
        return false;
    } finally {
      cursor.close();
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

    Cursor cursor = database_.rawQuery
      (SELECT_getContentKey, new String[] { Integer.toString(fixedTimeSlot) });
    try {
      if (cursor.moveToNext())
        return new Blob(cursor.getBlob(0));
      else
        throw new ProducerDb.Error
          ("AndroidSqlite3ProducerDb.getContentKey: Cannot get the key from the database");
    } finally {
      cursor.close();
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

    ContentValues values = new ContentValues();
    values.put("timeslot", fixedTimeSlot);
    values.put("key", key.getImmutableArray());
    if (database_.insert("contentkeys", null, values) < 0)
      throw new ProducerDb.Error
        ("AndroidSqlite3ProducerDb.addContentKey: SQLite error");
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

    database_.execSQL(DELETE_deleteContentKey, new Object[] { fixedTimeSlot });
  }

  private final SQLiteDatabase database_;
}
