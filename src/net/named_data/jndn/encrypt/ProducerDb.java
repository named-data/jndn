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

import net.named_data.jndn.util.Blob;

/**
 * ProducerDb is an abstract base class for the storage of keys for the producer. It
 * contains one table that maps time slots (to the nearest hour) to the content
 * key created for that time slot. A subclass must implement the methods. For
 * example, see Sqlite3ProducerDb.
 * @note This class is an experimental feature. The API may change.
 */
public abstract class ProducerDb {
  /**
   * ProducerDb.Error extends Exception for errors using ProducerDb methods.
   * Note that even though this is called "Error" to be consistent with the
   * other libraries, it extends the Java Exception class, not Error.
   */
  public static class Error extends Exception {
    public Error(String message)
    {
      super(message);
    }
  }

  /**
   * Check if a content key exists for the hour covering timeSlot.
   * @param timeSlot The time slot as milliseconds since Jan 1, 1970 UTC.
   * @return True if there is a content key for timeSlot.
   * @throws ProducerDb.Error for a database error.
   */
  public abstract boolean
  hasContentKey(double timeSlot) throws ProducerDb.Error;

  /**
   * Get the content key for the hour covering timeSlot.
   * @param timeSlot The time slot as milliseconds since Jan 1, 1970 UTC.
   * @return A Blob with the encoded key.
   * @throws ProducerDb.Error if there is no key covering timeSlot or other
   * database error.
   */
  public abstract Blob
  getContentKey(double timeSlot) throws ProducerDb.Error;

  /**
   * Add key as the content key for the hour covering timeSlot.
   * @param timeSlot The time slot as milliseconds since Jan 1, 1970 UTC.
   * @param key The encoded key.
   * @throws ProducerDb.Error if a key for the same hour already exists in the
   * database, or other database error.
   */
  public abstract void
  addContentKey(double timeSlot, Blob key) throws ProducerDb.Error;

  /**
   * Delete the content key for the hour covering timeSlot. If there is no key
   * for the time slot, do nothing.
   * @param timeSlot The time slot as milliseconds since Jan 1, 1970 UTC.
   * @throws ProducerDb.Error for a database error.
   */
  public abstract void
  deleteContentKey(double timeSlot) throws ProducerDb.Error;

  /**
   * Get the hour-based time slot.
   * @param timeSlot The time slot as milliseconds since Jan 1, 1970 UTC.
   * @return The hour-based time slot as hours since Jan 1, 1970 UTC.
   */
  protected static int
  getFixedTimeSlot(double timeSlot)
  {
    return (int)Math.floor(Math.round(timeSlot) / 3600000.0);
  }
}
