/**
 * Copyright (C) 2015-2016 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt src/group-manager-db https://github.com/named-data/ndn-group-encrypt
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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import net.named_data.jndn.Name;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.encoding.TlvWireFormat;
import net.named_data.jndn.util.Blob;

/**
 * AndroidSqlite3GroupManagerDb extends GroupManagerDb to implement the storage
 * of data used by the GroupManager using SQLite3.
 * @note This class is an experimental feature. The API may change.
 */
public class AndroidSqlite3GroupManagerDb extends Sqlite3GroupManagerDbBase {
  /**
   * Create an AndroidSqlite3GroupManagerDb to use the given SQLite3 file.
   * @param databaseFilePath The full path of the SQLite file.
   */
  public AndroidSqlite3GroupManagerDb(String databaseFilePath)
  {
    database_ = SQLiteDatabase.openDatabase
      (databaseFilePath, null,
       SQLiteDatabase.OPEN_READWRITE | SQLiteDatabase.CREATE_IF_NECESSARY);

    // Enable foreign keys.
    database_.execSQL(PRAGMA_foreign_keys);

    // Initialize database-specific tables.
    database_.execSQL(INITIALIZATION1);
    database_.execSQL(INITIALIZATION2);
    database_.execSQL(INITIALIZATION3);
    database_.execSQL(INITIALIZATION4);
  }

  ////////////////////////////////////////////////////// Schedule management.

  /**
   * Check if there is a schedule with the given name.
   * @param name The name of the schedule.
   * @return True if there is a schedule.
   * @throws GroupManagerDb.Error for a database error.
   */
  public boolean
  hasSchedule(String name) throws GroupManagerDb.Error
  {
    Cursor cursor = database_.rawQuery(SELECT_hasSchedule, new String[] { name });

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
   * List all the names of the schedules.
   * @return A new List of String with the names of all schedules. (Use List
   * without generics so it works with older Java compilers.)
   * @throws GroupManagerDb.Error for a database error.
   */
  public List
  listAllScheduleNames() throws GroupManagerDb.Error
  {
    List list = new ArrayList();
    Cursor cursor = database_.rawQuery
      (SELECT_listAllScheduleNames, new String[0]);

    try {
      while (cursor.moveToNext())
        list.add(cursor.getString(0));
    } finally {
      cursor.close();
    }

    return list;
  }

  /**
   * Get a schedule with the given name.
   * @param name The name of the schedule.
   * @return A new Schedule object.
   * @throws GroupManagerDb.Error if the schedule does not exist or other
   * database error.
   */
  public Schedule
  getSchedule(String name) throws GroupManagerDb.Error
  {
    Cursor cursor = database_.rawQuery(SELECT_getSchedule, new String[] { name });

    Schedule schedule = new Schedule();
    try {
      if (cursor.moveToNext()) {
        try {
          schedule.wireDecode(new Blob(cursor.getBlob(0)));
        } catch (EncodingException ex) {
          // We don't expect this to happen.
          throw new GroupManagerDb.Error
            ("AndroidSqlite3GroupManagerDb.getSchedule: Error decoding schedule: " + ex);
        }
      }
      else
        throw new GroupManagerDb.Error
          ("AndroidSqlite3GroupManagerDb.getSchedule: Cannot get the result from the database");
    } finally {
      cursor.close();
    }

    return schedule;
  }

  /**
   * For each member using the given schedule, get the name and public key DER
   * of the member's key.
   * @param name The name of the schedule.
   * @return a new Map where the map's key is the Name of the public key and the
   * value is the Blob of the public key DER. (Use Map without generics so it
   * works with older Java compilers.) Note that the member's identity name is
   * keyName.getPrefix(-1). If the schedule name is not found, the map is empty.
   * @throws GroupManagerDb.Error for a database error.
   */
  public Map
  getScheduleMembers(String name) throws GroupManagerDb.Error
  {
    Map map = new HashMap();

    Cursor cursor = database_.rawQuery
      (SELECT_getScheduleMembers, new String[] { name });

    try {
      while (cursor.moveToNext()) {
        Name keyName = new Name();
        try {
          keyName.wireDecode(new Blob(cursor.getBlob(0)), TlvWireFormat.get());
        } catch (EncodingException ex) {
          // We don't expect this to happen.
          throw new GroupManagerDb.Error
            ("AndroidSqlite3GroupManagerDb.getScheduleMembers: Error decoding name: " + ex);
        }

        map.put(keyName, new Blob(cursor.getBlob(1)));
      }
    } finally {
      cursor.close();
    }

    return map;
  }

  /**
   * Add a schedule with the given name.
   * @param name The name of the schedule. The name cannot be empty.
   * @param schedule The Schedule to add.
   * @throws GroupManagerDb.Error if a schedule with the same name already exists,
   * if the name is empty, or other database error.
   */
  public void
  addSchedule(String name, Schedule schedule) throws GroupManagerDb.Error
  {
    checkAddSchedule(name);

    ContentValues values = new ContentValues();
    values.put("schedule_name", name);
    values.put("schedule", schedule.wireEncode().getImmutableArray());
    if (database_.insert("schedules", null, values) < 0)
      throw new GroupManagerDb.Error
        ("AndroidSqlite3GroupManagerDb.addSchedule: SQLite error");
  }

  /**
   * Delete the schedule with the given name. Also delete members which use this
   * schedule. If there is no schedule with the name, then do nothing.
   * @param name The name of the schedule.
   * @throws GroupManagerDb.Error for a database error.
   */
  public void
  deleteSchedule(String name) throws GroupManagerDb.Error
  {
    database_.execSQL(DELETE_deleteSchedule, new Object[] { name });
  }

  /**
   * Rename a schedule with oldName to newName.
   * @param oldName The name of the schedule to be renamed.
   * @param newName The new name of the schedule. The name cannot be empty.
   * @throws GroupManagerDb.Error If a schedule with newName already exists, if
   * the schedule with oldName does not exist, if newName is empty, or other
   * database error.
   */
  public void
  renameSchedule(String oldName, String newName) throws GroupManagerDb.Error
  {
    checkRenameSchedule(newName);

    ContentValues values = new ContentValues();
    values.put("schedule_name", newName);
    if (database_.update
         ("schedules", values, WHERE_renameSchedule, new String[] { oldName }) <= 0)
      throw new GroupManagerDb.Error
        ("AndroidSqlite3GroupManagerDb.renameSchedule: SQLite error");
  }

  /**
   * Update the schedule with name and replace the old object with the given
   * schedule. Otherwise, if no schedule with name exists, a new schedule
   * with name and the given schedule will be added to database.
   * @param name The name of the schedule. The name cannot be empty.
   * @param schedule The Schedule to update or add.
   * @throws GroupManagerDb.Error if the name is empty, or other database error.
   */
  public void
  updateSchedule(String name, Schedule schedule) throws GroupManagerDb.Error
  {
    if (!hasSchedule(name)) {
      addSchedule(name, schedule);
      return;
    }

    ContentValues values = new ContentValues();
    values.put("schedule", schedule.wireEncode().getImmutableArray());
    if (database_.update
        ("schedules", values, WHERE_updateSchedule, new String[] { name }) <= 0)
      throw new GroupManagerDb.Error
        ("AndroidSqlite3GroupManagerDb.updateSchedule: SQLite error");
  }

  ////////////////////////////////////////////////////// Member management.

  /**
   * Check if there is a member with the given identity name.
   * @param identity The member's identity name.
   * @return True if there is a member.
   * @throws GroupManagerDb.Error for a database error.
   */
  public boolean
  hasMember(Name identity) throws GroupManagerDb.Error
  {
    // Use a statement because it allows binding a blob for the query.
    SQLiteStatement statement = database_.compileStatement(SELECT_hasMember);
    try {
      statement.bindBlob
        (1, identity.wireEncode(TlvWireFormat.get()).getImmutableArray());
      try {
        statement.simpleQueryForLong();
        return true;
      } catch (SQLiteDoneException ex) {
        // No match.
        return false;
      }
    } finally {
      statement.close();
    }
  }

  /**
   * List all the members.
   * @return A new List of Name with the names of all members. (Use List without
   * generics so it works with older Java compilers.)
   * @throws GroupManagerDb.Error for a database error.
   */
  public List
  listAllMembers() throws GroupManagerDb.Error
  {
    List list = new ArrayList();
    Cursor cursor = database_.rawQuery(SELECT_listAllMembers, new String[0]);

    try {
      while (cursor.moveToNext()) {
        Name identity = new Name();
        try {
          identity.wireDecode(new Blob(cursor.getBlob(0)), TlvWireFormat.get());
        } catch (EncodingException ex) {
          // We don't expect this to happen.
          throw new GroupManagerDb.Error
            ("AndroidSqlite3GroupManagerDb.listAllMembers: Error decoding name: " + ex);
        }

        list.add(identity);
      }
    } finally {
      cursor.close();
    }

    return list;
  }

  /**
   * Get the name of the schedule for the given member's identity name.
   * @param identity The member's identity name.
   * @return The name of the schedule.
   * @throws GroupManagerDb.Error if there's no member with the given identity
   * name in the database, or other database error.
   */
  public String
  getMemberSchedule(Name identity) throws GroupManagerDb.Error
  {
    // Use a statement because it allows binding a blob for the query.
    SQLiteStatement statement = database_.compileStatement
      (SELECT_getMemberSchedule);
    try {
      statement.bindBlob
        (1, identity.wireEncode(TlvWireFormat.get()).getImmutableArray());
      try {
        return statement.simpleQueryForString();
      } catch (SQLiteDoneException ex) {
        throw new GroupManagerDb.Error
          ("AndroidSqlite3GroupManagerDb.getMemberSchedule: Cannot get the result from the database");
      }
    } finally {
      statement.close();
    }
  }

  /**
   * Add a new member with the given key named keyName into a schedule named
   * scheduleName. The member's identity name is keyName.getPrefix(-1).
   * @param scheduleName The schedule name.
   * @param keyName The name of the key.
   * @param key A Blob of the public key DER.
   * @throws GroupManagerDb.Error If there's no schedule named scheduleName, if
   * the member's identity name already exists, or other database error.
   */
  public void
  addMember(String scheduleName, Name keyName, Blob key) throws GroupManagerDb.Error
  {
    int scheduleId = getScheduleId(scheduleName);
    if (scheduleId == -1)
      throw new GroupManagerDb.Error("The schedule does not exist");

    // Needs to be changed in the future.
    Name memberName = keyName.getPrefix(-1);

    ContentValues values = new ContentValues();
    values.put("schedule_id", scheduleId);
    values.put
      ("member_name",
       memberName.wireEncode(TlvWireFormat.get()).getImmutableArray());
    values.put
      ("key_name", keyName.wireEncode(TlvWireFormat.get()).getImmutableArray());
    values.put("pubkey", key.getImmutableArray());
    if (database_.insert("members", null, values) < 0)
      throw new GroupManagerDb.Error
        ("AndroidSqlite3GroupManagerDb.addMember: SQLite error");
  }

  /**
   * Change the name of the schedule for the given member's identity name.
   * @param identity The member's identity name.
   * @param scheduleName The new schedule name.
   * @throws GroupManagerDb.Error if there's no member with the given identity
   * name in the database, or there's no schedule named scheduleName, or other
   * database error.
   */
  public void
  updateMemberSchedule(Name identity, String scheduleName) throws GroupManagerDb.Error
  {
    int scheduleId = getScheduleId(scheduleName);
    if (scheduleId == -1)
      throw new GroupManagerDb.Error
        ("Sqlite3GroupManagerDb.updateMemberSchedule: The schedule does not exist");

    // Use a statement because it allows binding a blob for the where clause.
    SQLiteStatement statement = database_.compileStatement
      (UPDATE_updateMemberSchedule);
    try {
      statement.bindLong(1, scheduleId);
      statement.bindBlob
        (2, identity.wireEncode(TlvWireFormat.get()).getImmutableArray());
      if (statement.executeUpdateDelete() <= 0)
        throw new GroupManagerDb.Error
          ("AndroidSqlite3GroupManagerDb.updateMemberSchedule: SQLite error");
    } finally {
      statement.close();
    }
  }

  /**
   * Delete a member with the given identity name. If there is no member with
   * the identity name, then do nothing.
   * @param identity The member's identity name.
   * @throws GroupManagerDb.Error for a database error.
   */
  public void
  deleteMember(Name identity) throws GroupManagerDb.Error
  {
    database_.execSQL
      (DELETE_deleteMember,
       new Object[] { identity.wireEncode(TlvWireFormat.get()).getImmutableArray() });
  }

  /**
   * Get the ID for the schedule.
   * @param name The schedule name.
   * @return The ID, or -1 if the schedule name is not found.
   * @throws GroupManagerDb.Error for a database error.
   */
  private int
  getScheduleId(String name) throws GroupManagerDb.Error
  {
    Cursor cursor = database_.rawQuery(SELECT_getScheduleId, new String[] { name });

    try {
      if (cursor.moveToNext())
        return cursor.getInt(0);
      else
        return -1;
    } finally {
      cursor.close();
    }
  }

  private final SQLiteDatabase database_;
}
