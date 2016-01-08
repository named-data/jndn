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

import java.util.List;
import java.util.Map;
import net.named_data.jndn.Name;
import net.named_data.jndn.util.Blob;

/**
 * GroupManagerDb is an abstract base class for the storage of data used by the
 * GroupManager. It contains two tables to store Schedules and Members.
 * This is an abstract base class. A subclass must implement the methods.
 * For example, see Sqlite3GroupManagerDb.
 * @note This class is an experimental feature. The API may change.
 */
public abstract class GroupManagerDb {
  /**
   * GroupManagerDb.Error extends Exception for errors using GroupManagerDb
   * methods. Note that even though this is called "Error" to be consistent with
   * the other libraries, it extends the Java Exception class, not Error.
   */
  public static class Error extends Exception {
    public Error(String message)
    {
      super(message);
    }
  }

  ////////////////////////////////////////////////////// Schedule management.

  /**
   * Check if there is a schedule with the given name.
   * @param name The name of the schedule.
   * @return True if there is a schedule.
   * @throws GroupManagerDb.Error for a database error.
   */
  public abstract boolean
  hasSchedule(String name) throws GroupManagerDb.Error;

  /**
   * List all the names of the schedules.
   * @return A new List of String with the names of all schedules. (Use List
   * without generics so it works with older Java compilers.)
   * @throws GroupManagerDb.Error for a database error.
   */
  public abstract List
  listAllScheduleNames() throws GroupManagerDb.Error;

  /**
   * Get a schedule with the given name.
   * @param name The name of the schedule.
   * @return A new Schedule object.
   * @throws GroupManagerDb.Error if the schedule does not exist or other
   * database error.
   */
  public abstract Schedule
  getSchedule(String name) throws GroupManagerDb.Error;

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
  public abstract Map
  getScheduleMembers(String name) throws GroupManagerDb.Error;

  /**
   * Add a schedule with the given name.
   * @param name The name of the schedule. The name cannot be empty.
   * @param schedule The Schedule to add.
   * @throws GroupManagerDb.Error if a schedule with the same name already exists,
   * if the name is empty, or other database error.
   */
  public abstract void
  addSchedule(String name, Schedule schedule) throws GroupManagerDb.Error;

  /**
   * Delete the schedule with the given name. Also delete members which use this
   * schedule. If there is no schedule with the name, then do nothing.
   * @param name The name of the schedule.
   * @throws GroupManagerDb.Error for a database error.
   */
  public abstract void
  deleteSchedule(String name) throws GroupManagerDb.Error;

  /**
   * Rename a schedule with oldName to newName.
   * @param oldName The name of the schedule to be renamed.
   * @param newName The new name of the schedule. The name cannot be empty.
   * @throws GroupManagerDb.Error If a schedule with newName already exists, if
   * the schedule with oldName does not exist, if newName is empty, or other
   * database error.
   */
  public abstract void
  renameSchedule(String oldName, String newName) throws GroupManagerDb.Error;

  /**
   * Update the schedule with name and replace the old object with the given
   * schedule. Otherwise, if no schedule with name exists, a new schedule
   * with name and the given schedule will be added to database.
   * @param name The name of the schedule. The name cannot be empty.
   * @param schedule The Schedule to update or add.
   * @throws GroupManagerDb.Error if the name is empty, or other database error.
   */
  public abstract void
  updateSchedule(String name, Schedule schedule) throws GroupManagerDb.Error;

  ////////////////////////////////////////////////////// Member management.

  /**
   * Check if there is a member with the given identity name.
   * @param identity The member's identity name.
   * @return True if there is a member.
   * @throws GroupManagerDb.Error for a database error.
   */
  public abstract boolean
  hasMember(Name identity) throws GroupManagerDb.Error;

  /**
   * List all the members.
   * @return A new List of Name with the names of all members. (Use List without
   * generics so it works with older Java compilers.)
   * @throws GroupManagerDb.Error for a database error.
   */
  public abstract List
  listAllMembers() throws GroupManagerDb.Error;

  /**
   * Get the name of the schedule for the given member's identity name.
   * @param identity The member's identity name.
   * @return The name of the schedule.
   * @throws GroupManagerDb.Error if there's no member with the given identity
   * name in the database, or other database error.
   */
  public abstract String
  getMemberSchedule(Name identity) throws GroupManagerDb.Error;

  /**
   * Add a new member with the given key named keyName into a schedule named
   * scheduleName. The member's identity name is keyName.getPrefix(-1).
   * @param scheduleName The schedule name.
   * @param keyName The name of the key.
   * @param key A Blob of the public key DER.
   * @throws GroupManagerDb.Error If there's no schedule named scheduleName, if
   * the member's identity name already exists, or other database error.
   */
  public abstract void
  addMember(String scheduleName, Name keyName, Blob key) throws GroupManagerDb.Error;

  /**
   * Change the name of the schedule for the given member's identity name.
   * @param identity The member's identity name.
   * @param scheduleName The new schedule name.
   * @throws GroupManagerDb.Error if there's no member with the given identity
   * name in the database, or there's no schedule named scheduleName, or other
   * database error.
   */
  public abstract void
  updateMemberSchedule(Name identity, String scheduleName) throws GroupManagerDb.Error;

  /**
   * Delete a member with the given identity name. If there is no member with
   * the identity name, then do nothing.
   * @param identity The member's identity name.
   * @throws GroupManagerDb.Error for a database error.
   */
  public abstract void
  deleteMember(Name identity) throws GroupManagerDb.Error;
}
