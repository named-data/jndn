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

/**
 * Sqlite3GroupManagerDbBase is an abstract base class for the storage of data
 * used by the GroupManager. It contains two tables to store Schedules and
 * Members. A subclass must implement the methods. For example, see
 * Sqlite3GroupManagerDb. This base class has protected SQL strings and helpers
 * so the subclasses can work with similar tables using their own SQLite
 * libraries.
 * @note This class is an experimental feature. The API may change.
 */
public abstract class Sqlite3GroupManagerDbBase extends GroupManagerDb {
  /**
   * Throw an exception if it is an error for addSchedule to add the schedule.
   * @param name The name of the schedule. The name cannot be empty.
   * @throws GroupManagerDb.Error if the name is empty.
   */
  protected static void
  checkAddSchedule(String name) throws GroupManagerDb.Error
  {
    if (name.length() == 0)
      throw new GroupManagerDb.Error
        ("addSchedule: The schedule name cannot be empty");
  }

  /**
   * Throw an exception if it is an error for renameSchedule to rename the
   * schedule.
   * @param newName The new name of the schedule. The name cannot be empty.
   * @throws GroupManagerDb.Error if newName is empty.
   */
  protected static void
  checkRenameSchedule(String newName) throws GroupManagerDb.Error
  {
    if (newName.length() == 0)
      throw new GroupManagerDb.Error
        ("renameSchedule: The schedule newName cannot be empty");
  }

  protected static final String INITIALIZATION1 =
    "CREATE TABLE IF NOT EXISTS                         \n" +
    "  schedules(                                       \n" +
    "    schedule_id         INTEGER PRIMARY KEY,       \n" +
    "    schedule_name       TEXT NOT NULL,             \n" +
    "    schedule            BLOB NOT NULL              \n" +
    "  );                                               \n";
  protected static final String INITIALIZATION2 =
    "CREATE UNIQUE INDEX IF NOT EXISTS                  \n" +
    "   scheduleNameIndex ON schedules(schedule_name);  \n";

  protected static final String INITIALIZATION3 =
    "CREATE TABLE IF NOT EXISTS                         \n" +
    "  members(                                         \n" +
    "    member_id           INTEGER PRIMARY KEY,       \n" +
    "    schedule_id         INTEGER NOT NULL,          \n" +
    "    member_name         BLOB NOT NULL,             \n" +
    "    key_name            BLOB NOT NULL,             \n" +
    "    pubkey              BLOB NOT NULL,             \n" +
    "    FOREIGN KEY(schedule_id)                       \n" +
    "      REFERENCES schedules(schedule_id)            \n" +
    "      ON DELETE CASCADE                            \n" +
    "      ON UPDATE CASCADE                            \n" +
    "  );                                               \n";
  protected static final String INITIALIZATION4 =
    "CREATE UNIQUE INDEX IF NOT EXISTS                  \n" +
    "   memNameIndex ON members(member_name);           \n";

  protected static final String PRAGMA_foreign_keys =
    "PRAGMA foreign_keys = ON";

  protected static final String SELECT_hasSchedule =
    "SELECT schedule_id FROM schedules where schedule_name=?";
  protected static final String SELECT_listAllScheduleNames =
    "SELECT schedule_name FROM schedules";
  protected static final String SELECT_getSchedule =
    "SELECT schedule FROM schedules WHERE schedule_name=?";
  protected static final String SELECT_getScheduleMembers =
    "SELECT key_name, pubkey " +
    "FROM members JOIN schedules ON members.schedule_id=schedules.schedule_id " +
    "WHERE schedule_name=?";
  protected static final String INSERT_addSchedule =
    "INSERT INTO schedules (schedule_name, schedule) values (?, ?)";
  protected static final String DELETE_deleteSchedule =
    "DELETE FROM schedules WHERE schedule_name=?";
  protected static final String WHERE_renameSchedule = "schedule_name=?";
  protected static final String UPDATE_renameSchedule =
    "UPDATE schedules SET schedule_name=? WHERE " + WHERE_renameSchedule;
  protected static final String WHERE_updateSchedule = "schedule_name=?";
  protected static final String UPDATE_updateSchedule =
    "UPDATE schedules SET schedule=? WHERE " + WHERE_updateSchedule;
  protected static final String SELECT_getScheduleId =
    "SELECT schedule_id FROM schedules WHERE schedule_name=?";

  protected static final String SELECT_hasMember =
    "SELECT member_id FROM members WHERE member_name=?";
  protected static final String SELECT_listAllMembers =
    "SELECT member_name FROM members";
  protected static final String SELECT_getMemberSchedule =
    "SELECT schedule_name " +
    "FROM schedules JOIN members ON schedules.schedule_id = members.schedule_id " +
    "WHERE member_name=?";
  protected static final String INSERT_addMember =
    "INSERT INTO members(schedule_id, member_name, key_name, pubkey) " +
    "values (?, ?, ?, ?)";
  protected static final String UPDATE_updateMemberSchedule =
    "UPDATE members SET schedule_id=? WHERE member_name=?";
  protected static final String DELETE_deleteMember =
    "DELETE FROM members WHERE member_name=?";
}
