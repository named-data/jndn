/**
 * Copyright (C) 2015 Regents of the University of California.
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

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.named_data.jndn.Name;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.encoding.TlvWireFormat;
import net.named_data.jndn.util.Blob;

/**
 * GroupManagerDbSqlite3 extends GroupManagerDb to implement the storage of
 * data used by the GroupManager using SQLite3.
 */
public class GroupManagerDbSqlite3 extends GroupManagerDb {

  /**
   * Create a GroupManagerDbSqlite3 to use the given SQLite3 file.
   * @param databaseFilePath The path of the SQLite file.
   * @throws GroupManagerDb.Error for a database error.
   */
  public GroupManagerDbSqlite3(String databaseFilePath) throws GroupManagerDb.Error
  {
    try {
      Class.forName("org.sqlite.JDBC");
    } catch (ClassNotFoundException ex) {
      // We don't expect this to happen.
      Logger.getLogger(GroupManagerDbSqlite3.class.getName()).log
        (Level.SEVERE, null, ex);
      return;
    }

    try {
      database_ = DriverManager.getConnection("jdbc:sqlite:" + databaseFilePath);

      Statement statement = database_.createStatement();
      // Use "try/finally instead of "try-with-resources" or "using" which are
      // not supported before Java 7.
      try {
        // Enable foreign keys.
        statement.executeUpdate("PRAGMA foreign_keys = ON");

        // Initialize database specific tables.
        statement.executeUpdate(INITIALIZATION);
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new GroupManagerDb.Error
        ("GroupManagerDbSqlite3: SQLite error: " + exception);
    }
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
    try {
      PreparedStatement statement = database_.prepareStatement
        ("SELECT schedule_id FROM schedules where schedule_name=?");
      statement.setString(1, name);

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
      throw new GroupManagerDb.Error("GroupManagerDbSqlite3.hasSchedule: SQLite error: " + exception);
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

    try {
      PreparedStatement statement = database_.prepareStatement
        ("SELECT schedule_name FROM schedules");

      try {
        ResultSet result = statement.executeQuery();

        while (result.next())
          list.add(result.getString(1));
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new GroupManagerDb.Error("GroupManagerDbSqlite3.listAllScheduleNames: SQLite error: " + exception);
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
    try {
      PreparedStatement statement = database_.prepareStatement
        ("SELECT schedule FROM schedules WHERE schedule_name=?");
      statement.setString(1, name);

      Schedule schedule = new Schedule();
      try {
        ResultSet result = statement.executeQuery();

        if (result.next()) {
          try {
            schedule.wireDecode(new Blob(result.getBytes(1)));
          } catch (EncodingException ex) {
            // We don't expect this to happen.
            throw new GroupManagerDb.Error
              ("GroupManagerDbSqlite3.getSchedule: Error decoding schedule: " + ex);
          }
        }
        else
          throw new GroupManagerDb.Error
            ("GroupManagerDbSqlite3.getSchedule: Cannot get the result from database");
      } finally {
        statement.close();
      }

      return schedule;
    } catch (SQLException exception) {
      throw new GroupManagerDb.Error
        ("GroupManagerDbSqlite3.getSchedule: SQLite error: " + exception);
    }
  }

  /**
   * For each member using the given schedule, get the name and public key DER
   * of the member's key.
   * @param name The name of the schedule.
   * @return a new Map where the map's key is the Name of the public key and the
   * value is the Blob of the public key DER. (Use Map without generics so it 
   * works with older Java compilers.) Note that the member's identity name is
   * keyName.getPrefix(-1).
   * @throws GroupManagerDb.Error for a database error.
   */
  public Map
  getScheduleMembers(String name) throws GroupManagerDb.Error
  {
    Map map = new HashMap();

    try {
      PreparedStatement statement = database_.prepareStatement
        ("SELECT key_name, pubkey " +
         "FROM members JOIN schedules " +
         "ON members.schedule_id=schedules.schedule_id " +
         "WHERE schedule_name=?");
      statement.setString(1, name);

      try {
        ResultSet result = statement.executeQuery();

        while (result.next()) {
          Name keyName = new Name();
          try {
            keyName.wireDecode(new Blob(result.getBytes(1)), TlvWireFormat.get());
          } catch (EncodingException ex) {
            // We don't expect this to happen.
            throw new GroupManagerDb.Error
              ("GroupManagerDbSqlite3.getScheduleMembers: Error decoding name: " + ex);
          }

          map.put(keyName, new Blob(result.getBytes(2)));
        }
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new GroupManagerDb.Error("GroupManagerDbSqlite3.getScheduleMembers: SQLite error: " + exception);
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
    if (name.length() == 0)
      throw new GroupManagerDb.Error
        ("GroupManagerDbSqlite3.addSchedule: The schedule name cannot be empty");

    try {
      PreparedStatement statement = database_.prepareStatement
        ("INSERT INTO schedules (schedule_name, schedule) values (?, ?)");
      statement.setString(1, name);
      statement.setBytes(2, schedule.wireEncode().getImmutableArray());

      try {
        statement.executeUpdate();
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new GroupManagerDb.Error
        ("GroupManagerDbSqlite3.addSchedule: SQLite error: " + exception);
    }
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
    try {
      PreparedStatement statement = database_.prepareStatement
        ("DELETE FROM schedules WHERE schedule_name=?");
      statement.setString(1, name);

      try {
        statement.executeUpdate();
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new GroupManagerDb.Error
        ("GroupManagerDbSqlite3.deleteSchedule: SQLite error: " + exception);
    }
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
    if (newName.length() == 0)
      throw new GroupManagerDb.Error
        ("GroupManagerDbSqlite3.renameSchedule: The schedule newName cannot be empty");

    try {
      PreparedStatement statement = database_.prepareStatement
        ("UPDATE schedules SET schedule_name=? WHERE schedule_name=?");
      statement.setString(1, newName);
      statement.setString(2, oldName);

      try {
        statement.executeUpdate();
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new GroupManagerDb.Error
        ("GroupManagerDbSqlite3.renameSchedule: SQLite error: " + exception);
    }
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

    try {
      PreparedStatement statement = database_.prepareStatement
        ("UPDATE schedules SET schedule=? WHERE schedule_name=?");
      statement.setBytes(1, schedule.wireEncode().getImmutableArray());
      statement.setString(2, name);

      try {
        statement.executeUpdate();
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new GroupManagerDb.Error
        ("GroupManagerDbSqlite3.updateSchedule: SQLite error: " + exception);
    }
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
    try {
      PreparedStatement statement = database_.prepareStatement
        ("SELECT member_id FROM members WHERE member_name=?");
      statement.setBytes
        (1, identity.wireEncode(TlvWireFormat.get()).getImmutableArray());

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
      throw new GroupManagerDb.Error("GroupManagerDbSqlite3.hasMember: SQLite error: " + exception);
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

    try {
      PreparedStatement statement = database_.prepareStatement
        ("SELECT member_name FROM members");

      try {
        ResultSet result = statement.executeQuery();

        while (result.next()) {
          Name identity = new Name();
          try {
            identity.wireDecode(new Blob(result.getBytes(1)), TlvWireFormat.get());
          } catch (EncodingException ex) {
            // We don't expect this to happen.
            throw new GroupManagerDb.Error
              ("GroupManagerDbSqlite3.listAllMembers: Error decoding name: " + ex);
          }

          list.add(identity);
        }
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new GroupManagerDb.Error("GroupManagerDbSqlite3.listAllMembers: SQLite error: " + exception);
    }

    return list;
  }

  /**
   * Get the name of the schedule for the given member's identity name.
   * @param identity The member's identity name.
   * @return The name of the schedule.
   * @throws GroupManagerDb.Error if there's no member with the given identity
   * name in the database.
   */
  public String
  getMemberSchedule(Name identity) throws GroupManagerDb.Error
  {
    try {
      PreparedStatement statement = database_.prepareStatement
        ("SELECT schedule_name " +
         "FROM schedules JOIN members " +
         "ON schedules.schedule_id = members.schedule_id " +
         "WHERE member_name=?");
      statement.setBytes
        (1, identity.wireEncode(TlvWireFormat.get()).getImmutableArray());

      try {
        ResultSet result = statement.executeQuery();

        if (result.next())
          return result.getString(1);
        else
          throw new GroupManagerDb.Error
            ("GroupManagerDbSqlite3.getMemberSchedule: Cannot get the result from database");
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new GroupManagerDb.Error
        ("GroupManagerDbSqlite3.getMemberSchedule: SQLite error: " + exception);
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
      throw new GroupManagerDb.Error("The schedule dose not exist");

    // Need to be changed in the future.
    Name memberName = keyName.getPrefix(-1);
    
    try {
      PreparedStatement statement = database_.prepareStatement
        ("INSERT INTO members(schedule_id, member_name, key_name, pubkey) " +
         "values (?, ?, ?, ?)");
      statement.setInt(1, scheduleId);
      statement.setBytes
        (2, memberName.wireEncode(TlvWireFormat.get()).getImmutableArray());
      statement.setBytes
        (3, keyName.wireEncode(TlvWireFormat.get()).getImmutableArray());
      statement.setBytes(4, key.getImmutableArray());

      try {
        statement.executeUpdate();
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new GroupManagerDb.Error("GroupManagerDbSqlite3.addMember: SQLite error: " + exception);
    }
  }

  /**
   * Change the name of the schedule for the given member's identity name.
   * @param identity The member's identity name.
   * @param scheduleName The new schedule name.
   * @throws GroupManagerDb.Error if there's no member with the given identity
   * name in the database, or there's no schedule named scheduleName.
   */
  public void
  updateMemberSchedule(Name identity, String scheduleName) throws GroupManagerDb.Error
  {
    int scheduleId = getScheduleId(scheduleName);
    if (scheduleId == -1)
      throw new GroupManagerDb.Error
        ("GroupManagerDbSqlite3.updateMemberSchedule: The schedule dose not exist");

    try {
      PreparedStatement statement = database_.prepareStatement
        ("UPDATE members SET schedule_id=? WHERE member_name=?");
      statement.setInt(1, scheduleId);
      statement.setBytes
        (2, identity.wireEncode(TlvWireFormat.get()).getImmutableArray());

      try {
        statement.executeUpdate();
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new GroupManagerDb.Error
        ("GroupManagerDbSqlite3.updateMemberSchedule: SQLite error: " + exception);
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
    try {
      PreparedStatement statement = database_.prepareStatement
        ("DELETE FROM members WHERE member_name=?");
      statement.setBytes
        (1, identity.wireEncode(TlvWireFormat.get()).getImmutableArray());

      try {
        statement.executeUpdate();
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new GroupManagerDb.Error
        ("GroupManagerDbSqlite3.deleteMember: SQLite error: " + exception);
    }
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
    try {
      PreparedStatement statement = database_.prepareStatement
        ("SELECT schedule_id FROM schedules WHERE schedule_name=?");
      statement.setString(1, name);

      try {
        ResultSet result = statement.executeQuery();

        if (result.next())
          return result.getInt(1);
        else
          return -1;
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new GroupManagerDb.Error
        ("GroupManagerDbSqlite3.getScheduleId: SQLite error: " + exception);
    }
  }

  private static final String INITIALIZATION =
    "CREATE TABLE IF NOT EXISTS                         \n" +
    "  schedules(                                       \n" +
    "    schedule_id         INTEGER PRIMARY KEY,       \n" +
    "    schedule_name       TEXT NOT NULL,             \n" +
    "    schedule            BLOB NOT NULL              \n" +
    "  );                                               \n" +
    "CREATE UNIQUE INDEX IF NOT EXISTS                  \n" +
    "   scheduleNameIndex ON schedules(schedule_name);  \n" +
    "                                                   \n" +
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
    "  );                                               \n" +
    "CREATE UNIQUE INDEX IF NOT EXISTS                  \n" +
    "   memNameIndex ON members(member_name);           \n";

  Connection database_ = null;
}
