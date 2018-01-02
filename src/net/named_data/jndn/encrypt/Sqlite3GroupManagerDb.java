/**
 * Copyright (C) 2015-2018 Regents of the University of California.
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
 * Sqlite3GroupManagerDb extends GroupManagerDb to implement the storage of
 * data used by the GroupManager using SQLite3.
 * @note This class is an experimental feature. The API may change.
 */
public class Sqlite3GroupManagerDb extends Sqlite3GroupManagerDbBase {
  /**
   * Create an Sqlite3GroupManagerDb to use the given SQLite3 file.
   * @param databaseFilePath The path of the SQLite file.
   * @throws GroupManagerDb.Error for a database error.
   */
  public Sqlite3GroupManagerDb(String databaseFilePath) throws GroupManagerDb.Error
  {
    try {
      Class.forName("org.sqlite.JDBC");
    } catch (ClassNotFoundException ex) {
      // We don't expect this to happen.
      Logger.getLogger(Sqlite3GroupManagerDb.class.getName()).log
        (Level.SEVERE, null, ex);
      return;
    }

    try {
      database_ = DriverManager.getConnection("jdbc:sqlite:" + databaseFilePath);

      Statement statement = database_.createStatement();
      // Use "try/finally instead of "try-with-resources" or "using" which are
      // not supported before Java 7.
      try {
        // Initialize database-specific tables.
        statement.executeUpdate(INITIALIZATION1);
        statement.executeUpdate(INITIALIZATION2);
        statement.executeUpdate(INITIALIZATION3);
        statement.executeUpdate(INITIALIZATION4);
        statement.executeUpdate(INITIALIZATION5);
        statement.executeUpdate(INITIALIZATION6);
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new GroupManagerDb.Error
        ("Sqlite3GroupManagerDb: SQLite error: " + exception);
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
        (SELECT_hasSchedule);
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
      throw new GroupManagerDb.Error("Sqlite3GroupManagerDb.hasSchedule: SQLite error: " + exception);
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
        (SELECT_listAllScheduleNames);

      try {
        ResultSet result = statement.executeQuery();

        while (result.next())
          list.add(result.getString(1));
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new GroupManagerDb.Error("Sqlite3GroupManagerDb.listAllScheduleNames: SQLite error: " + exception);
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
        (SELECT_getSchedule);
      statement.setString(1, name);

      Schedule schedule = new Schedule();
      try {
        ResultSet result = statement.executeQuery();

        if (result.next()) {
          try {
            schedule.wireDecode(new Blob(result.getBytes(1), false));
          } catch (EncodingException ex) {
            // We don't expect this to happen.
            throw new GroupManagerDb.Error
              ("Sqlite3GroupManagerDb.getSchedule: Error decoding schedule: " + ex);
          }
        }
        else
          throw new GroupManagerDb.Error
            ("Sqlite3GroupManagerDb.getSchedule: Cannot get the result from the database");
      } finally {
        statement.close();
      }

      return schedule;
    } catch (SQLException exception) {
      throw new GroupManagerDb.Error
        ("Sqlite3GroupManagerDb.getSchedule: SQLite error: " + exception);
    }
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

    try {
      PreparedStatement statement = database_.prepareStatement
        (SELECT_getScheduleMembers);
      statement.setString(1, name);

      try {
        ResultSet result = statement.executeQuery();

        while (result.next()) {
          Name keyName = new Name();
          try {
            keyName.wireDecode(new Blob(result.getBytes(1), false), TlvWireFormat.get());
          } catch (EncodingException ex) {
            // We don't expect this to happen.
            throw new GroupManagerDb.Error
              ("Sqlite3GroupManagerDb.getScheduleMembers: Error decoding name: " + ex);
          }

          map.put(keyName, new Blob(result.getBytes(2), false));
        }
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new GroupManagerDb.Error("Sqlite3GroupManagerDb.getScheduleMembers: SQLite error: " + exception);
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

    try {
      PreparedStatement statement = database_.prepareStatement
        (INSERT_addSchedule);
      statement.setString(1, name);
      statement.setBytes(2, schedule.wireEncode().getImmutableArray());

      try {
        statement.executeUpdate();
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new GroupManagerDb.Error
        ("Sqlite3GroupManagerDb.addSchedule: SQLite error: " + exception);
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
    int scheduleId = getScheduleId(name);
    if (scheduleId == -1)
      return;

    try {
      // First delete the members. We don't use FOREIGN KEY because some SQLite
      // implementations don's support it.
      PreparedStatement membersStatement = database_.prepareStatement
        (DELETE_deleteScheduleMembers);
      membersStatement.setInt(1, scheduleId);

      try {
        membersStatement.executeUpdate();
      } finally {
        membersStatement.close();
      }

      PreparedStatement statement = database_.prepareStatement
        (DELETE_deleteSchedule);
      statement.setInt(1, scheduleId);

      try {
        statement.executeUpdate();
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new GroupManagerDb.Error
        ("Sqlite3GroupManagerDb.deleteSchedule: SQLite error: " + exception);
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
    checkRenameSchedule(newName);

    try {
      PreparedStatement statement = database_.prepareStatement
        (UPDATE_renameSchedule);
      statement.setString(1, newName);
      statement.setString(2, oldName);

      try {
        statement.executeUpdate();
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new GroupManagerDb.Error
        ("Sqlite3GroupManagerDb.renameSchedule: SQLite error: " + exception);
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
        (UPDATE_updateSchedule);
      statement.setBytes(1, schedule.wireEncode().getImmutableArray());
      statement.setString(2, name);

      try {
        statement.executeUpdate();
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new GroupManagerDb.Error
        ("Sqlite3GroupManagerDb.updateSchedule: SQLite error: " + exception);
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
        (SELECT_hasMember);
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
      throw new GroupManagerDb.Error("Sqlite3GroupManagerDb.hasMember: SQLite error: " + exception);
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
        (SELECT_listAllMembers);

      try {
        ResultSet result = statement.executeQuery();

        while (result.next()) {
          Name identity = new Name();
          try {
            identity.wireDecode(new Blob(result.getBytes(1), false), TlvWireFormat.get());
          } catch (EncodingException ex) {
            // We don't expect this to happen.
            throw new GroupManagerDb.Error
              ("Sqlite3GroupManagerDb.listAllMembers: Error decoding name: " + ex);
          }

          list.add(identity);
        }
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new GroupManagerDb.Error("Sqlite3GroupManagerDb.listAllMembers: SQLite error: " + exception);
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
    try {
      PreparedStatement statement = database_.prepareStatement
        (SELECT_getMemberSchedule);
      statement.setBytes
        (1, identity.wireEncode(TlvWireFormat.get()).getImmutableArray());

      try {
        ResultSet result = statement.executeQuery();

        if (result.next())
          return result.getString(1);
        else
          throw new GroupManagerDb.Error
            ("Sqlite3GroupManagerDb.getMemberSchedule: Cannot get the result from the database");
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new GroupManagerDb.Error
        ("Sqlite3GroupManagerDb.getMemberSchedule: SQLite error: " + exception);
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

    try {
      PreparedStatement statement = database_.prepareStatement
        (INSERT_addMember);
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
      throw new GroupManagerDb.Error("Sqlite3GroupManagerDb.addMember: SQLite error: " + exception);
    }
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

    try {
      PreparedStatement statement = database_.prepareStatement
        (UPDATE_updateMemberSchedule);
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
        ("Sqlite3GroupManagerDb.updateMemberSchedule: SQLite error: " + exception);
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
        (DELETE_deleteMember);
      statement.setBytes
        (1, identity.wireEncode(TlvWireFormat.get()).getImmutableArray());

      try {
        statement.executeUpdate();
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new GroupManagerDb.Error
        ("Sqlite3GroupManagerDb.deleteMember: SQLite error: " + exception);
    }
  }

  /**
   * Check if there is an EKey with the name eKeyName in the database.
   * @param eKeyName The name of the EKey.
   * @return True if the EKey exists.
   * @throws GroupManagerDb.Error for a database error.
   */
  public boolean
  hasEKey(Name eKeyName) throws GroupManagerDb.Error
  {
    try {
      PreparedStatement statement = database_.prepareStatement(SELECT_hasEKey);
      statement.setBytes
        (1, eKeyName.wireEncode(TlvWireFormat.get()).getImmutableArray());

      try {
        ResultSet result = statement.executeQuery();

        return result.next();
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new GroupManagerDb.Error("Sqlite3GroupManagerDb.hasEKey: SQLite error: " + exception);
    }
  }

  /**
   * Add the EKey with name eKeyName to the database.
   * @param eKeyName The name of the EKey. This copies the Name.
   * @param publicKey The encoded public Key of the group key pair.
   * @param privateKey The encoded private Key of the group key pair.
   * @throws GroupManagerDb.Error If a key with name eKeyName already exists in
   * the database, or other database error.
   */
  public void
  addEKey(Name eKeyName, Blob publicKey, Blob privateKey) throws GroupManagerDb.Error
  {
    try {
      PreparedStatement statement = database_.prepareStatement(INSERT_addEKey);
      statement.setBytes
        (1, eKeyName.wireEncode(TlvWireFormat.get()).getImmutableArray());
      statement.setBytes(2, publicKey.getImmutableArray());

      try {
        statement.executeUpdate();
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new GroupManagerDb.Error("Sqlite3GroupManagerDb.addEKey: SQLite error: " + exception);
    }

    privateKeyBase_.put(new Name(eKeyName), privateKey);
  }

  /**
   * Get the group key pair with the name eKeyName from the database.
   * @param eKeyName The name of the EKey.
   * @param publicKey Set publicKey[0] to the encoded public Key.
   * @param privateKey Set publicKey[0] to the encoded private Key.
   * @throws GroupManagerDb.Error If the key with name eKeyName does not exist
   * in the database, or other database error.
   */
  public void
  getEKey(Name eKeyName, Blob[] publicKey, Blob[] privateKey)
    throws GroupManagerDb.Error
  {
    try {
      PreparedStatement statement = database_.prepareStatement(SELECT_getEKey);
      statement.setBytes
        (1, eKeyName.wireEncode(TlvWireFormat.get()).getImmutableArray());

      try {
        ResultSet result = statement.executeQuery();

        if (result.next())
          publicKey[0] = new Blob(result.getBytes(3), false);
        else
          throw new GroupManagerDb.Error
            ("Sqlite3GroupManagerDb.getEKey: Cannot get the result from the database");
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new GroupManagerDb.Error
        ("Sqlite3GroupManagerDb.getEKey: SQLite error: " + exception);
    }

    privateKey[0] = privateKeyBase_.get(eKeyName);
  }

  /**
   * Delete all the EKeys in the database.
   * The database will keep growing because EKeys will keep being added, so this
   * method should be called periodically.
   * @throws GroupManagerDb.Error for a database error.
   */
  public void
  cleanEKeys() throws GroupManagerDb.Error
  {
    try {
      PreparedStatement statement = database_.prepareStatement
        (DELETE_cleanEKeys);
      try {
        statement.executeUpdate();
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new GroupManagerDb.Error
        ("Sqlite3GroupManagerDb.cleanEKeys: SQLite error: " + exception);
    }

    privateKeyBase_.clear();
  }

  /**
   * Delete the EKey with name eKeyName from the database. If no key with the
   * name exists in the database, do nothing.
   * @param eKeyName The name of the EKey.
   * @throws GroupManagerDb.Error for a database error.
   */
  public void
  deleteEKey(Name eKeyName) throws GroupManagerDb.Error
  {
    try {
      PreparedStatement statement = database_.prepareStatement
        (DELETE_deleteEKey);
      statement.setBytes
        (1, eKeyName.wireEncode(TlvWireFormat.get()).getImmutableArray());

      try {
        statement.executeUpdate();
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new GroupManagerDb.Error
        ("Sqlite3GroupManagerDb.deleteEKey: SQLite error: " + exception);
    }

    privateKeyBase_.remove(eKeyName);
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
        (SELECT_getScheduleId);
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
        ("Sqlite3GroupManagerDb.getScheduleId: SQLite error: " + exception);
    }
  }

  private Connection database_ = null;
  private final HashMap<Name, Blob> privateKeyBase_ = new HashMap<Name, Blob>();
}
