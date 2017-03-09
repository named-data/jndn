/**
 * Copyright (C) 2015-2017 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt unit tests
 * https://github.com/named-data/ndn-group-encrypt/blob/master/tests/unit-tests/group-manager-db.t.cpp
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

package src.net.named_data.jndn.tests.integration_tests;

import java.io.File;
import java.nio.ByteBuffer;
import java.text.ParseException;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.named_data.jndn.Name;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.encrypt.DecryptKey;
import net.named_data.jndn.encrypt.EncryptKey;
import net.named_data.jndn.encrypt.GroupManagerDb;
import net.named_data.jndn.encrypt.Sqlite3GroupManagerDb;
import net.named_data.jndn.encrypt.RepetitiveInterval;
import net.named_data.jndn.encrypt.Schedule;
import net.named_data.jndn.encrypt.algo.RsaAlgorithm;
import net.named_data.jndn.security.RsaKeyParams;
import net.named_data.jndn.util.Blob;
import static net.named_data.jndn.encrypt.Schedule.fromIsoString;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.fail;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class TestGroupManagerDb {
  // Convert the int array to a ByteBuffer.
  public static ByteBuffer
  toBuffer(int[] array)
  {
    ByteBuffer result = ByteBuffer.allocate(array.length);
    for (int i = 0; i < array.length; ++i)
      result.put((byte)(array[i] & 0xff));

    result.flip();
    return result;
  }

  private static final ByteBuffer SCHEDULE = toBuffer(new int[] {
  0x8f, 0xc4,// Schedule
  0x8d, 0x90,// WhiteIntervalList
  0x8c, 0x2e, // RepetitiveInterval
    0x86, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x35, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x87, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x35, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x88, 0x01,
      0x04,
    0x89, 0x01,
      0x07,
    0x8a, 0x01,
      0x00,
    0x8b, 0x01,
      0x00,
  0x8c, 0x2e, // RepetitiveInterval
    0x86, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x35, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x87, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x38, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x88, 0x01,
      0x05,
    0x89, 0x01,
      0x0a,
    0x8a, 0x01,
      0x02,
    0x8b, 0x01,
      0x01,
  0x8c, 0x2e, // RepetitiveInterval
    0x86, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x35, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x87, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x38, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x88, 0x01,
      0x06,
    0x89, 0x01,
      0x08,
    0x8a, 0x01,
      0x01,
    0x8b, 0x01,
      0x01,
  0x8e, 0x30, // BlackIntervalList
  0x8c, 0x2e, // RepetitiveInterval
     0x86, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x37, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x87, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x37, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x88, 0x01,
      0x07,
    0x89, 0x01,
      0x08,
    0x8a, 0x01,
      0x00,
    0x8b, 0x01,
      0x00
  });

  @Before
  public void
  setUp() throws GroupManagerDb.Error
  {
    // Don't show INFO log messages.
    Logger.getLogger("").setLevel(Level.WARNING);

    File policyConfigDirectory = IntegrationTestsCommon.getPolicyConfigDirectory();

    databaseFilePath = new File(policyConfigDirectory, "test.db");
    databaseFilePath.delete();

    database = new Sqlite3GroupManagerDb(databaseFilePath.getAbsolutePath());
  }

  @After
  public void
  tearDown()
  {
    databaseFilePath.delete();
  }

  @Test
  public void
  testDatabaseFunctions() throws ParseException, GroupManagerDb.Error, EncodingException
  {
    Blob scheduleBlob = new Blob(SCHEDULE, false);

    // Create a schedule.
    Schedule schedule = new Schedule();
    try {
      schedule.wireDecode(scheduleBlob);
    } catch (EncodingException ex) {
      // We don't expect this to happen.
      fail("Error decoding Schedule: " + ex.getMessage());
    }

    // Create a member.
    RsaKeyParams params = new RsaKeyParams();
    DecryptKey decryptKey;
    EncryptKey encryptKey;
    try {
      decryptKey = RsaAlgorithm.generateKey(params);
      encryptKey = RsaAlgorithm.deriveEncryptKey(decryptKey.getKeyBits());
    } catch (Exception ex) {
      // Don't expect this to happen.
      fail("Error creating test keys: " + ex.getMessage());
      return;
    }
    Blob keyBlob = encryptKey.getKeyBits();

    Name name1 = new Name("/ndn/BoyA/ksk-123");
    Name name2 = new Name("/ndn/BoyB/ksk-1233");
    Name name3 = new Name("/ndn/GirlC/ksk-123");
    Name name4 = new Name("/ndn/GirlD/ksk-123");
    Name name5 = new Name("/ndn/Hello/ksk-123");

    // Add schedules into the database.
    try {
      database.addSchedule("work-time", schedule);
      database.addSchedule("rest-time", schedule);
      database.addSchedule("play-time", schedule);
      database.addSchedule("boelter-time", schedule);
    } catch (Throwable ex) {
      fail("Unexpected error adding a schedule: " + ex.getMessage());
    }

    // Throw an exception when adding a schedule with an existing name.
    boolean gotError = true;
    try {
      database.addSchedule("boelter-time", schedule);
      gotError = false;
    } catch (GroupManagerDb.Error ex) {}
    if (!gotError)
      fail("Expected an error adding a duplicate schedule");

    // Add members into the database.
    try {
      database.addMember("work-time", name1, keyBlob);
      database.addMember("rest-time", name2, keyBlob);
      database.addMember("play-time", name3, keyBlob);
      database.addMember("play-time", name4, keyBlob);
    } catch (Throwable ex) {
      fail("Unexpected error adding a member: " + ex.getMessage());
    }

    // Throw an exception when adding a member with a non-existing schedule name.
    gotError = true;
    try {
      database.addMember("false-time", name5, keyBlob);
      gotError = false;
    } catch (GroupManagerDb.Error ex) {}
    if (!gotError)
      fail("Expected an error adding a member with non-existing schedule");

    try {
      database.addMember("boelter-time", name5, keyBlob);
    } catch (Throwable ex) {
      fail("Unexpected error adding a member: " + ex.getMessage());
    }

    // Throw an exception when adding a member having an existing identity.
    gotError = true;
    try {
      database.addMember("work-time", name5, keyBlob);
      gotError = false;
    } catch (GroupManagerDb.Error ex) {}
    if (!gotError)
      fail("Expected an error adding a member with an existing identity");

    // Test has functions.
    assertEquals(true, database.hasSchedule("work-time"));
    assertEquals(true, database.hasSchedule("rest-time"));
    assertEquals(true, database.hasSchedule("play-time"));
    assertEquals(false, database.hasSchedule("sleep-time"));
    assertEquals(false, database.hasSchedule(""));

    assertEquals(true, database.hasMember(new Name("/ndn/BoyA")));
    assertEquals(true, database.hasMember(new Name("/ndn/BoyB")));
    assertEquals(false, database.hasMember(new Name("/ndn/BoyC")));

    // Get a schedule.
    Schedule scheduleResult = database.getSchedule("work-time");
    assertTrue(scheduleResult.wireEncode().equals(scheduleBlob));

    scheduleResult = database.getSchedule("play-time");
    assertTrue(scheduleResult.wireEncode().equals(scheduleBlob));

    // Throw an exception when when there is no such schedule in the database.
    gotError = true;
    try {
      database.getSchedule("work-time-11");
      gotError = false;
    } catch (GroupManagerDb.Error ex) {}
    if (!gotError)
      fail("Expected an error getting a non-existing schedule");

    // List all schedule names.
    List names = database.listAllScheduleNames();
    assertTrue(names.contains("work-time"));
    assertTrue(names.contains("play-time"));
    assertTrue(names.contains("rest-time"));
    assertTrue(!names.contains("sleep-time"));

    // List members of a schedule.
    Map memberMap = database.getScheduleMembers("play-time");
    assertTrue(memberMap.size() != 0);

    // When there's no such schedule, the return map's size should be 0.
    assertEquals(0, database.getScheduleMembers("sleep-time").size());

    // List all members.
    List members = database.listAllMembers();
    assertTrue(members.contains(new Name("/ndn/GirlC")));
    assertTrue(members.contains(new Name("/ndn/GirlD")));
    assertTrue(members.contains(new Name("/ndn/BoyA")));
    assertTrue(members.contains(new Name("/ndn/BoyB")));

    // Rename a schedule.
    assertEquals(true, database.hasSchedule("boelter-time"));
    database.renameSchedule("boelter-time", "rieber-time");
    assertEquals(false, database.hasSchedule("boelter-time"));
    assertEquals(true, database.hasSchedule("rieber-time"));
    assertEquals("rieber-time", database.getMemberSchedule(new Name("/ndn/Hello")));

    // Update a schedule.
    Schedule newSchedule = new Schedule();
    try {
      newSchedule.wireDecode(scheduleBlob);
    } catch (EncodingException ex) {
      // We don't expect this to happen.
      fail("Error decoding Schedule: " + ex.getMessage());
    }
    RepetitiveInterval repetitiveInterval = new RepetitiveInterval
      (fromIsoString("20150825T000000"), fromIsoString("20150921T000000"), 2, 10,
       5, RepetitiveInterval.RepeatUnit.DAY);
    newSchedule.addWhiteInterval(repetitiveInterval);
    database.updateSchedule("rieber-time", newSchedule);
    scheduleResult = database.getSchedule("rieber-time");
    assertTrue(!scheduleResult.wireEncode().equals(scheduleBlob));
    assertTrue(scheduleResult.wireEncode().equals(newSchedule.wireEncode()));

    // Add a new schedule when updating a non-existing schedule.
    assertEquals(false, database.hasSchedule("ralphs-time"));
    database.updateSchedule("ralphs-time", newSchedule);
    assertEquals(true, database.hasSchedule("ralphs-time"));

    // Update the schedule of a member.
    database.updateMemberSchedule(new Name("/ndn/Hello"), "play-time");
    assertEquals("play-time", database.getMemberSchedule(new Name("/ndn/Hello")));

    // Delete a member.
    assertEquals(true, database.hasMember(new Name("/ndn/Hello")));
    database.deleteMember(new Name("/ndn/Hello"));
    assertEquals(false, database.hasMember(new Name("/ndn/Hello")));

    // Delete a non-existing member.
    try {
      database.deleteMember(new Name("/ndn/notExisting"));
    } catch (Throwable ex) {
      fail("Unexpected error deleting a non-existing member: " + ex.getMessage());
    }

    // Delete a schedule. All the members using this schedule should be deleted.
    database.deleteSchedule("play-time");
    assertEquals(false, database.hasSchedule("play-time"));
    assertEquals(false, database.hasMember(new Name("/ndn/GirlC")));
    assertEquals(false, database.hasMember(new Name("/ndn/GirlD")));

    // Delete a non-existing schedule.
    try {
      database.deleteSchedule("not-existing-time");
    } catch (Throwable ex) {
      fail("Unexpected error deleting a non-existing schedule: " + ex.getMessage());
    }
  }
  
  private File databaseFilePath;
  private GroupManagerDb database;
}
