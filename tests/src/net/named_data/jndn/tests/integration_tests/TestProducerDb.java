/**
 * Copyright (C) 2015-2017 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt unit tests
 * https://github.com/named-data/ndn-group-encrypt/blob/master/tests/unit-tests/producer-db.t.cpp
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
import java.text.ParseException;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.encrypt.ConsumerDb;
import net.named_data.jndn.encrypt.ProducerDb;
import net.named_data.jndn.encrypt.Sqlite3ProducerDb;
import net.named_data.jndn.encrypt.algo.AesAlgorithm;
import net.named_data.jndn.security.AesKeyParams;
import net.named_data.jndn.util.Blob;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static net.named_data.jndn.encrypt.Schedule.fromIsoString;
import static org.junit.Assert.fail;

public class TestProducerDb {
  @Before
  public void
  setUp() throws ConsumerDb.Error
  {
    File policyConfigDirectory = IntegrationTestsCommon.getPolicyConfigDirectory();

    databaseFilePath = new File(policyConfigDirectory, "test.db");
    databaseFilePath.delete();
  }

  @After
  public void
  tearDown()
  {
    databaseFilePath.delete();
  }

  @Test
  public void
  testDatabaseFunctions() throws ProducerDb.Error, ParseException, EncodingException
  {
    // Test construction.
    ProducerDb database = new Sqlite3ProducerDb(databaseFilePath.getAbsolutePath());

    // Create member.
    AesKeyParams params = new AesKeyParams(128);
    Blob keyBlob1 = AesAlgorithm.generateKey(params).getKeyBits();
    Blob keyBlob2 = AesAlgorithm.generateKey(params).getKeyBits();

    double point1 = fromIsoString("20150101T100000");
    double point2 = fromIsoString("20150102T100000");
    double point3 = fromIsoString("20150103T100000");
    double point4 = fromIsoString("20150104T100000");

    // Add keys into the database.
    database.addContentKey(point1, keyBlob1);
    database.addContentKey(point2, keyBlob1);
    database.addContentKey(point3, keyBlob2);

    // Throw an exception when adding a key to an existing time slot.
    try {
      database.addContentKey(point1, keyBlob1);
      fail("addContentKey did not throw an exception");
    }
    catch (ProducerDb.Error ex) {}
    catch (Exception ex) { fail("addContentKey did not throw an exception"); }

    // Check has functions.
    assertEquals(true, database.hasContentKey(point1));
    assertEquals(true, database.hasContentKey(point2));
    assertEquals(true, database.hasContentKey(point3));
    assertEquals(false, database.hasContentKey(point4));

    // Get content keys.
    Blob keyResult = database.getContentKey(point1);
    assertTrue(keyResult.equals(keyBlob1));

    keyResult = database.getContentKey(point3);
    assertTrue(keyResult.equals(keyBlob2));

    // Throw exception when there is no such time slot in the database.
    try {
      database.getContentKey(point4);
      fail("getContentKey did not throw an exception");
    }
    catch (ProducerDb.Error ex) {}
    catch (Exception ex) { fail("getContentKey did not throw an exception"); }

    // Delete content keys.
    assertEquals(true, database.hasContentKey(point1));
    database.deleteContentKey(point1);
    assertEquals(false, database.hasContentKey(point1));

    // Delete at a non-existing time slot.
    try {
      database.deleteContentKey(point4);
    } catch (Exception ex) { fail("deleteContentKey threw an exception"); }
  }
  
  private File databaseFilePath;
}
