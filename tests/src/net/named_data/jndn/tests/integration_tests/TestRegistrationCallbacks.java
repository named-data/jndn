/**
 * Copyright (C) 2015-2017 Regents of the University of California.
 * @author: Andrew Brown <andrew.brown@intel.com>
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

import java.util.logging.Level;
import java.util.logging.Logger;
import net.named_data.jndn.Face;
import net.named_data.jndn.Name;
import net.named_data.jndn.OnInterestCallback;
import net.named_data.jndn.OnRegisterFailed;
import net.named_data.jndn.OnRegisterSuccess;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.util.Common;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;

/**
 * Test that registration callbacks work as expected; optionally can use a
 * non-localhost NFD (run with -Dnfd.hostname=...) but will use localhost by
 * default.
 *
 * @author Andrew Brown <andrew.brown@intel.com>
 */
public class TestRegistrationCallbacks {

  private static final Logger logger = Logger.getLogger(TestRegistrationCallbacks.class.getName());
  private static final long MAX_TEST_DURATION_MS = 10000;
  private static final long PROCESS_EVENTS_INTERVAL_MS = 50;
  protected Face face;

  @Before
  public void setUp() throws SecurityException {
    // retrieve NFD hostname to use
    String hostname = System.getProperty("nfd.hostname");
    if (hostname == null) {
      hostname = "localhost";
    }

    // build face
    face = IntegrationTestsCommon.buildFaceWithKeyChain(hostname);
  }

  @Test
  public void testRegistrationCallbacks() throws Exception {
    final long startTime = System.currentTimeMillis();
    final Counter counter = new Counter();

    // register the prefix and count when it registers successfully
    face.registerPrefix(new Name("/test/register/callbacks"),
      (OnInterestCallback) null, new OnRegisterFailed() {
        @Override
        public void onRegisterFailed(Name prefix) {
          long endTime = System.currentTimeMillis();
          logger.log(Level.INFO, "Registration failed in (ms): " + (endTime - startTime));
        }
      }, new OnRegisterSuccess() {
        @Override
        public void onRegisterSuccess(Name prefix, long registeredPrefixId) {
          long endTime = System.currentTimeMillis();
          counter.count++;
          logger.log(Level.INFO, "Registration succeeded in (ms): " + (endTime - startTime));
        }
      });

    // wait until complete or the test times out
    long endTime = startTime + MAX_TEST_DURATION_MS;
    while (counter.count < 1 && System.currentTimeMillis() < endTime) {
      face.processEvents();
      Thread.sleep(PROCESS_EVENTS_INTERVAL_MS);
    }

    assertEquals(1, counter.count);
  }

  /**
   * Helper class for enclosing a final reference int the callbacks
   */
  public class Counter {

    public int count = 0;
  }

  // This is to force an import of net.named_data.jndn.util.
  private static Common dummyCommon_ = new Common();
}
