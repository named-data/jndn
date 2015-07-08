/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package src.net.named_data.jndn.tests.integration_tests;

import java.io.IOException;
import java.util.logging.Logger;
import net.named_data.jndn.Face;
import net.named_data.jndn.Interest;
import net.named_data.jndn.InterestFilter;
import net.named_data.jndn.Name;
import net.named_data.jndn.OnInterestCallback;
import net.named_data.jndn.OnRegisterFailed;
import net.named_data.jndn.OnRegisterSuccess;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.security.SecurityException;
import org.junit.Assert;
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
      (OnInterestCallback) null, new OnRegisterSuccess() {
        @Override
        public void onRegisterSuccess(Name prefix, long registeredPrefixId) {
          long endTime = System.currentTimeMillis();
          counter.count++;
          logger.info("Registration succeeded in (ms): " + (endTime - startTime));
        }
      }, new OnRegisterFailed() {
        @Override
        public void onRegisterFailed(Name prefix) {
          long endTime = System.currentTimeMillis();
          logger.info("Registration failed in (ms): " + (endTime - startTime));
        }
      });

    // wait until complete or the test times out
    long endTime = startTime + MAX_TEST_DURATION_MS;
    while (counter.count < 1 && System.currentTimeMillis() < endTime) {
      face.processEvents();
      Thread.sleep(PROCESS_EVENTS_INTERVAL_MS);
    }

    Assert.assertEquals(1, counter.count);
  }

  /**
   * Helper class for enclosing a final reference int the callbacks
   */
  private class Counter {

    public int count = 0;
  }
}
