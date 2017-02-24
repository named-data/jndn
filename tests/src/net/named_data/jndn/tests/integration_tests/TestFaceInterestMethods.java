/**
 * Copyright (C) 2014-2017 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From PyNDN unit-tests by Adeola Bannis.
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

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.named_data.jndn.Data;
import net.named_data.jndn.Face;
import net.named_data.jndn.Interest;
import net.named_data.jndn.Name;
import net.named_data.jndn.NetworkNack;
import net.named_data.jndn.OnData;
import net.named_data.jndn.OnNetworkNack;
import net.named_data.jndn.OnTimeout;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.encoding.WireFormat;
import net.named_data.jndn.util.Common;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import org.junit.Before;

import org.junit.Test;

class CallbackCounter implements OnData, OnTimeout, OnNetworkNack {
  public void
  onData(Interest interest, Data data)
  {
    interest_ = interest;
    data_ = data;
    ++onDataCallCount_;
  }

  public void
  onTimeout(Interest interest)
  {
    interest_ = interest;
    ++onTimeoutCallCount_;
  }

  public void
  onNetworkNack(Interest interest, NetworkNack networkNack)
  {
    networkNack_ = networkNack;
    ++onNetworkNackCallCount_;
  }

  public int onDataCallCount_ = 0;
  public int onTimeoutCallCount_ = 0;
  public int onNetworkNackCallCount_ = 0;
  public Interest interest_;
  public Data data_;
  public NetworkNack networkNack_;
}

public class TestFaceInterestMethods {
  public static double
  getNowMilliseconds() { return Common.getNowMilliseconds(); }

  // Returns a CallbackCounter object so we can test data callback, nack callback
  // and timeout behavior.
  private static CallbackCounter
  runExpressNameTest
    (Face face, String interestName, double timeout, boolean useOnNack)
  {
    Name name = new Name(interestName);
    CallbackCounter counter = new CallbackCounter();
    try {
      if (useOnNack)
        // Debug: Use one of the simpler forms
        face.expressInterest(new Interest(name), counter, counter, counter,
          WireFormat.getDefaultWireFormat());
      else
        face.expressInterest(name, counter, counter);
    } catch (IOException ex) {
      Logger.getLogger(TestFaceInterestMethods.class.getName()).log(Level.SEVERE, null, ex);
      return null;
    }

    double startTime = getNowMilliseconds();
    while (getNowMilliseconds() - startTime < timeout &&
           counter.onDataCallCount_ == 0 && counter.onTimeoutCallCount_ == 0 &&
           counter.onNetworkNackCallCount_ == 0) {
      try {
        try {
          face.processEvents();
        } catch (IOException ex) {
          Logger.getLogger(TestFaceInterestMethods.class.getName()).log(Level.SEVERE, null, ex);
          break;
        } catch (EncodingException ex) {
          Logger.getLogger(TestFaceInterestMethods.class.getName()).log(Level.SEVERE, null, ex);
          break;
        }

        // We need to sleep for a few milliseconds so we don't use 100% of the CPU.
        Thread.sleep(10);
      } catch (InterruptedException ex) {
        Logger.getLogger(TestFaceInterestMethods.class.getName()).log(Level.SEVERE, null, ex);
        break;
      }
    }

    return counter;
  }

  private static CallbackCounter
  runExpressNameTest(Face face, String interestName)
  {
    return runExpressNameTest(face, interestName, 10000, false);
  }

  Face face;

  @Before
  public void
  setUp()
  {
    face = new Face("localhost");
  }

  @Test
  public void
  testAnyInterest()
  {
    String uri = "/";
    CallbackCounter counter = runExpressNameTest(face, uri);
    assertTrue("Timeout on expressed interest", counter.onTimeoutCallCount_ == 0);

    // check that the callback was correct
    assertEquals("Expected 1 onData callback, got " + counter.onDataCallCount_,
                 1, counter.onDataCallCount_);

    // just check that the interest was returned correctly.
    Interest callbackInterest = counter.interest_;
    assertTrue("Interest returned on callback had different name",
               callbackInterest.getName().equals(new Name(uri)));
  }

  /*
  TODO: Replace this with a test that connects to a Face on localhost
  def test_specific_interest(self):
    uri = "/ndn/edu/ucla/remap/ndn-js-test/howdy.txt/%FD%052%A1%DF%5E%A4"
    (dataCallback, timeoutCallback) = self.run_express_name_test(uri)
    self.assertTrue(timeoutCallback.call_count == 0, 'Unexpected timeout on expressed interest')

    // check that the callback was correct
    self.assertEqual(dataCallback.call_count, 1, 'Expected 1 onData callback, got '+str(dataCallback.call_count))

    onDataArgs = dataCallback.call_args[0] # the args are returned as ([ordered arguments], [keyword arguments])

    // just check that the interest was returned correctly?
    callbackInterest = onDataArgs[0]
    self.assertTrue(callbackInterest.getName().equals(Name(uri)), 'Interest returned on callback had different name')
  */

  @Test
  public void
  testTimeout()
  {
    String uri = "/test123/timeout";
    CallbackCounter counter = runExpressNameTest(face, uri);

    // we're expecting a timeout callback, and only 1
    assertEquals("Data callback called for invalid interest",
                 0, counter.onDataCallCount_);

    assertTrue("Expected 1 timeout call, got " + counter.onTimeoutCallCount_,
               counter.onTimeoutCallCount_ == 1);

    // just check that the interest was returned correctly.
    Interest callbackInterest = counter.interest_;
    assertTrue("Interest returned on callback had different name",
               callbackInterest.getName().equals(new Name(uri)));
  }

  @Test
  public void
  testRemovePending()
  {
    Name name = new Name("/ndn/edu/ucla/remap/");
    CallbackCounter counter = new CallbackCounter();
    long interestID;
    try {
      interestID = face.expressInterest(name, counter, counter);
    } catch (IOException ex) {
      fail("Error in expressInterest: " + ex);
      return;
    }

    face.removePendingInterest(interestID);

    double timeout = 10000;
    double startTime = getNowMilliseconds();
    while (getNowMilliseconds() - startTime < timeout &&
           counter.onDataCallCount_ == 0 && counter.onTimeoutCallCount_ == 0) {
      try {
        face.processEvents();
      } catch (IOException ex) {
        fail("Error in processEvents: " + ex);
        return;
      } catch (EncodingException ex) {
        fail("Error in processEvents: " + ex);
        return;
      }

      try {
        // We need to sleep for a few milliseconds so we don't use 100% of the CPU.
        Thread.sleep(10);
      } catch (InterruptedException ex) {
        fail("Error in sleep: " + ex);
        return;
      }
    }

    assertEquals("Should not have called data callback after interest was removed",
                 0, counter.onDataCallCount_);
    assertTrue("Should not have called timeout callback after interest was removed",
               counter.onTimeoutCallCount_ == 0);
  }

  @Test
  public void
  testMaxNdnPacketSize() throws IOException
  {
    // Construct an interest whose encoding is one byte larger than getMaxNdnPacketSize.
    int targetSize = Face.getMaxNdnPacketSize() + 1;
    // Start with an interest which is almost the right size.
    Interest interest = new Interest();
    interest.getName().append(new byte[targetSize]);
    int initialSize = interest.wireEncode().size();
    // Now replace the component with the desired size which trims off the extra encoding.
    interest.setName
      (new Name().append(new byte[targetSize - (initialSize - targetSize)]));
    int interestSize = interest.wireEncode().size();
    assertEquals("Wrong interest size for MaxNdnPacketSize",
                 targetSize, interestSize);

    CallbackCounter counter = new CallbackCounter();
    boolean gotError = true;
    try {
      face.expressInterest(interest, counter, counter);
      gotError = false;
    } catch (Error ex) {}
    if (!gotError)
      fail("expressInterest didn't throw an exception when the interest size exceeds getMaxNdnPacketSize()");
  }

  @Test
  public void
  testNetworkNack()
  {
    String uri = "/noroute" + System.currentTimeMillis();
    // Use a short timeout since we expect an immediate Nack.
    CallbackCounter counter = runExpressNameTest(face, uri, 1000, true);

    // We're expecting a network Nack callback, and only 1.
    assertEquals("Data callback called for unroutable interest",
                 0, counter.onDataCallCount_);
    assertEquals("Timeout callback called for unroutable interest",
                 0, counter.onTimeoutCallCount_);
    assertEquals("Expected 1 network Nack call",
                 1, counter.onNetworkNackCallCount_);

    assertEquals("Network Nack has unexpected reason",
                 NetworkNack.Reason.NO_ROUTE, counter.networkNack_.getReason());
  }

  // This is to force an import of net.named_data.jndn.util.
  private static Common dummyCommon_ = new Common();
}
