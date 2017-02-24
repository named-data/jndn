/**
 * Copyright (C) 2016-2017 Regents of the University of California.
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
import net.named_data.jndn.InterestFilter;
import net.named_data.jndn.Name;
import net.named_data.jndn.OnData;
import net.named_data.jndn.OnInterestCallback;
import net.named_data.jndn.OnRegisterFailed;
import net.named_data.jndn.OnTimeout;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.security.KeyChain;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.Common;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Before;

import org.junit.Test;

public class TestFaceCallRegisterMethods {
  Face faceIn;
  Face faceOut;
  KeyChain keyChain;
  Name certificateName;

  @Before
  public void
  setUp() throws SecurityException
  {
    Name[] localCertificateName = new Name[1];
    keyChain = IntegrationTestsCommon.buildKeyChain(localCertificateName);
    certificateName = localCertificateName[0];

    faceIn = IntegrationTestsCommon.buildFaceWithKeyChain
      ("localhost", keyChain, certificateName);
    faceOut = IntegrationTestsCommon.buildFaceWithKeyChain
      ("localhost", keyChain, certificateName);
  }

  @Test
  public void
  testRegisterPrefixResponse() throws IOException, SecurityException
  {
    Name prefixName = new Name("/test");

    final int[] interestCallbackCount = new int[] { 0 };
    final int[] failedCallbackCount = new int[] { 0 };
    faceIn.registerPrefix
       (prefixName, new OnInterestCallback() {
        public void onInterest
          (Name prefix, Interest interest, Face face, long interestFilterId,
           InterestFilter filter) {
          ++interestCallbackCount[0];
          Data data = new Data(interest.getName());
          data.setContent(new Blob("SUCCESS"));

          try {
            keyChain.sign(data, certificateName);
          } catch (SecurityException ex) {
            logger.log(Level.SEVERE, null, ex);
          }
          try {
            face.putData(data);
          } catch (IOException ex) {
            logger.log(Level.SEVERE, null, ex);
          }
        }
      }, new OnRegisterFailed() {
        public void onRegisterFailed(Name prefix) { ++failedCallbackCount[0]; }
      });

    // Give the "server" time to register the interest.
    double timeout = 1000;
    double startTime = getNowMilliseconds();
    while (getNowMilliseconds() - startTime < timeout) {
      try {
        faceIn.processEvents();
      } catch (IOException ex) {
        logger.log(Level.SEVERE, null, ex);
        break;
      } catch (EncodingException ex) {
        logger.log(Level.SEVERE, null, ex);
        break;
      }

      try {
        // We need to sleep for a few milliseconds so we don't use 100% of the CPU.
        Thread.sleep(10);
      } catch (InterruptedException ex) {
        logger.log(Level.SEVERE, null, ex);
        break;
      }
    }

    // Now express an interest on this new face, and see if onInterest is called.
    // Add the timestamp so it is unique and we don't get a cached response.
    final int[] dataCallbackCount = new int[] { 0 };
    final int[] timeoutCallbackCount = new int[] { 0 };
    final Data[] receivedData = new Data[1];
    Name interestName = prefixName.append("hello" + getNowMilliseconds());
    faceOut.expressInterest
      (interestName, new OnData() {
        public void onData(Interest interest, Data data) {
          ++dataCallbackCount[0];
          receivedData[0] = data;
        }
      }, new OnTimeout() {
        public void onTimeout(Interest interest) { ++timeoutCallbackCount[0]; }
      });

    // Process events for the in and out faces.
    timeout = 10000;
    startTime = getNowMilliseconds();
    while (getNowMilliseconds() - startTime < timeout) {
      try {
        faceIn.processEvents();
        faceOut.processEvents();
      } catch (IOException ex) {
        logger.log(Level.SEVERE, null, ex);
        break;
      } catch (EncodingException ex) {
        logger.log(Level.SEVERE, null, ex);
        break;
      }

      boolean done = true;
      if (interestCallbackCount[0] == 0 && failedCallbackCount[0] == 0)
        // Still processing faceIn.
        done = false;
      if (dataCallbackCount[0] == 0 && timeoutCallbackCount[0] == 0)
        // Still processing face_out.
        done = false;

      if (done)
          break;

      try {
        // We need to sleep for a few milliseconds so we don't use 100% of the CPU.
        Thread.sleep(10);
      } catch (InterruptedException ex) {
        logger.log(Level.SEVERE, null, ex);
        break;
      }
    }

    assertEquals("Failed to register prefix at all",
                 0, failedCallbackCount[0]);
    assertEquals("Expected 1 onInterest callback",
                 1, interestCallbackCount[0]);
    assertEquals("Expected 1 onData callback",
                 1, dataCallbackCount[0]);

    // Check the message content.
    Blob expectedBlob = new Blob("SUCCESS");
    assertTrue("Data received on the face does not match the expected format",
               expectedBlob.equals(receivedData[0].getContent()));
  }

  public static double
  getNowMilliseconds() { return Common.getNowMilliseconds(); }

  private static final Logger logger = Logger.getLogger
    (TestFaceCallRegisterMethods.class.getName());
}
