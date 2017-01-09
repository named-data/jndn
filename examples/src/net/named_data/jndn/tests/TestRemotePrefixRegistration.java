/**
 * Copyright (C) 2015-2017 Regents of the University of California.
 *
 * @author: Andrew Brown <andrew.brown@intel.com>
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>. A copy
 * of the GNU Lesser General Public License is in the file COPYING.
 */
package net.named_data.jndn.tests;

import java.util.logging.Logger;
import java.io.IOException;
import net.named_data.jndn.Data;
import net.named_data.jndn.Face;
import net.named_data.jndn.Interest;
import net.named_data.jndn.InterestFilter;
import net.named_data.jndn.Name;
import net.named_data.jndn.OnData;
import net.named_data.jndn.OnInterestCallback;
import net.named_data.jndn.OnRegisterFailed;
import net.named_data.jndn.OnTimeout;
import net.named_data.jndn.security.KeyChain;
import net.named_data.jndn.security.identity.IdentityManager;
import net.named_data.jndn.security.identity.MemoryIdentityStorage;
import net.named_data.jndn.security.identity.MemoryPrivateKeyStorage;
import net.named_data.jndn.util.Blob;

/**
 * Remote prefix registration example.
 */
public class TestRemotePrefixRegistration {

  /**
   * Ensure remote NFD has localhop configuration enabled for any certificate;
   * inside the examples directory, run with
   * `mvn -q test -DclassName=TestRemotePrefixRegistration -Dip=[IP address to remote NFD]`.
   *
   * @param args
   * @throws Exception
   */
  public static void main(String[] args) throws Exception {
    Face face = new Face(System.getProperty("ip"));
    KeyChain keyChain = buildTestKeyChain();
    face.setCommandSigningInfo(keyChain, keyChain.getDefaultCertificateName());

    // test connection
    Interest interest = new Interest(new Name("/localhop/nfd/rib/list"));
    interest.setInterestLifetimeMilliseconds(1000);
    face.expressInterest(interest, new OnData() {
      public void onData(Interest interest, Data data) {
        logger.info("Data received (bytes): " + data.getContent().size());
      }
    }, new OnTimeout() {
      public void onTimeout(Interest interest) {
        logger.severe("Failed to retrieve localhop data from NFD: " + interest.toUri());
        System.exit(1);
      }
    });

	// check if face is local
	logger.info("Face is local: " + face.isLocal());

    // register remotely
    face.registerPrefix(new Name("/remote-prefix"), new OnInterestCallback() {
      public void onInterest
          (Name prefix, Interest interest, Face face, long interestFilterId,
           InterestFilter filter) {
        Data data = new Data(interest.getName());
        data.setContent(new Blob("..."));
        try {
          face.putData(data);
        } catch (IOException e) {
          logger.severe("Failed to send data: " + e.getMessage());
          System.exit(1);
        }
      }
    }, new OnRegisterFailed() {
      public void onRegisterFailed(Name prefix) {
        logger.severe("Failed to register the external forwarder: " + prefix.toUri());
        System.exit(1);
      }
    });

    // process events until process is killed
    while (true) {
      face.processEvents();
    }
  }

  /**
   * Setup an in-memory KeyChain with a default identity.
   *
   * @return
   * @throws net.named_data.jndn.security.SecurityException
   */
  public static KeyChain buildTestKeyChain() throws net.named_data.jndn.security.SecurityException {
    MemoryIdentityStorage identityStorage = new MemoryIdentityStorage();
    MemoryPrivateKeyStorage privateKeyStorage = new MemoryPrivateKeyStorage();
    IdentityManager identityManager = new IdentityManager(identityStorage, privateKeyStorage);
    KeyChain keyChain = new KeyChain(identityManager);
    try {
      keyChain.getDefaultCertificateName();
    } catch (net.named_data.jndn.security.SecurityException e) {
      keyChain.createIdentityAndCertificate(new Name("/test/identity"));
      keyChain.getIdentityManager().setDefaultIdentity(new Name("/test/identity"));
    }
    return keyChain;
  }

  private static final Logger logger = Logger.getLogger(TestRemotePrefixRegistration.class.getName());
}
