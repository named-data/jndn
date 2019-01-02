/**
 * Copyright (C) 2017-2019 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt unit tests
 * https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/validator-fixture.cpp
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
import java.util.ArrayList;
import net.named_data.jndn.Face;
import net.named_data.jndn.Interest;
import net.named_data.jndn.OnData;
import net.named_data.jndn.OnNetworkNack;
import net.named_data.jndn.OnTimeout;
import net.named_data.jndn.encoding.WireFormat;
import net.named_data.jndn.security.KeyChain;
import net.named_data.jndn.security.pib.PibImpl;
import net.named_data.jndn.security.v2.CertificateCacheV2;
import net.named_data.jndn.security.v2.CertificateFetcherFromNetwork;
import net.named_data.jndn.security.v2.CertificateV2;
import net.named_data.jndn.security.v2.ValidationPolicy;
import net.named_data.jndn.security.v2.Validator;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.util.Common;

/**
 * ValidatorFixture extends IdentityManagementFixture to use the given policy
 * and to set up a test face to answer Interests.
 */
public class ValidatorFixture extends IdentityManagementFixture {
  /**
   * Create a ValidatorFixture to use the given policy. Set the default
   * face_.processInterest_ to use the cache_ to respond to expressInterest. To
   * change this behavior, you can set face_.processInterest_ to your callback,
   * or to null to always time out.
   * @param policy The ValidationPolicy used by validator_.
   */
  public ValidatorFixture(ValidationPolicy policy)
    throws KeyChain.Error, PibImpl.Error, SecurityException, IOException
  {
    validator_ = new Validator(policy, new CertificateFetcherFromNetwork(face_));
    policy_ = policy;

    face_.processInterest_ = new TestFace.ProcessInterest() {
      public void processInterest
        (Interest interest, OnData onData, OnTimeout onTimeout,
         OnNetworkNack onNetworkNack) {
        CertificateV2 certificate = cache_.find(interest);
        if (certificate != null)
          onData.onData(interest, certificate);
        else
          onTimeout.onTimeout(interest);
      }
    };
  }

  /**
   * TestFace extends Face to instantly simulate a call to expressInterest.
   * See expressInterest for details.
   */
  public static class TestFace extends Face {
    public interface ProcessInterest {
      void processInterest
        (Interest interest, OnData onData, OnTimeout onTimeout,
         OnNetworkNack onNetworkNack);
    }

    public TestFace()
    {
      super("localhost");
    }

    /**
     * If processInterest_ is not null, call
     * processInterest_.processInterest(interest, onData, onTimeout, onNetworkNack)
     * which must call one of the callbacks to simulate the response. Otherwise, 
     * just call onTimeout(interest) to simulate a timeout. This adds a copy of
     * the interest to sentInterests_ .
     */
    public long
    expressInterest
      (Interest interest, OnData onData, OnTimeout onTimeout,
       OnNetworkNack onNetworkNack, WireFormat wireFormat) throws IOException
    {
      // Makes a copy of the interest.
      sentInterests_.add(new Interest(interest));

      if (processInterest_ != null)
        processInterest_.processInterest
          (interest, onData, onTimeout, onNetworkNack);
      else
        onTimeout.onTimeout(interest);

      return 0;
    }

    public ProcessInterest processInterest_ = null;
    public ArrayList<Interest> sentInterests_ = new ArrayList<Interest>();
  };

  public final TestFace face_ = new TestFace();
  public final Validator validator_;
  public final ValidationPolicy policy_;
  // Set maxLifetime to 100 days.
  public final CertificateCacheV2 cache_ =
    new CertificateCacheV2(100 * 24 * 3600 * 1000.0);
  // This is to force an import of net.named_data.jndn.util.
  private static Common dummyCommon_ = new Common();
}
