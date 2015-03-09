/**
 * Copyright (C) 2015 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
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

import src.net.named_data.jndn.tests.integration_tests.*;
import java.io.File;
import net.named_data.jndn.Data;
import net.named_data.jndn.security.OnVerified;
import net.named_data.jndn.security.OnVerifyFailed;

/**
 * Common static methods and package classes for integration tests.
 */
public class IntegrationTestsCommon {
  /**
   * Get the policy_config directory based on the current top-level jndn directory.
   * @return
   */
  public static File
  getPolicyConfigDirectory()
  {
    File result = new File(System.getProperty("user.dir"));
    String[] path =
      {"integration-tests", "src", "net", "named_data", "jndn", "tests", "integration_tests", "policy_config"};
    for (int i = 0; i < path.length; ++i)
      result = new File(result, path[i]);

    return result;
  }
}

class VerifyCounter implements OnVerified, OnVerifyFailed
{
  public void
  onVerified(Data data)
  {
    ++onVerifiedCallCount_;
  }

  public void
  onVerifyFailed(Data data)
  {
    ++onVerifyFailedCallCount_;
  }

  public int onVerifiedCallCount_ = 0;
  public int onVerifyFailedCallCount_ = 0;
}
