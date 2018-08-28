/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/v2/validation-policy-simple-hierarchy.hpp
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

package net.named_data.jndn.security.v2;

import net.named_data.jndn.Data;
import net.named_data.jndn.Interest;
import net.named_data.jndn.Name;
import net.named_data.jndn.security.ValidatorConfigError;

/**
 * ValidationPolicySimpleHierarchy extends ValidationPolicy to implement a
 * Validation policy for a simple hierarchical trust model.
 */
public class ValidationPolicySimpleHierarchy extends ValidationPolicy {
  public void
  checkPolicy
    (Data data, ValidationState state, ValidationContinuation continueValidation)
      throws CertificateV2.Error, ValidatorConfigError
  {
    Name keyLocatorName = getKeyLocatorName(data, state);
    if (state.isOutcomeFailed())
      // Already called state.fail().)
      return;

    if (keyLocatorName.getPrefix(-2).isPrefixOf(data.getName()))
      continueValidation.continueValidation
        (new CertificateRequest(new Interest(keyLocatorName)), state);
    else
      state.fail(new ValidationError(ValidationError.INVALID_KEY_LOCATOR,
        "Data signing policy violation for " + data.getName().toUri() + " by " +
        keyLocatorName.toUri()));
  }

  public void
  checkPolicy
    (Interest interest, ValidationState state,
     ValidationContinuation continueValidation)
    throws CertificateV2.Error, ValidatorConfigError
  {
    Name keyLocatorName = getKeyLocatorName(interest, state);
    if (state.isOutcomeFailed())
      // Already called state.fail().)
      return;

    if (keyLocatorName.getPrefix(-2).isPrefixOf(interest.getName()))
      continueValidation.continueValidation
        (new CertificateRequest(new Interest(keyLocatorName)), state);
    else
      state.fail(new ValidationError(ValidationError.INVALID_KEY_LOCATOR,
        "Interest signing policy violation for " + interest.getName().toUri() +
        " by " + keyLocatorName.toUri()));
  }

}
