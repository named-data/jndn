/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/v2/validation-policy-accept-all.hpp
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
import net.named_data.jndn.security.ValidatorConfigError;

/**
 * ValidationPolicyAcceptAll extends ValidationPolicy to implement a validator
 * policy that accepts any signature of a Data or Interest packet.
 */
public class ValidationPolicyAcceptAll extends ValidationPolicy {
  public void
  checkPolicy
    (Data data, ValidationState state, ValidationContinuation continueValidation)
    throws CertificateV2.Error, ValidatorConfigError
  {
    continueValidation.continueValidation(null, state);
  }

  public void
  checkPolicy
    (Interest interest, ValidationState state,
     ValidationContinuation continueValidation)
    throws CertificateV2.Error, ValidatorConfigError
  {
    continueValidation.continueValidation(null, state);
  }
}
