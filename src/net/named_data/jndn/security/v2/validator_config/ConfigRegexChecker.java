/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/v2/validator-config/checker.cpp
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

package net.named_data.jndn.security.v2.validator_config;

import net.named_data.jndn.Name;
import net.named_data.jndn.security.ValidatorConfigError;
import net.named_data.jndn.security.v2.ValidationError;
import net.named_data.jndn.security.v2.ValidationState;
import net.named_data.jndn.util.regex.NdnRegexMatcherBase;
import net.named_data.jndn.util.regex.NdnRegexTopMatcher;

public class ConfigRegexChecker extends ConfigChecker {
  public ConfigRegexChecker(String regexString)
    throws NdnRegexMatcherBase.Error
  {
    regex_ = new NdnRegexTopMatcher(regexString);
  }

  protected boolean
  checkNames(Name packetName, Name keyLocatorName, ValidationState state)
    throws ValidatorConfigError
  {
    boolean result;
    try {
      result = regex_.match(keyLocatorName);
    } catch (NdnRegexMatcherBase.Error ex) {
      throw new ValidatorConfigError("Error matching regex: " + ex);
    }

    if (!result)
      state.fail(new ValidationError(ValidationError.POLICY_ERROR,
        "KeyLocator check failed: regex " + regex_.getExpr() + " for packet " +
        packetName.toUri() + " is invalid (KeyLocator=" + keyLocatorName.toUri() +
        ")"));

    return result;
  }

  private final NdnRegexTopMatcher regex_;
}
