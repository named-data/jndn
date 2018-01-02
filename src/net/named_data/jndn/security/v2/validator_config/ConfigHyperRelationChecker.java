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

public class ConfigHyperRelationChecker extends ConfigChecker {
  public ConfigHyperRelationChecker
    (String packetNameRegexString, String packetNameExpansion,
     String keyNameRegexString, String keyNameExpansion,
     ConfigNameRelation.Relation hyperRelation)
    throws NdnRegexMatcherBase.Error
  {
    packetNameRegex_ = new NdnRegexTopMatcher(packetNameRegexString);
    packetNameExpansion_ = packetNameExpansion;
    keyNameRegex_ = new NdnRegexTopMatcher(keyNameRegexString);
    keyNameExpansion_ = keyNameExpansion;
    hyperRelation_ = hyperRelation;
  }

  protected boolean
  checkNames(Name packetName, Name keyLocatorName, ValidationState state)
    throws ValidatorConfigError
  {
    boolean isMatch;
    try {
      isMatch = packetNameRegex_.match(packetName);
    } catch (NdnRegexMatcherBase.Error ex) {
      throw new ValidatorConfigError("Error in regex match: " + ex);
    }
    if (!isMatch) {
      state.fail(new ValidationError(ValidationError.POLICY_ERROR,
        "The packet " + packetName.toUri() + " (KeyLocator=" +
        keyLocatorName.toUri() +
        ") does not match the hyper relation packet name regex " +
        packetNameRegex_.getExpr()));
      return false;
    }

    try {
      isMatch = keyNameRegex_.match(keyLocatorName);
    } catch (NdnRegexMatcherBase.Error ex) {
      throw new ValidatorConfigError("Error in regex match: " + ex);
    }
    if (!isMatch) {
      state.fail(new ValidationError(ValidationError.POLICY_ERROR,
        "The packet " + packetName.toUri() + " (KeyLocator=" +
        keyLocatorName.toUri() +
        ") does not match the hyper relation key name regex " +
        keyNameRegex_.getExpr()));
      return false;
    }

    Name keyNameMatchExpansion;
    try {
      keyNameMatchExpansion = keyNameRegex_.expand(keyNameExpansion_);
    } catch (NdnRegexMatcherBase.Error ex) {
      throw new ValidatorConfigError("Error in regex expand: " + ex);
    }
    Name packetNameMatchExpansion;
    try {
      packetNameMatchExpansion = packetNameRegex_.expand(packetNameExpansion_);
    } catch (NdnRegexMatcherBase.Error ex) {
      throw new ValidatorConfigError("Error in regex expand: " + ex);
    }

    boolean result = ConfigNameRelation.checkNameRelation
      (hyperRelation_, keyNameMatchExpansion, packetNameMatchExpansion);
    if (!result)
      state.fail(new ValidationError(ValidationError.POLICY_ERROR,
        "KeyLocator check failed: hyper relation " +
        ConfigNameRelation.toString(hyperRelation_) + " packet name match=" +
        packetNameMatchExpansion.toUri() + ", key name match=" +
        keyNameMatchExpansion.toUri() + " of packet " + packetName.toUri() +
        " (KeyLocator=" + keyLocatorName.toUri() + ") is invalid"));

    return result;
  }

  private final NdnRegexTopMatcher packetNameRegex_;
  private final String packetNameExpansion_;
  private final NdnRegexTopMatcher keyNameRegex_;
  private final String keyNameExpansion_;
  private final ConfigNameRelation.Relation hyperRelation_;
}
