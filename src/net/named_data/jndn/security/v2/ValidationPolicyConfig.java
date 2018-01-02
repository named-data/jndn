/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/v2/validation-policy-config.cpp
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

import java.io.IOException;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.named_data.jndn.Data;
import net.named_data.jndn.Interest;
import net.named_data.jndn.Name;
import net.named_data.jndn.security.ValidatorConfigError;
import net.named_data.jndn.security.v2.validator_config.ConfigRule;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.BoostInfoParser;
import net.named_data.jndn.util.BoostInfoTree;
import net.named_data.jndn.util.Common;

/**
 * ValidationPolicyConfig implements a validator which can be set up via a
 * configuration file. For command Interest validation, this policy must be
 * combined with ValidationPolicyCommandInterest in order to guard against
 * replay attacks.
 * @note This policy does not support inner policies (a sole policy or a
 * terminal inner policy).
 * See https://named-data.net/doc/ndn-cxx/current/tutorials/security-validator-config.html
 */
public class ValidationPolicyConfig extends ValidationPolicy {
  /**
   * Create a default ValidationPolicyConfig.
   */
  public ValidationPolicyConfig()
  {
    shouldBypass_ = false;
    isConfigured_ = false;
  }

  /**
   * Load the configuration from the given config file. This replaces any
   * existing configuration.
   * @param filePath The The path of the config file.
   */
  public final void
  load(String filePath)
    throws IOException, ValidatorConfigError
  {
    BoostInfoParser parser = new BoostInfoParser();
    parser.read(filePath);
    load(parser.getRoot(), filePath);
  }

  /**
   * Load the configuration from the given input string. This replaces any
   * existing configuration.
   * @param input The contents of the configuration rules, with lines separated
   * by "\n" or "\r\n".
   * @param inputName Used for log messages, etc.
   */
  public final void
  load(String input, String inputName)
    throws IOException, ValidatorConfigError
  {
    BoostInfoParser parser = new BoostInfoParser();
    parser.read(input, inputName);
    load(parser.getRoot(), inputName);
  }

  /**
   * Load the configuration from the given configSection. This replaces any
   * existing configuration.
   * @param configSection The configuration section loaded from the config file.
   * It should have one "validator" section.
   * @param inputName Used for log messages, etc.
   */
  public final void
  load(BoostInfoTree configSection, String inputName)
    throws ValidatorConfigError
  {
    if (isConfigured_) {
      // Reset the previous configuration.
      shouldBypass_ = false;
      dataRules_.clear();
      interestRules_.clear();

      validator_.resetAnchors();
      validator_.resetVerifiedCertificates();
    }
    isConfigured_ = true;

    ArrayList<BoostInfoTree> validatorList = configSection.get("validator");
    if (validatorList.size() != 1)
      throw new ValidatorConfigError
        ("ValidationPolicyConfig: Expected one validator section");
    BoostInfoTree validatorSection = validatorList.get(0);

    // Get the rules.
    ArrayList<BoostInfoTree> ruleList = validatorSection.get("rule");
    for (int i = 0; i < ruleList.size(); ++i) {
      ConfigRule rule = ConfigRule.create(ruleList.get(i));
      if (rule.getIsForInterest())
        interestRules_.add(rule);
      else
        dataRules_.add(rule);
    }

    // Get the trust anchors.
    ArrayList<BoostInfoTree> trustAnchorList = validatorSection.get("trust-anchor");
    for (int i = 0; i < trustAnchorList.size(); ++i)
      processConfigTrustAnchor(trustAnchorList.get(i), inputName);
  }

  public void
  checkPolicy
    (Data data, ValidationState state, ValidationContinuation continueValidation)
    throws CertificateV2.Error, ValidatorConfigError
  {
    if (hasInnerPolicy())
      throw new ValidatorConfigError
        ("ValidationPolicyConfig must be a terminal inner policy");

    if (shouldBypass_) {
      continueValidation.continueValidation(null, state);
      return;
    }

    Name keyLocatorName = getKeyLocatorName(data, state);
    if (state.isOutcomeFailed())
      // Already called state.fail() .
      return;

    for (int i = 0; i < dataRules_.size(); ++i) {
      ConfigRule rule = dataRules_.get(i);

      if (rule.match(false, data.getName())) {
        if (rule.check(false, data.getName(), keyLocatorName, state)) {
          continueValidation.continueValidation
            (new CertificateRequest(new Interest(keyLocatorName)),
             state);
          return;
        }
        else
          // rule.check failed and already called state.fail() .
          return;
      }
    }

    state.fail(new ValidationError(ValidationError.POLICY_ERROR,
      "No rule matched for data `" + data.getName().toUri() + "`"));
  }

  public void
  checkPolicy
    (Interest interest, ValidationState state,
     ValidationContinuation continueValidation)
    throws CertificateV2.Error, ValidatorConfigError
  {
    if (hasInnerPolicy())
      throw new ValidatorConfigError
        ("ValidationPolicyConfig must be a terminal inner policy");

    if (shouldBypass_) {
      continueValidation.continueValidation(null, state);
      return;
    }

    Name keyLocatorName = getKeyLocatorName(interest, state);
    if (state.isOutcomeFailed())
      // Already called state.fail() .
      return;

    for (int i = 0; i < interestRules_.size(); ++i) {
      ConfigRule rule = interestRules_.get(i);

      if (rule.match(true, interest.getName())) {
        if (rule.check(true, interest.getName(), keyLocatorName, state)) {
          continueValidation.continueValidation
            (new CertificateRequest(new Interest(keyLocatorName)),
             state);
          return;
        }
        else
          // rule.check failed and already called state.fail() .
          return;
      }
    }

    state.fail(new ValidationError(ValidationError.POLICY_ERROR,
      "No rule matched for interest `" + interest.getName().toUri() + "`"));
  }

  /**
   * Process the trust-anchor configuration section and call
   * validator_.loadAnchor as needed.
   * @param configSection The section containing the definition of the trust
   * anchor, e.g. one of "validator.trust-anchor".
   * @param inputName Used for log messages, etc.
   */
  private void
  processConfigTrustAnchor(BoostInfoTree configSection, String inputName)
    throws ValidatorConfigError
  {
    String anchorType = configSection.getFirstValue("type");
    if (anchorType == null)
      throw new ValidatorConfigError("Expected <trust-anchor.type>");

    if (anchorType.equalsIgnoreCase("file")) {
      // Get trust-anchor.file .
      String fileName = configSection.getFirstValue("file-name");
      if (fileName == null)
        throw new ValidatorConfigError("Expected <trust-anchor.file-name>");

      double refreshPeriod = getRefreshPeriod(configSection);
      try {
        validator_.loadAnchor(fileName, fileName, refreshPeriod, false);
      } catch (TrustAnchorContainer.Error ex) {
        throw new ValidatorConfigError("Error in loadAnchor: " + ex);
      }

      return;
    }
    else if (anchorType.equalsIgnoreCase("base64")) {
      // Get trust-anchor.base64-string .
      String base64String = configSection.getFirstValue("base64-string");
      if (base64String == null)
        throw new ValidatorConfigError("Expected <trust-anchor.base64-string>");

      byte[] encoding = Common.base64Decode(base64String);
      CertificateV2 certificate = new CertificateV2();
      try {
        certificate.wireDecode(new Blob(encoding));
      } catch (Exception ex) {
        throw new ValidatorConfigError
          ("Cannot decode certificate from base64-string: " + ex);
      }
      try {
        validator_.loadAnchor("", certificate);
      } catch (TrustAnchorContainer.Error ex) {
        throw new ValidatorConfigError("Error in loadAnchor: " + ex);
      }

      return;
    }
    else if (anchorType.equalsIgnoreCase("dir")) {
      // Get trust-anchor.dir .
      String dirString = configSection.getFirstValue("dir");
      if (dirString == null)
        throw new ValidatorConfigError("Expected <trust-anchor.dir>");

      double refreshPeriod = getRefreshPeriod(configSection);
      try {
        validator_.loadAnchor(dirString, dirString, refreshPeriod, true);
      } catch (TrustAnchorContainer.Error ex) {
        throw new ValidatorConfigError("Error in loadAnchor: " + ex);
      }

      return;
    }
    else if (anchorType.equalsIgnoreCase("any"))
      shouldBypass_ = true;
    else
      throw new ValidatorConfigError("Unsupported trust-anchor.type");
  }

  /**
   * Get the "refresh" value. If the value is 9, return a period of one hour.
   * @param configSection The section containing the definition of the trust
   * anchor, e.g. one of "validator.trust-anchor".
   * @return The refresh period in milliseconds. However if there is no
   * "refresh" value, return a large number (effectively no refresh).
   */
  private static double
  getRefreshPeriod(BoostInfoTree configSection)
  {
    String refreshString = configSection.getFirstValue("refresh");
    if (refreshString == null)
      // Return a large value (effectively no refresh).
      return 1e14;

    double refreshSeconds = 0;
    Pattern regex1 = Pattern.compile("(\\d+)([hms])");
    Matcher refreshMatch = regex1.matcher(refreshString);
    if (refreshMatch.find()) {
      refreshSeconds = Integer.parseInt(refreshMatch.group(1));
      if (!refreshMatch.group(2).equals("s")) {
        refreshSeconds *= 60;
        if (!refreshMatch.group(2).equals("m"))
          refreshSeconds *= 60;
      }
    }

    if (refreshSeconds == 0.0)
      // Use an hour instead of 0.
      return 3600 * 1000.0;
    else
      // Convert from seconds to milliseconds.
      return refreshSeconds * 1000.0;
  }

  /** shouldBypass_ is set to true when 'any' is specified as a trust anchor,
   * causing all packets to bypass validation.
   */
  private boolean shouldBypass_;
  private boolean isConfigured_;
  private final ArrayList<ConfigRule> dataRules_ = new ArrayList<ConfigRule>();
  private final ArrayList<ConfigRule> interestRules_ = new ArrayList<ConfigRule>();
}
