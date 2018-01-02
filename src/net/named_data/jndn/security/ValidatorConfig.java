/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/validator-config.cpp
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

package net.named_data.jndn.security;

import java.io.IOException;
import net.named_data.jndn.Face;
import net.named_data.jndn.security.v2.CertificateFetcher;
import net.named_data.jndn.security.v2.CertificateFetcherFromNetwork;
import net.named_data.jndn.security.v2.ValidationPolicyConfig;
import net.named_data.jndn.security.v2.Validator;
import net.named_data.jndn.util.BoostInfoTree;

/**
 * ValidatorConfig extends Validator to implements a validator which can be
 * set up via a configuration file.
 */
public class ValidatorConfig extends Validator {
  // TODO: Add Options.
  // TODO: Add ValidationPolicyCommandInterest.
  public ValidatorConfig(CertificateFetcher fetcher)
  {
    super(new ValidationPolicyConfig(), fetcher);
    // TODO: Use getInnerPolicy().
    policyConfig_ = (ValidationPolicyConfig)getPolicy();
  }

  // TODO: Add Options.
  // TODO: Add ValidationPolicyCommandInterest.
  /**
   * Create a ValidatorConfig that uses a CertificateFetcherFromNetwork for the
   * given Face.
   * @param face The face for the certificate fetcher to call expressInterest.
   */
  public ValidatorConfig(Face face)
  {
    super(new ValidationPolicyConfig(), new CertificateFetcherFromNetwork(face));
    // TODO: Use getInnerPolicy().
    policyConfig_ = (ValidationPolicyConfig)getPolicy();
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
    policyConfig_.load(filePath);
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
    policyConfig_.load(input, inputName);
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
    policyConfig_.load(configSection, inputName);
  }

  private final ValidationPolicyConfig policyConfig_;
}
