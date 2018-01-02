/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/v2/validator-config/filter.cpp
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
import net.named_data.jndn.util.BoostInfoTree;

/**
 * ConfigFilter is an abstract base class for RegexNameFilter, etc. used by
 * ValidatorConfig. The ValidatorConfig class consists of a set of rules.
 * The Filter class is a part of a rule and is used to match a packet.
 * Matched packets will be checked against the checkers defined in the rule.
 */
public abstract class ConfigFilter {
  /**
   * Call the virtual matchName method based on the packet type.
   * @param isForInterest True if packetName is for an Interest, false if for a
   * Data packet.
   * @param packetName The packet name. For a signed interest, the last two
   * components are skipped but not removed.
   * @return True for a match.
   */
  public final boolean
  match(boolean isForInterest, Name packetName)
    throws ValidatorConfigError
  {
    if (isForInterest) {
      final int signedInterestMinSize = 2;

      if (packetName.size() < signedInterestMinSize)
        return false;

      return matchName(packetName.getPrefix(-signedInterestMinSize));
    }
    else
      // Data packet.
      return matchName(packetName);
  }

  /**
   * Create a filter from the configuration section.
   * @param configSection The section containing the definition of the filter,
   * e.g. one of "validator.rule.filter".
   * @return A new filter created from the configuration section.
   */
  public static ConfigFilter
  create(BoostInfoTree configSection)
    throws ValidatorConfigError
  {
    String filterType = configSection.getFirstValue("type");
    if (filterType == null)
      throw new ValidatorConfigError("Expected <filter.type>");

    if (filterType.equalsIgnoreCase("name"))
      return createNameFilter(configSection);
    else
      throw new ValidatorConfigError("Unsupported filter.type: " + filterType);
  }

  /**
   * Implementation of the check for match.
   * @param packetName The packet name, which is already stripped of signature
   * components if this is a signed Interest name.
   * @return True for a match.
   */
  protected abstract boolean
  matchName(Name packetName) throws ValidatorConfigError;

  /**
   * This is a helper for create() to create a filter from the configuration
   * section which is type "name".
   * @param configSection The section containing the definition of the filter.
   * @return A new filter created from the configuration section.
   */
  private static ConfigFilter
  createNameFilter(BoostInfoTree configSection)
    throws ValidatorConfigError
  {
    String nameUri = configSection.getFirstValue("name");
    if (nameUri != null) {
      // Get the filter.name.
      Name name = new Name(nameUri);

      // Get the filter.relation.
      String relationValue = configSection.getFirstValue("relation");
      if (relationValue == null)
        throw new ValidatorConfigError("Expected <filter.relation>");

      ConfigNameRelation.Relation relation =
        ConfigNameRelation.getNameRelationFromString(relationValue);

      return new ConfigRelationNameFilter(name, relation);
    }

    String regexString = configSection.getFirstValue("regex");
    if (regexString != null) {
      try {
        return new ConfigRegexNameFilter(regexString);
      }
      catch (Exception e) {
        throw new ValidatorConfigError("Wrong filter.regex: " + regexString);
      }
    }

    throw new ValidatorConfigError("Wrong filter(name) properties");
  }
}
