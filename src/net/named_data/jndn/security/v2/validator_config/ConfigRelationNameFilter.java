/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/v2/validator-config/filter.hpp
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

/**
 * ConfigRelationNameFilter extends ConfigFilter to check that the name is in
 * the given relation to the packet name.
 * The configuration
 * "filter
 * {
 *   type name
 *   name /example
 *   relation is-prefix-of
 * }"
 * creates ConfigRelationNameFilter("/example",
 *   ConfigNameRelation.Relation.IS_PREFIX_OF) .
 */
public class ConfigRelationNameFilter extends ConfigFilter {
  /**
   * Create a ConfigRelationNameFilter for the given values.
   * @param name The relation name, which is copied.
   * @param relation The relation type as a ConfigNameRelation.Relation enum.
   */
  public ConfigRelationNameFilter
    (Name name, ConfigNameRelation.Relation relation)
  {
    // Copy the Name.
    name_ = new Name(name);
    relation_ = relation;
  }

  /**
   * Implementation of the check for match.
   * @param packetName The packet name, which is already stripped of signature
   * components if this is a signed Interest name.
   * @return True for a match.
   */
  protected boolean
  matchName(Name packetName) throws ValidatorConfigError
  {
    return ConfigNameRelation.checkNameRelation(relation_, name_, packetName);
  }

  private final Name name_;
  private final ConfigNameRelation.Relation relation_;
}
