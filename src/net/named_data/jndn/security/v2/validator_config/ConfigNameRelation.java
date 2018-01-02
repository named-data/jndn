/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/v2/validator-config/name-relation.cpp
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

/** ConfigNameRelation defines the ConfigNameRelation.Relation enum and static
 * methods to work with name relations for the ValidatorConfig.
 */
public class ConfigNameRelation {
  public enum Relation {
    EQUAL,
    IS_PREFIX_OF,
    IS_STRICT_PREFIX_OF
  }

  /**
   * Get a string representation of the Relation enum.
   * @param relation The value for the ConfigNameRelation.Relation enum.
   * @return The string representation.
   */
  public static String
  toString(Relation relation)
  {
    if (relation == Relation.EQUAL)
      return "equal";
    else if (relation == Relation.IS_PREFIX_OF)
      return "is-prefix-of";
    else if (relation == Relation.IS_STRICT_PREFIX_OF)
      return "is-strict-prefix-of";
    else
      // We don't expect this to happen.
      return "";
  }

  /**
   * Check whether name1 and name2 satisfy the relation.
   * @param relation The value for the ConfigNameRelation.Relation enum.
   * @param name1 The first name to check.
   * @param name2 The second name to check.
   * @return True if the names satisfy the relation.
   */
  public static boolean
  checkNameRelation(Relation relation, Name name1, Name name2)
  {
    if (relation == Relation.EQUAL)
      return name1.equals(name2);
    else if (relation == Relation.IS_PREFIX_OF)
      return name1.isPrefixOf(name2);
    else if (relation == Relation.IS_STRICT_PREFIX_OF)
      return name1.isPrefixOf(name2) && name1.size() < name2.size();
    else
      // We don't expect this to happen.
      return false;
  }

  /**
   * Convert relationString to a ConfigNameRelation.Relation enum.
   * @throws ValidatorConfigError if relationString cannot be converted.
   */
  public static Relation
  getNameRelationFromString(String relationString)
    throws ValidatorConfigError
  {
    if (relationString.equalsIgnoreCase("equal"))
      return Relation.EQUAL;
    else if (relationString.equalsIgnoreCase("is-prefix-of"))
      return Relation.IS_PREFIX_OF;
    else if (relationString.equalsIgnoreCase("is-strict-prefix-of"))
      return Relation.IS_STRICT_PREFIX_OF;
    else
      throw new ValidatorConfigError("Unsupported relation: " + relationString);
  }
}
