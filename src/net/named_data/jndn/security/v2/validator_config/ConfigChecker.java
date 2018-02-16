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

import java.util.ArrayList;
import net.named_data.jndn.Name;
import net.named_data.jndn.security.ValidatorConfigError;
import net.named_data.jndn.security.v2.ValidationState;
import net.named_data.jndn.util.BoostInfoTree;
import net.named_data.jndn.util.regex.NdnRegexMatcherBase;

/**
 * A ConfigChecker is an abstract base class for ConfigNameRelationChecker, etc.
 * used by ValidatorConfig to check if a packet name and KeyLocator satisfy the
 * conditions in a configuration section.
 */
public abstract class ConfigChecker {
  /**
   * Check if the packet name ane KeyLocator name satisfy this checker's
   * conditions.
   * @param isForInterest True if packetName is for an Interest, false if for a
   * Data packet.
   * @param packetName The packet name. For a signed interest, the last two
   * components are skipped but not removed.
   * @param keyLocatorName The KeyLocator's name.
   * @param state This calls state.fail() if the packet is invalid.
   * @return True if further signature verification is needed, or false if the
   * packet is immediately determined to be invalid in which case this calls
   * state.fail() with the proper code and message.
   */
  public final boolean
  check
    (boolean isForInterest, Name packetName, Name keyLocatorName,
     ValidationState state) throws ValidatorConfigError
  {
    if (isForInterest) {
      final int signedInterestMinSize = 2;

      if (packetName.size() < signedInterestMinSize)
        return false;

      return checkNames
        (packetName.getPrefix(-signedInterestMinSize), keyLocatorName, state);
    }
    else
      return checkNames(packetName, keyLocatorName, state);
  }

  /**
   * Create a checker from the configuration section.
   * @param configSection The section containing the definition of the checker,
   * e.g. one of "validation.rule.checker".
   * @return A new checker created from the configuration section.
   */
  public static ConfigChecker
  create(BoostInfoTree configSection) throws ValidatorConfigError
  {
    // Get checker.type.
    String checkerType = configSection.getFirstValue("type");
    if (checkerType == null)
      throw new ValidatorConfigError("Expected <checker.type>");

    if (checkerType.equalsIgnoreCase("customized"))
      return createCustomizedChecker(configSection);
    else if (checkerType.equalsIgnoreCase("hierarchical"))
      return createHierarchicalChecker(configSection);
    else
      throw new ValidatorConfigError("Unsupported checker type: " + checkerType);
  }

  /**
   * Check if the packet name ane KeyLocator name satisfy this checker's
   * conditions.
   * @param packetName The packet name, which is already stripped of signature
   * components if this is a signed Interest name.
   * @param keyLocatorName The KeyLocator's name.
   * @param state This calls state.fail() if the packet is invalid.
   * @return True if further signature verification is needed, or false if the
   * packet is immediately determined to be invalid in which case this calls
   * state.fail() with the proper code and message.
   */
  protected abstract boolean
  checkNames(Name packetName, Name keyLocatorName, ValidationState state)
    throws ValidatorConfigError;

  private static ConfigChecker
  createCustomizedChecker(BoostInfoTree configSection)
    throws ValidatorConfigError
  {
    // Ignore sig-type.
    // Get checker.key-locator .
    ArrayList<BoostInfoTree> keyLocatorSection = configSection.get("key-locator");
    if (keyLocatorSection.size() != 1)
      throw new ValidatorConfigError("Expected one <checker.key-locator>");

    return createKeyLocatorChecker(keyLocatorSection.get(0));
  }

  private static ConfigChecker
  createHierarchicalChecker(BoostInfoTree configSection)
    throws ValidatorConfigError
  {
    try {
      // Ignore sig-type.
      return new ConfigHyperRelationChecker
        ("^(<>*)$",        "\\1",
         "^(<>*)<KEY><>$", "\\1",
         ConfigNameRelation.Relation.IS_PREFIX_OF);
    } catch (NdnRegexMatcherBase.Error ex) {
      throw new ValidatorConfigError("Error creating ConfigHyperRelationChecker: " + ex);
    }
  }

  private static ConfigChecker
  createKeyLocatorChecker(BoostInfoTree configSection)
    throws ValidatorConfigError
  {
    // Get checker.key-locator.type .
    String keyLocatorType = configSection.getFirstValue("type");
    if (keyLocatorType == null)
      throw new ValidatorConfigError("Expected <checker.key-locator.type>");

    if (keyLocatorType.equalsIgnoreCase("name"))
      return createKeyLocatorNameChecker(configSection);
    else
      throw new ValidatorConfigError
        ("Unsupported checker.key-locator.type: " + keyLocatorType);
  }

  private static ConfigChecker
  createKeyLocatorNameChecker(BoostInfoTree configSection)
    throws ValidatorConfigError
  {
    String nameUri = configSection.getFirstValue("name");
    if (nameUri != null) {
      Name name = new Name(nameUri);

      String relationValue = configSection.getFirstValue("relation");
      if (relationValue == null)
        throw new ValidatorConfigError("Expected <checker.key-locator.relation>");

      ConfigNameRelation.Relation relation =
        ConfigNameRelation.getNameRelationFromString(relationValue);
      return new ConfigNameRelationChecker(name, relation);
    }

    String regexString = configSection.getFirstValue("regex");
    if (regexString != null) {
      try {
        return new ConfigRegexChecker(regexString);
      }
      catch (Exception e) {
        throw new ValidatorConfigError
          ("Invalid checker.key-locator.regex: " + regexString);
      }
    }

    ArrayList<BoostInfoTree> hyperRelationList = configSection.get("hyper-relation");
    if (hyperRelationList.size() == 1) {
      BoostInfoTree hyperRelation = hyperRelationList.get(0);

      // Get k-regex.
      String keyRegex = hyperRelation.getFirstValue("k-regex");
      if (keyRegex == null)
        throw new ValidatorConfigError
          ("Expected <checker.key-locator.hyper-relation.k-regex>");

      // Get k-expand.
      String keyExpansion = hyperRelation.getFirstValue("k-expand");
      if (keyExpansion == null)
        throw new ValidatorConfigError
          ("Expected <checker.key-locator.hyper-relation.k-expand");

      // Get h-relation.
      String hyperRelationString = hyperRelation.getFirstValue("h-relation");
      if (hyperRelationString == null)
        throw new ValidatorConfigError
          ("Expected <checker.key-locator.hyper-relation.h-relation>");

      // Get p-regex.
      String packetNameRegex = hyperRelation.getFirstValue("p-regex");
      if (packetNameRegex == null)
        throw new ValidatorConfigError
          ("Expected <checker.key-locator.hyper-relation.p-regex>");

      // Get p-expand.
      String packetNameExpansion = hyperRelation.getFirstValue("p-expand");
      if (packetNameExpansion == null)
        throw new ValidatorConfigError
          ("Expected <checker.key-locator.hyper-relation.p-expand>");

      ConfigNameRelation.Relation relation =
        ConfigNameRelation.getNameRelationFromString(hyperRelationString);

      try {
        return new ConfigHyperRelationChecker
          (packetNameRegex, packetNameExpansion, keyRegex, keyExpansion, relation);
      }
      catch (Exception e) {
        throw new ValidatorConfigError
          ("Invalid regex for key-locator.hyper-relation");
      }
    }

    throw new ValidatorConfigError("Unsupported checker.key-locator");
  }
}
