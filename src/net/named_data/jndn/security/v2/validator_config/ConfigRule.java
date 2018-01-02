/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/v2/validator-config/rule.cpp
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
import java.util.logging.Level;
import java.util.logging.Logger;
import net.named_data.jndn.Name;
import net.named_data.jndn.security.ValidatorConfigError;
import net.named_data.jndn.security.v2.ValidationState;
import net.named_data.jndn.util.BoostInfoTree;

/**
 * A ConfigRule represents a rule configuration section, used by ConfigValidator.
 */
public class ConfigRule {
  /**
   * Create a ConfigRule with empty filters and checkers.
   * @param id The rule ID from the configuration section.
   * @param isForInterest True if the rule is for an Interest packet, false if
   * it is for a Data packet.
   */
  public ConfigRule(String id, boolean isForInterest)
  {
    id_ = id;
    isForInterest_ = isForInterest;
  }

  /**
   * Get the rule ID.
   * @return The rule ID.
   */
  public final String
  getId() { return id_; }

  /**
   * Get the isForInterest flag.
   * @return True if the rule is for an Interest packet, false if it is for a
   * Data packet.
   */
  public final boolean
  getIsForInterest() { return isForInterest_; }

  /**
   * Add the ConfigFilter to the list of filters.
   * @param filter The ConfigFilter.
   */
  public final void
  addFilter(ConfigFilter filter) { filters_.add(filter); }

  /**
   * Add the ConfigChecker to the list of checkers.
   * @param checker The ConfigChecker.
   */
  public final void
  addChecker(ConfigChecker checker) { checkers_.add(checker); }

  /**
   * Check if the packet name matches the rule's filter.
   * If no filters were added, the rule matches everything.
   * @param isForInterest True if packetName is for an Interest, false if for a
   * Data packet.
   * @param packetName The packet name. For a signed interest, the last two
   * components are skipped but not removed.
   * @return True if at least one filter matches the packet name, false if none
   * of the filters match the packet name.
   * @throws ValidatorConfigError if the supplied isForInterest doesn't match the
   * one for which the rule is designed.
   */
  public final boolean
  match(boolean isForInterest, Name packetName)
    throws ValidatorConfigError
  {
    logger_.log(Level.FINE, "Trying to match {0}", packetName.toUri());

    if (isForInterest != isForInterest_)
      throw new ValidatorConfigError
        ("Invalid packet type supplied ( " +
         (isForInterest ? "interest" : "data") + " != " +
         (isForInterest_ ? "interest" : "data") + ")");

    if (filters_.size() == 0)
      return true;

    boolean result = false;
    for (int i = 0; i < filters_.size(); ++i) {
      result = (result || filters_.get(i).match(isForInterest, packetName));
      if (result)
        break;
    }

    return result;
  }

  /**
   * Check if the packet satisfies the rule's condition.
   * @param isForInterest True if packetName is for an Interest, false if for a
   * Data packet.
   * @param packetName The packet name. For a signed interest, the last two
   * components are skipped but not removed.
   * @param keyLocatorName The KeyLocator's name.
   * @param state This calls state.fail() if the packet is invalid.
   * @return True if further signature verification is needed, or false if the
   * packet is immediately determined to be invalid in which case this calls
   * state.fail() with the proper code and message.
   * @throws ValidatorConfigError if the supplied isForInterest doesn't match the
   * one for which the rule is designed.
   */
  public final boolean
  check
    (boolean isForInterest, Name packetName, Name keyLocatorName,
     ValidationState state)
    throws ValidatorConfigError
  {
    logger_.log(Level.FINE, "Trying to check {0} with keyLocator {1}",
      new Object[] { packetName.toUri(), keyLocatorName.toUri() });

    if (isForInterest != isForInterest_)
      throw new ValidatorConfigError
        ("Invalid packet type supplied ( " +
         (isForInterest ? "interest" : "data") + " != " +
         (isForInterest_ ? "interest" : "data") + ")");

    boolean hasPendingResult = false;
    for (int i = 0; i < checkers_.size(); ++i) {
      boolean result = checkers_.get(i).check
        (isForInterest, packetName, keyLocatorName, state);
      if (!result)
        return result;
      hasPendingResult = true;
    }

    return hasPendingResult;
  }

  /**
   * Create a rule from configuration section.
   * @param configSection The section containing the definition of the checker,
   * e.g. one of "validator.rule".
   * @return A new ConfigRule created from the configuration
   */
  public static ConfigRule
  create(BoostInfoTree configSection)
    throws ValidatorConfigError
  {
    // Get rule.id .
    String ruleId = configSection.getFirstValue("id");
    if (ruleId == null)
      throw new ValidatorConfigError("Expecting <rule.id>");

    // Get rule.for .
    String usage = configSection.getFirstValue("for");
    if (usage == null)
      throw new ValidatorConfigError("Expecting <rule.for> in rule: " + ruleId);

    boolean isForInterest;
    if (usage.equalsIgnoreCase("data"))
      isForInterest = false;
    else if (usage.equalsIgnoreCase("interest"))
      isForInterest = true;
    else
      throw new ValidatorConfigError
        ("Unrecognized <rule.for>: " + usage + " in rule: " + ruleId);

    ConfigRule rule = new ConfigRule(ruleId, isForInterest);

    // Get rule.filter(s)
    ArrayList<BoostInfoTree> filterList = configSection.get("filter");
    for (int i = 0; i < filterList.size(); ++i)
      rule.addFilter(ConfigFilter.create(filterList.get(i)));

    // Get rule.checker(s)
    ArrayList<BoostInfoTree> checkerList = configSection.get("checker");
    for (int i = 0; i < checkerList.size(); ++i)
      rule.addChecker(ConfigChecker.create(checkerList.get(i)));

    // Check other stuff.
    if (checkerList.size() == 0)
      throw new ValidatorConfigError
        ("No <rule.checker> is specified in rule: " + ruleId);

    return rule;
  }

  private final String id_;
  private final boolean isForInterest_;
  private final ArrayList<ConfigFilter> filters_ = new ArrayList<ConfigFilter>();
  private final ArrayList<ConfigChecker> checkers_ = new ArrayList<ConfigChecker>();
  private static final Logger logger_ =
    Logger.getLogger(ConfigRule.class.getName());
}
