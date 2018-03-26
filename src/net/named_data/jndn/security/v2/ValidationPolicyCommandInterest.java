/**
 * Copyright (C) 2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/v2/validation-policy-command-interest.cpp
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

import java.util.ArrayList;
import net.named_data.jndn.Data;
import net.named_data.jndn.Interest;
import net.named_data.jndn.Name;
import net.named_data.jndn.security.CommandInterestSigner;
import net.named_data.jndn.security.ValidatorConfigError;
import net.named_data.jndn.util.Common;

/**
 * ValidationPolicyCommandInterest extends ValidationPolicy as a policy for
 * stop-and-wait command Interests. See:
 * https://redmine.named-data.net/projects/ndn-cxx/wiki/CommandInterest
 *
 * This policy checks the timestamp field of a stop-and-wait command Interest.
 * Signed Interest validation and Data validation requests are delegated to an
 * inner policy.
 */
public class ValidationPolicyCommandInterest extends ValidationPolicy {
  public static class Options {
    /**
     * Create a ValidationPolicyCommandInterest.Options with the values.
     * @param gracePeriod See below for description.
     * @param maxRecords See below for description.
     * @param recordLifetime See below for description.
     */
    public Options(double gracePeriod, int maxRecords, double recordLifetime)
    {
      gracePeriod_ = gracePeriod;
      maxRecords_ = maxRecords;
      recordLifetime_ = recordLifetime;
    }

    /**
     * Create a ValidationPolicyCommandInterest.Options with the values and
     * where recordLifetime is 1 hour.
     * @param gracePeriod See below for description.
     * @param maxRecords See below for description.
     */
    public Options(double gracePeriod, int maxRecords)
    {
      gracePeriod_ = gracePeriod;
      maxRecords_ = maxRecords;
      recordLifetime_ = 3600 * 1000.0;
    }

    /**
     * Create a ValidationPolicyCommandInterest.Options with the gracePeriod and
     * where maxRecords is 1000 and recordLifetime is 1 hour.
     * @param gracePeriod See below for description.
     */
    public Options(double gracePeriod)
    {
      gracePeriod_ = gracePeriod;
      maxRecords_ = 1000;
      recordLifetime_ = 3600 * 1000.0;
    }

    /**
     * Create a ValidationPolicyCommandInterest.Options where gracePeriod is 2
     * minutes, maxRecords is 1000 and recordLifetime is 1 hour.
     */
    public Options()
    {
      gracePeriod_ = 2 * 60 * 1000.0;
      maxRecords_ = 1000;
      recordLifetime_ = 3600 * 1000.0;
    }

    /**
     * Create a ValidationPolicyCommandInterest.Options from the given options.
     * @param options The ValidationPolicyCommandInterest.Options with values to
     * copy.
     */
    public Options(Options options)
    {
      gracePeriod_ = options.gracePeriod_;
      maxRecords_ = options.maxRecords_;
      recordLifetime_ = options.recordLifetime_;
    }

    /**
     * gracePeriod is the tolerance of the initial timestamp in milliseconds.
     *
     * A stop-and-wait command Interest is considered "initial" if the validator
     * has not recorded the last timestamp from the same public key, or when
     * such knowledge has been erased. For an initial command Interest, its
     * timestamp is compared to the current system clock, and the command
     * Interest is rejected if the absolute difference is greater than the grace
     * interval.
     *
     * This should be positive. Setting this option to 0 or negative causes the
     * validator to require exactly the same timestamp as the system clock,
     * which most likely rejects all command Interests.
     */
    public double gracePeriod_;

    /**
     * maxRecords is the maximum number of distinct public keys of which to
     * record the last timestamp.
     *
     * The validator records the last timestamps for every public key. For a
     * subsequent command Interest using the same public key, its timestamp is
     * compared to the last timestamp from that public key, and the command
     * Interest is rejected if its timestamp is less than or equal to the
     * recorded timestamp.
     *
     * This option limits the number of distinct public keys being tracked. If
     * the limit is exceeded, then the oldest record is deleted.
     *
     * Setting this option to -1 allows tracking unlimited public keys. Setting
     * this option to 0 disables using last timestamp records and causes every
     * command Interest to be processed as initial.
     */
    public int maxRecords_;

    /**
     * recordLifetime is the maximum lifetime of a last timestamp record in
     * milliseconds.
     *
     * A last timestamp record expires and can be deleted if it has not been
     * refreshed within this duration. Setting this option to 0 or negative
     * makes last timestamp records expire immediately and causes every command
     * Interest to be processed as initial.
     */
    public double recordLifetime_;
  }

  /**
   * Create a ValidationPolicyCommandInterest.
   * @param innerPolicy a ValidationPolicy for signed Interest signature
   * validation and Data validation. This must not be null.
   * @param options The stop-and-wait command Interest validation options.
   * @throws AssertionError if innerPolicy is null.
   */
  public ValidationPolicyCommandInterest
    (ValidationPolicy innerPolicy, Options options)
  {
    // Copy the Options.
    options_ = new Options(options);

    if (innerPolicy == null)
      throw new AssertionError("inner policy is missing");

    setInnerPolicy(innerPolicy);

    if (options_.gracePeriod_ < 0.0)
      options_.gracePeriod_ = 0.0;
  }

  /**
   * Create a ValidationPolicyCommandInterest with default Options.
   * @param innerPolicy a ValidationPolicy for signed Interest signature
   * validation and Data validation. This must not be null.
   * @throws AssertionError if innerPolicy is null.
   */
  public ValidationPolicyCommandInterest(ValidationPolicy innerPolicy)
  {
    options_ = new Options();

    if (innerPolicy == null)
      throw new AssertionError("inner policy is missing");

    setInnerPolicy(innerPolicy);
  }

  public void
  checkPolicy
    (Data data, ValidationState state, ValidationContinuation continueValidation)
    throws CertificateV2.Error, ValidatorConfigError
  {
    getInnerPolicy().checkPolicy(data, state, continueValidation);
  }

  public void
  checkPolicy
    (Interest interest, ValidationState state,
     ValidationContinuation continueValidation)
    throws CertificateV2.Error, ValidatorConfigError
  {
    Name[] keyName = new Name[1];
    double[] timestamp = new double[1];
    if (!parseCommandInterest(interest, state, keyName, timestamp))
      return;

    if (!checkTimestamp(state, keyName[0], timestamp[0]))
      return;

    getInnerPolicy().checkPolicy(interest, state, continueValidation);
  }

  /**
   * Set the offset when insertNewRecord() and cleanUp() get the current time,
   * which should only be used for testing.
   * @param nowOffsetMilliseconds The offset in milliseconds.
   */
  public final void
  setNowOffsetMilliseconds_(double nowOffsetMilliseconds)
  {
    nowOffsetMilliseconds_ = nowOffsetMilliseconds;
  }

  private static class LastTimestampRecord
  {
    public LastTimestampRecord
      (Name keyName, double timestamp, double lastRefreshed)
    {
      // Copy the Name.
      keyName_ = new Name(keyName);
      timestamp_ = timestamp;
      lastRefreshed_ = lastRefreshed;
    }

    public Name keyName_;
    public double timestamp_;
    public double lastRefreshed_;
  };

  private void
  cleanUp()
  {
    // nowOffsetMilliseconds_ is only used for testing.
    double now = Common.getNowMilliseconds() + nowOffsetMilliseconds_;
    double expiring = now - options_.recordLifetime_;

    while ((container_.size() > 0 && container_.get(0).lastRefreshed_ <= expiring) ||
           (options_.maxRecords_ >= 0 && container_.size() > options_.maxRecords_))
      container_.remove(0);
  }

  /**
   * Get the keyLocatorName and timestamp from the command interest.
   * @param interest The Interest to parse.
   * @param state On error, this calls state.fail and returns false.
   * @param keyLocatorName Set keyLocatorName[0] to the KeyLocator name.
   * @param timestamp Set timestamp[0] to the timestamp as milliseconds since
   * Jan 1, 1970 UTC.
   * @return On success, return true. On error, call state.fail and return false.
   */
  private static boolean
  parseCommandInterest
    (Interest interest, ValidationState state, Name[] keyLocatorName,
     double[] timestamp)
  {
    keyLocatorName[0] = new Name();
    timestamp[0] = 0;

    Name name = interest.getName();
    if (name.size() < CommandInterestSigner.MINIMUM_SIZE) {
      state.fail(new ValidationError(ValidationError.POLICY_ERROR,
        "Command interest name `" + interest.getName().toUri() + "` is too short"));
      return false;
    }

    timestamp[0] = name.get(CommandInterestSigner.POS_TIMESTAMP).toNumber();

    keyLocatorName[0] = getKeyLocatorName(interest, state);
    if (state.isOutcomeFailed())
      // Already failed.
      return false;

    return true;
  }

  /**
   *
   * @param state On error, this calls state.fail and returns false.
   * @param keyName The key name.
   * @param timestamp The timestamp as milliseconds since Jan 1, 1970 UTC.
   * @return On success, return true. On error, call state.fail and return false.
   */
  private boolean
  checkTimestamp(ValidationState state, final Name keyName, final double timestamp)
  {
    cleanUp();

    // nowOffsetMilliseconds_ is only used for testing.
    double now = Common.getNowMilliseconds() + nowOffsetMilliseconds_;
    if (timestamp < now - options_.gracePeriod_ ||
        timestamp > now + options_.gracePeriod_) {
      state.fail(new ValidationError(ValidationError.POLICY_ERROR,
        "Timestamp is outside the grace period for key " + keyName.toUri()));
      return false;
    }

    int index = findByKeyName(keyName);
    if (index >= 0) {
      if (timestamp <= container_.get(index).timestamp_) {
        state.fail(new ValidationError(ValidationError.POLICY_ERROR,
          "Timestamp is reordered for key " + keyName.toUri()));
        return false;
      }
    }

    InterestValidationState interestState = (InterestValidationState)state;
    interestState.addSuccessCallback
      (new InterestValidationSuccessCallback() {
        public void successCallback(Interest interest) {
          insertNewRecord(interest, keyName, timestamp);
        }
      });

    return true;
  }

  private void
  insertNewRecord(Interest interest, Name keyName, double timestamp)
  {
    // nowOffsetMilliseconds_ is only used for testing.
    double now = Common.getNowMilliseconds() + nowOffsetMilliseconds_;
    LastTimestampRecord newRecord = new LastTimestampRecord
      (keyName, timestamp, now);

    int index = findByKeyName(keyName);
    if (index >= 0)
      // Remove the existing record so we can move it to the end.
      container_.remove(index);

    container_.add(newRecord);
  }

  /**
   * Find the record in container_ which has the keyName.
   * @param keyName The key name to search for.
   * @return The index in container_ of the record, or -1 if not found.
   */
  int
  findByKeyName(Name keyName)
  {
    for (int i = 0; i < container_.size(); ++i) {
      if (container_.get(i).keyName_.equals(keyName))
        return i;
    }

    return -1;
  }

  private final Options options_;
  private final ArrayList<LastTimestampRecord> container_ =
    new ArrayList<LastTimestampRecord>();
  private double nowOffsetMilliseconds_ = 0;
  // This is to force an import of net.named_data.jndn.util.
  private static Common dummyCommon_ = new Common();
}
