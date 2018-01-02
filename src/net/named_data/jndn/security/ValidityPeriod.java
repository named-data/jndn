/**
 * Copyright (C) 2016-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx src/security https://github.com/named-data/ndn-cxx
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
import net.named_data.jndn.Sha256WithEcdsaSignature;
import net.named_data.jndn.Sha256WithRsaSignature;
import net.named_data.jndn.Signature;
import net.named_data.jndn.util.ChangeCountable;
import net.named_data.jndn.util.Common;

/**
 * A ValidityPeriod is used in a Data packet's SignatureInfo and represents the
 * begin and end times of a certificate's validity period.
 */
public class ValidityPeriod implements ChangeCountable {
  /** Create a default ValidityPeriod where the period is not specified.
   */
  public ValidityPeriod() {}

  /**
   * Create a new ValidityPeriod with a copy of the fields in the given
   * validityPeriod.
   * @param validityPeriod The ValidityPeriod to copy.
   */
  public ValidityPeriod(ValidityPeriod validityPeriod)
  {
    notBefore_ = validityPeriod.notBefore_;
    notAfter_ = validityPeriod.notAfter_;
  }

  /**
   * Create a ValidityPeriod with the given period.
   * @param notBefore The beginning of the validity period range as milliseconds
   * since Jan 1, 1970 UTC. Note that this is rounded up to the nearest whole
   * second.
   * @param notAfter The end of the validity period range as milliseconds
   * since Jan 1, 1970 UTC. Note that this is rounded down to the nearest whole
   * second.
   */
  public ValidityPeriod(double notBefore, double notAfter)
  {
    setPeriod(notBefore, notAfter);
  }

  /**
   * Check if the period has been set.
   * @return True if the period has been set, false if the period is not
   * specified (after calling the default constructor or clear).
   */
  public final boolean
  hasPeriod()
  {
    return !(notBefore_ == Double.MAX_VALUE && notAfter_ == -Double.MAX_VALUE);
  }

  /**
   * Get the beginning of the validity period range.
   * @return The time as milliseconds since Jan 1, 1970 UTC.
   */
  public final double
  getNotBefore() { return notBefore_; }

  /**
   * Get the end of the validity period range.
   * @return The time as milliseconds since Jan 1, 1970 UTC.
   */
  public final double
  getNotAfter() { return notAfter_; }

  /** Reset to a default ValidityPeriod where the period is not specified.
   */
  public final void
  clear()
  {
    notBefore_ = Double.MAX_VALUE;
    notAfter_ = -Double.MAX_VALUE;
    ++changeCount_;
  }

  /**
   * Set the validity period.
   * @param notBefore The beginning of the validity period range as milliseconds
   * since Jan 1, 1970 UTC. Note that this is rounded up to the nearest whole
   * second.
   * @param notAfter The end of the validity period range as milliseconds
   * since Jan 1, 1970 UTC. Note that this is rounded down to the nearest whole
   * second.
   * @return This ValidityPeriod so that you can chain calls to update values.
   */
  public final ValidityPeriod
  setPeriod(double notBefore, double notAfter)
  {
    // Round up to the nearest second.
    notBefore_ = Math.round(Math.ceil(Math.round(notBefore) / 1000.0) * 1000.0);
    // Round down to the nearest second.
    notAfter_ = Math.round(Math.floor(Math.round(notAfter) / 1000.0) * 1000.0);
    ++changeCount_;

    return this;
  }

  /**
   * Check if this is the same validity period as other.
   * @param other The other ValidityPeriod to compare with.
   * @return true if the validity periods are equal.
   */
  public final boolean
  equals(ValidityPeriod other)
  {
    return notBefore_ == other.notBefore_ && notAfter_ == other.notAfter_;
  }

  public boolean
  equals(Object other)
  {
    if (!(other instanceof ValidityPeriod))
      return false;

    return equals((ValidityPeriod)other);
  }

  /**
   * Check if the time falls within the validity period.
   * @param time The time to check as milliseconds since Jan 1, 1970 UTC.
   * @return True if the beginning of the validity period is less than or equal
   * to time and time is less than or equal to the end of the validity period.
   */
  public final boolean
  isValid(double time)
  {
    return notBefore_ <= time && time <= notAfter_;
  }

  /**
   * Check if the current time falls within the validity period.
   * @return True if the beginning of the validity period is less than or equal
   * to the current time and the current time is less than or equal to the end
   * of the validity period.
   */
  public final boolean
  isValid()
  {
    // Round up to the nearest second like in setPeriod.
    return isValid(Math.round
      (Math.ceil(Math.round(Common.getNowMilliseconds()) / 1000.0) * 1000.0));
  }

  /**
   * If the signature is a type that has a ValidityPeriod (so that
   * getFromSignature will succeed), return true.
   * Note: This is a static method of ValidityPeriod instead of a method of
   * Signature so that the Signature base class does not need to be overloaded
   * with all the different kinds of information that various signature
   * algorithms may use.
   * @param signature An object of a subclass of Signature.
   * @return True if the signature is a type that has a ValidityPeriod,
   * otherwise false.
   */
  public static boolean
  canGetFromSignature(Signature signature)
  {
    return signature instanceof Sha256WithRsaSignature ||
           signature instanceof Sha256WithEcdsaSignature;
  }

  /**
   * If the signature is a type that has a ValidityPeriod, then return it.
   * Otherwise throw an error.
   * @param signature An object of a subclass of Signature.
   * @return The signature's ValidityPeriod. It is an error if signature doesn't
   * have a ValidityPeriod.
   */
  public static ValidityPeriod
  getFromSignature(Signature signature)
  {
    if (signature instanceof Sha256WithRsaSignature)
      return ((Sha256WithRsaSignature)signature).getValidityPeriod();
    else if (signature instanceof Sha256WithEcdsaSignature)
      return ((Sha256WithEcdsaSignature)signature).getValidityPeriod();
    else
      throw new Error
        ("ValidityPeriod.getFromSignature: Signature type does not have a ValidityPeriod");
  }

  /**
   * Get the change count, which is incremented each time this object is changed.
   * @return The change count.
   */
  public final long
  getChangeCount() { return changeCount_; }

  private double notBefore_ = Double.MAX_VALUE; // MillisecondsSince1970
  private double notAfter_ = -Double.MAX_VALUE; // MillisecondsSince1970
  private long changeCount_ = 0;
}
