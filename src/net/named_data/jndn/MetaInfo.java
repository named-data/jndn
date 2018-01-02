/**
 * Copyright (C) 2013-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
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

package net.named_data.jndn;
import net.named_data.jndn.util.ChangeCountable;

public class MetaInfo implements ChangeCountable {
  /**
   * Create a new MetaInfo with default values.
   */
  public MetaInfo()
  {
  }

  /**
   * Create a new MetaInfo with a copy of the fields in the given metaInfo.
   * @param metaInfo The MetaInfo to copy.
   */
  public MetaInfo(MetaInfo metaInfo)
  {
    type_ = metaInfo.type_;
    otherTypeCode_ = metaInfo.otherTypeCode_;
    freshnessPeriod_ = metaInfo.freshnessPeriod_;
    // Name.Component is read-only, so we don't need a deep copy.
    finalBlockId_ = metaInfo.finalBlockId_;
  }

  /**
   * Get the content type.
   * @return The content type enum value. If this is ContentType.OTHER_CODE,
   * then call getOtherTypeCode() to get the unrecognized content type code.
   */
  public final ContentType
  getType() { return type_; }

  /**
   * Get the content type code from the packet which is other than a recognized
   * ContentType enum value. This is only meaningful if getType() is
   * ContentType.OTHER_CODE.
   * @return The type code.
   */
  public final int
  getOtherTypeCode() { return otherTypeCode_; }

  public final double
  getFreshnessPeriod() { return freshnessPeriod_; }

  /**
   * @deprecated Use getFreshnessPeriod.
   */
  public final int
  getFreshnessSeconds()
  {
    return freshnessPeriod_ < 0 ? -1 : (int)Math.round(freshnessPeriod_ / 1000.0);
  }

  public final Name.Component
  getFinalBlockId() { return finalBlockId_; }

  /**
   * @deprecated Use getFinalBlockId.
   */
  public final Name.Component
  getFinalBlockID() { return getFinalBlockId(); }

  /**
   * Set the content type.
   * @param type The content type enum value. If the packet's content type is
   * not a recognized ContentType enum value, use ContentType.OTHER_CODE and
   * call setOtherTypeCode().
   */
  public final void
  setType(ContentType type)
  {
    type_ = type;
    ++changeCount_;
  }

  /**
   * Set the packet's content type code to use when the content type enum is
   * ContentType.OTHER_CODE. If the packet's content type code is a recognized
   * enum value, just call setType().
   * @param otherTypeCode The packet's unrecognized content type code, which
   * must be non-negative.
   */
  public final void
  setOtherTypeCode(int otherTypeCode)
  {
    if (otherTypeCode < 0)
      throw new Error("MetaInfo other type code must be non-negative");

    otherTypeCode_ = otherTypeCode;
    ++changeCount_;
  }

  public final void
  setFreshnessPeriod(double freshnessPeriod)
  {
    freshnessPeriod_ = freshnessPeriod;
    ++changeCount_;
  }

  /**
   * @deprecated Use setFreshnessPeriod.
   */
  public final void
  setFreshnessSeconds(int freshnessSeconds)
  {
    setFreshnessPeriod
      (freshnessSeconds < 0 ? -1.0 : (double)freshnessSeconds * 1000.0);
  }

  public final void
  setFinalBlockId(Name.Component finalBlockId)
  {
    finalBlockId_ = (finalBlockId == null ? new Name.Component() : finalBlockId);
    ++changeCount_;
  }

  /**
   * @deprecated Use setFinalBlockId.
   */
  public final void
  setFinalBlockID(Name.Component finalBlockId)
  {
    setFinalBlockId(finalBlockId);
  }

  /**
   * Get the change count, which is incremented each time this object is changed.
   * @return The change count.
   */
  public final long
  getChangeCount() { return changeCount_; }

  private ContentType type_ = ContentType.BLOB; /**< default is ContentType.BLOB. */
  private int otherTypeCode_ = -1;
  private double freshnessPeriod_ = -1; /**< -1 for none */
  private Name.Component finalBlockId_ = new Name.Component(); /**< size 0 for none */
  private long changeCount_ = 0;
}
