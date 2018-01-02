/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/v2/validation-error.cpp
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

/**
 * A ValidationError holds an error code and an optional detailed error message.
 */
public class ValidationError {
  public static final int NO_ERROR =                    0;
  public static final int INVALID_SIGNATURE =           1;
  public static final int NO_SIGNATURE =                2;
  public static final int CANNOT_RETRIEVE_CERTIFICATE = 3;
  public static final int EXPIRED_CERTIFICATE =         4;
  public static final int LOOP_DETECTED =               5;
  public static final int MALFORMED_CERTIFICATE =       6;
  public static final int EXCEEDED_DEPTH_LIMIT =        7;
  public static final int INVALID_KEY_LOCATOR =         8;
  public static final int POLICY_ERROR =                9;
  public static final int IMPLEMENTATION_ERROR =        255;
  // Custom error codes should use >= USER_MIN.
  public static final int USER_MIN =                    256;

  /**
   * Create a new ValidationError for the given code.
   * @param code The code which is one of the standard error codes such as
   * INVALID_SIGNATURE, or a custom code if greater than or equal to USER_MIN.
   * @param info The error message.
   */
  public ValidationError(int code, String info)
  {
    code_ = code;
    info_ = info;
  }

  /**
   * Create a new ValidationError for the given code and an empty error message.
   * @param code The code which is one of the standard error codes such as
   * INVALID_SIGNATURE, or a custom code if greater than or equal to USER_MIN.
   */
  public ValidationError(int code)
  {
    code_ = code;
    info_ = "";
  }

  /**
   * Get the error code given to the constructor.
   * @return The error code which is one of the standard error codes such as
   * INVALID_SIGNATURE, or a custom code if greater than or equal to USER_MIN.
   */
  public final int
  getCode() { return code_; }

  /**
   * Get the error message given to the constructor.
   * @return The error message, or "" if none.
   */
  public final String
  getInfo() { return info_; }

  /**
   * Get a string representation of this ValidationError.
   * @return The string representation.
   */
  public String toString()
  {
    String result;

    if (code_ == NO_ERROR)
      result = "No error";
    else if (code_ == INVALID_SIGNATURE)
      result = "Invalid signature";
    else if (code_ == NO_SIGNATURE)
      result = "Missing signature";
    else if (code_ == CANNOT_RETRIEVE_CERTIFICATE)
      result = "Cannot retrieve certificate";
    else if (code_ == EXPIRED_CERTIFICATE)
      result = "Certificate expired";
    else if (code_ == LOOP_DETECTED)
      result = "Loop detected in certification chain";
    else if (code_ == MALFORMED_CERTIFICATE)
      result = "Malformed certificate";
    else if (code_ == EXCEEDED_DEPTH_LIMIT)
      result = "Exceeded validation depth limit";
    else if (code_ == INVALID_KEY_LOCATOR)
      result = "Key locator violates validation policy";
    else if (code_ == POLICY_ERROR)
      result = "Validation policy error";
    else if (code_ == IMPLEMENTATION_ERROR)
      result = "Internal implementation error";
    else if (code_ >= USER_MIN)
      result = "Custom error code " + code_;
    else
      result = "Unrecognized error code " + code_;

    if (info_.length() > 0)
      result += " (" + info_ + ")";

    return result;
  }

  private int code_;
  private String info_;
}
