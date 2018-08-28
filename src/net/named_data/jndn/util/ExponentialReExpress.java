/**
 * Copyright (C) 2017-2018 Regents of the University of California.
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

package net.named_data.jndn.util;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.named_data.jndn.Face;
import net.named_data.jndn.Interest;
import net.named_data.jndn.OnData;
import net.named_data.jndn.OnTimeout;

/**
 * An ExponentialReExpress uses an internal onTimeout to express the interest
 * again with double the interestLifetime. See
 * ExponentialReExpress.makeOnTimeout.
 */
public class ExponentialReExpress implements OnTimeout {
  /**
   * Return an OnTimeout object to use in expressInterest for onTimeout which
   * will express the interest again with double the interestLifetime. If the
   * interesLifetime goes over maxInterestLifetime (see below), then call the
   * provided onTimeout. If a Data packet is received, this calls the provided
   * onData.
   * @param face This calls face.expressInterest.
   * @param onData When a matching data packet is received, this calls
   * onData.onData(interest, data) where interest is the interest given to
   * expressInterest and data is the received Data object. This is normally the
   * same onData you initially passed to expressInterest.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onTimeout If the interesLifetime goes over maxInterestLifetime, this
   * calls onTimeout.onTimeout(interest). However, if onTimeout is null, this
   * does not use it.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param maxInterestLifetime The maximum lifetime in milliseconds for
   * re-expressed interests.
   * @return The OnTimeout object to pass to expressInterest.
   */
  public static OnTimeout
  makeOnTimeout
    (Face face, OnData onData, OnTimeout onTimeout, double maxInterestLifetime)
  {
    return new ExponentialReExpress
      (face, onData, onTimeout, maxInterestLifetime);
  }

  /**
   * Return an OnTimeout object to use in expressInterest for onTimeout which
   * will express the interest again with double the interestLifetime. If the
   * interesLifetime goes over 16000 milliseconds, then call the provided
   * onTimeout. If a Data packet is received, this calls the provided onData.
   * @param face This calls face.expressInterest.
   * @param onData When a matching data packet is received, this calls
   * onData.onData(interest, data) where interest is the interest given to
   * expressInterest and data is the received Data object. This is normally the
   * same onData you initially passed to expressInterest.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onTimeout If the interesLifetime goes over 16000 milliseconds, this
   * calls onTimeout.onTimeout(interest). However, if onTimeout is null, this
   * does not use it.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @return The OnTimeout object to pass to expressInterest.
   */
  public static OnTimeout
  makeOnTimeout(Face face, OnData onData, OnTimeout onTimeout)
  {
    return makeOnTimeout(face, onData, onTimeout, 16000.0);
  }

  /**
   * Create a new ExponentialReExpress where onTimeout expresses the interest
   * again with double the interestLifetime. If the interesLifetime goes over
   * maxInterestLifetime, then call the given onTimeout. If this internally
   * gets onData, just call the given onData.
   */
  private ExponentialReExpress
    (Face face, OnData onData, OnTimeout onTimeout, double maxInterestLifetime)
  {
    face_ = face;
    callerOnData_ = onData;
    callerOnTimeout_ = onTimeout;
    maxInterestLifetime_ = maxInterestLifetime;
  }

  public void
  onTimeout(Interest interest)
  {
    double interestLifetime = interest.getInterestLifetimeMilliseconds();
    if (interestLifetime < 0) {
      // Can't re-express.
      if (callerOnTimeout_ != null) {
        try {
          callerOnTimeout_.onTimeout(interest);
        } catch (Throwable ex) {
          logger_.log(Level.SEVERE, "Error in onTimeout", ex);
        }
      }
      return;
    }

    double nextInterestLifetime = interestLifetime * 2;
    if (nextInterestLifetime > maxInterestLifetime_) {
      if (callerOnTimeout_ != null) {
        try {
          callerOnTimeout_.onTimeout(interest);
        } catch (Throwable ex) {
          logger_.log(Level.SEVERE, "Error in onTimeout", ex);
        }
      }
      return;
    }

    Interest nextInterest = new Interest(interest);
    nextInterest.setInterestLifetimeMilliseconds(nextInterestLifetime);
    logger_.log(Level.FINE,
      "ExponentialReExpress: Increasing interest lifetime from {0} to {1} ms. Re-express interest {2}",
      new Object[] { interestLifetime,  nextInterestLifetime,
        nextInterest.getName().toUri()});
    try {
      face_.expressInterest(nextInterest, callerOnData_, this);
    } catch (IOException ex) {
      logger_.log(Level.SEVERE, null, ex);
    }
  }

  private final Face face_;
  private final OnData callerOnData_;
  private final OnTimeout callerOnTimeout_;
  private final double maxInterestLifetime_;
  private static final Logger logger_ =
    Logger.getLogger(ExponentialReExpress.class.getName());
}
