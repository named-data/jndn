/**
 * Copyright (C) 2015-2016 Regents of the University of California.
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

import java.io.IOException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.named_data.jndn.encoding.WireFormat;
import net.named_data.jndn.transport.Transport;

/**
 * ThreadPoolFace extends Face to provide the main methods for NDN communication
 * by submitting to a given ScheduledExecutorService thread pool. This also
 * uses the thread pool to schedule the interest timeouts.
 */
public class ThreadPoolFace extends Face {
  /**
   * Create a new ThreadPoolFace for communication with an NDN hub with the given
   * Transport object and connectionInfo.
   * @param threadPool The thread pool used to submit method calls such as
   * expressInterest and the related callbacks such as onData. The thread pool
   * is also used to schedule the interest timeouts.
   * @param transport A Transport object used for communication. If you do not
   * want to call processEvents, then the transport should be an async transport
   * like AsyncTcpTransport, in which case the transport should use the same
   * ioService.
   * @param connectionInfo A Transport.ConnectionInfo to be used to connect to
   * the transport.
   */
  public ThreadPoolFace
    (ScheduledExecutorService threadPool, Transport transport,
     Transport.ConnectionInfo connectionInfo)
  {
    super(transport, connectionInfo);
    threadPool_ = threadPool;
  }

  /**
   * Submit a task to the thread pool to send the Interest through the
   * transport, read the entire response and call onData(interest, data).
   * @param interest The Interest to send.  This copies the Interest.
   * @param onData  When a matching data packet is received, this calls
   * onData.onData(interest, data) where interest is the interest given to
   * expressInterest and data is the received Data object. NOTE: You must not
   * change the interest object - if you need to change it then make a copy.
   * This wraps the callback to submit it to the thread pool.
   * @param onTimeout If the interest times out according to the interest
   * lifetime, this calls onTimeout.onTimeout(interest) where interest is the
   * interest given to expressInterest. If onTimeout is null, this does not use
   * it. This wraps the callback to submit it to the thread pool.
   * @param wireFormat A WireFormat object used to encode the message.
   * @return The pending interest ID which can be used with
   * removePendingInterest.
   */
  public long
  expressInterest
    (final Interest interest, OnData onData, OnTimeout onTimeout,
     final WireFormat wireFormat) throws IOException
  {
    final long pendingInterestId = node_.getNextEntryId();

    // Wrap onData and onTimeout to submit to the thread pool.
    final OnData finalOnData = onData;
    final OnData onDataSubmit = new OnData() {
      public void onData(final Interest localInterest, final Data data) {
        threadPool_.submit(new Runnable() {
          // Call the passed-in onData.
          public void run() {
            // Need to catch and log exceptions at this async entry point.
            try {
              finalOnData.onData(localInterest, data);
            } catch (Throwable ex) {
              logger_.log(Level.SEVERE, null, ex);
            }
          }
        });
      }
    };

    final OnTimeout finalOnTimeout = onTimeout;
    final OnTimeout onTimeoutSubmit = onTimeout == null ? null :
      new OnTimeout() {
        public void onTimeout(final Interest localInterest) {
          threadPool_.submit(new Runnable() {
            // Call the passed-in onTimeout.
            public void run() {
              // Need to catch and log exceptions at this async entry point.
              try {
                finalOnTimeout.onTimeout(localInterest);
              } catch (Throwable ex) {
                logger_.log(Level.SEVERE, null, ex);
              }
            }
          });
        }
      };

    threadPool_.submit(new Runnable() {
      public void run() {
        // Need to catch and log exceptions at this async entry point.
        try {
          node_.expressInterest
            (pendingInterestId, interest, onDataSubmit, onTimeoutSubmit,
             wireFormat, ThreadPoolFace.this);
        } catch (Throwable ex) {
          logger_.log(Level.SEVERE, null, ex);
        }
      }
    });

    return pendingInterestId;
  }

  /**
   * Override to schedule in the thread pool to call callback.run() after the
   * given delay. Even though this is public, it is not part of the public API
   * of Face.
   * @param delayMilliseconds The delay in milliseconds.
   * @param callback This calls callback.run() after the delay.
   */
  public void
  callLater(double delayMilliseconds, final Runnable callback)
  {
    threadPool_.schedule
      (new Runnable() {
        public void run() {
          // Need to catch and log exceptions at this async entry point.
          try {
            callback.run();
          } catch (Throwable ex) {
            logger_.log(Level.SEVERE, null, ex);
          }
        }
       },
       (long)delayMilliseconds, TimeUnit.MILLISECONDS);
  }

  private final ScheduledExecutorService threadPool_;
  private static final Logger logger_ = Logger.getLogger
    (ThreadPoolFace.class.getName());
}
