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
   * Override to submit a task to use the thread pool given to the constructor.
   * Also wrap the supplied onData, onTimeout and onNetworkNack callbacks in an
   * outer callback which submits a task to the thread pool to call the supplied
   * callback. See Face.expressInterest for calling details.
   */
  public long
  expressInterest
    (final Interest interest, OnData onData, OnTimeout onTimeout,
     final OnNetworkNack onNetworkNack, final WireFormat wireFormat)
     throws IOException
  {
    final long pendingInterestId = node_.getNextEntryId();

    // Wrap callbacks to submit to the thread pool.
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
              logger_.log(Level.SEVERE, "Error in onData", ex);
            }
          }
        });
      }
    };

    final OnTimeout finalOnTimeout = onTimeout;
    final OnTimeout onTimeoutSubmit = onTimeout == null ? null : new OnTimeout() {
      public void onTimeout(final Interest localInterest) {
        threadPool_.submit(new Runnable() {
          // Call the passed-in onTimeout.
          public void run() {
            // Need to catch and log exceptions at this async entry point.
            try {
              finalOnTimeout.onTimeout(localInterest);
            } catch (Throwable ex) {
              logger_.log(Level.SEVERE, "Error in onTimeout", ex);
            }
          }
        });
      }
    };

    final OnNetworkNack finalOnNetworkNack = onNetworkNack;
    final OnNetworkNack onNetworkNackSubmit =
        onNetworkNack == null ? null : new OnNetworkNack() {
      public void onNetworkNack
          (final Interest localInterest, final NetworkNack networkNack) {
        threadPool_.submit(new Runnable() {
          // Call the passed-in onData.
          public void run() {
            // Need to catch and log exceptions at this async entry point.
            try {
              finalOnNetworkNack.onNetworkNack(localInterest, networkNack);
            } catch (Throwable ex) {
              logger_.log(Level.SEVERE, "Error in onNetworkNack", ex);
            }
          }
        });
      }
    };

    // Make an interest copy as required by Node.expressInterest.
    final Interest interestCopy = new Interest(interest);
    threadPool_.submit(new Runnable() {
      public void run() {
        // Need to catch and log exceptions at this async entry point.
        try {
          node_.expressInterest
            (pendingInterestId, interestCopy, onDataSubmit, onTimeoutSubmit,
             onNetworkNackSubmit, wireFormat, ThreadPoolFace.this);
        } catch (Throwable ex) {
          logger_.log(Level.SEVERE, null, ex);
        }
      }
    });

    return pendingInterestId;
  }

  /**
   * Override to submit a task to use the thread pool given to the constructor.
   * Also wrap the supplied onData, onTimeout and onNetworkNack callbacks in an
   * outer callback which submits a task to the thread pool to call the supplied
   * callback. See Face.expressInterest for calling details. We make a separate
   * expressInterest overload for supplying a Name vs. Interest to avoid making
   * multiple copies of the Interest.
   */
  public long
  expressInterest
    (Name name, Interest interestTemplate, OnData onData, OnTimeout onTimeout,
     final OnNetworkNack onNetworkNack, final WireFormat wireFormat)
     throws IOException
  {
    final long pendingInterestId = node_.getNextEntryId();

    // Wrap callbacks to submit to the thread pool.
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
              logger_.log(Level.SEVERE, "Error in onData", ex);
            }
          }
        });
      }
    };

    final OnTimeout finalOnTimeout = onTimeout;
    final OnTimeout onTimeoutSubmit = onTimeout == null ? null : new OnTimeout() {
      public void onTimeout(final Interest localInterest) {
        threadPool_.submit(new Runnable() {
          // Call the passed-in onTimeout.
          public void run() {
            // Need to catch and log exceptions at this async entry point.
            try {
              finalOnTimeout.onTimeout(localInterest);
            } catch (Throwable ex) {
              logger_.log(Level.SEVERE, "Error in onTimeout", ex);
            }
          }
        });
      }
    };

    final OnNetworkNack finalOnNetworkNack = onNetworkNack;
    final OnNetworkNack onNetworkNackSubmit =
        onNetworkNack == null ? null : new OnNetworkNack() {
      public void onNetworkNack
          (final Interest localInterest, final NetworkNack networkNack) {
        threadPool_.submit(new Runnable() {
          // Call the passed-in onData.
          public void run() {
            // Need to catch and log exceptions at this async entry point.
            try {
              finalOnNetworkNack.onNetworkNack(localInterest, networkNack);
            } catch (Throwable ex) {
              logger_.log(Level.SEVERE, "Error in onNetworkNack", ex);
            }
          }
        });
      }
    };

    // Make an interest copy as required by Node.expressInterest.
    final Interest interestCopy = getInterestCopy(name, interestTemplate);
    threadPool_.submit(new Runnable() {
      public void run() {
        // Need to catch and log exceptions at this async entry point.
        try {
          node_.expressInterest
            (pendingInterestId, interestCopy, onDataSubmit, onTimeoutSubmit,
             onNetworkNackSubmit, wireFormat, ThreadPoolFace.this);
        } catch (Throwable ex) {
          logger_.log(Level.SEVERE, null, ex);
        }
      }
    });

    return pendingInterestId;
  }

  /**
   * Submit a task to the thread pool to register prefix with the connected
   * forwarder and call onInterest when a matching interest is received. To
   * register a prefix with NFD, you must first call setCommandSigningInfo.
   * @param prefix A Name for the prefix to register. This copies the Name.
   * @param onInterest If not null, this creates an interest filter from prefix
   * so that when an Interest is received which matches the filter, this calls
   * onInterest.onInterest(prefix, interest, face, interestFilterId, filter).
   * The onInterest callback should supply the Data with face.putData().
   * NOTE: You must not change the prefix or filter objects - if you need to
   * change them then make a copy.
   * If onInterest is null, it is ignored and you must call setInterestFilter.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onRegisterFailed If register prefix fails for any reason, this
   * calls onRegisterFailed.onRegisterFailed(prefix).
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onRegisterSuccess This calls
   * onRegisterSuccess.onRegisterSuccess(prefix, registeredPrefixId) when this
   * receives a success message from the forwarder. If onRegisterSuccess is null,
   * this does not use it. (The onRegisterSuccess parameter comes after
   * onRegisterFailed because it can be null or omitted, unlike onRegisterFailed.)
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param flags The flags for finer control of which interests are forwarded
   * to the application.
   * @param wireFormat A WireFormat object used to encode the message.
   * @return The registered prefix ID which can be used with
   * removeRegisteredPrefix.
   */
  public long
  registerPrefix
    (final Name prefix, OnInterestCallback onInterest,
     OnRegisterFailed onRegisterFailed, OnRegisterSuccess onRegisterSuccess,
     final ForwardingFlags flags, final WireFormat wireFormat)
    throws IOException, SecurityException
  {
    final long registeredPrefixId = node_.getNextEntryId();

    // Wrap callbacks to submit to the thread pool.
    final OnInterestCallback finalOnInterest = onInterest;
    final OnInterestCallback onInterestSubmit =
        onInterest == null ? null : new OnInterestCallback() {
      public void onInterest(final Name localPrefix, final Interest interest,
          final Face face, final long interestFilterId, final InterestFilter filter) {
        threadPool_.submit(new Runnable() {
          // Call the passed-in onInterest.
          public void run() {
            // Need to catch and log exceptions at this async entry point.
            try {
              finalOnInterest.onInterest
                (localPrefix, interest, face, interestFilterId, filter);
            } catch (Throwable ex) {
              logger_.log(Level.SEVERE, "Error in onInterest", ex);
            }
          }
        });
      }
    };

    final OnRegisterFailed finalOnRegisterFailed = onRegisterFailed;
    final OnRegisterFailed onRegisterFailedSubmit =
        new OnRegisterFailed() {
      public void onRegisterFailed(final Name localPrefix) {
        threadPool_.submit(new Runnable() {
          // Call the passed-in onRegisterFailed.
          public void run() {
            // Need to catch and log exceptions at this async entry point.
            try {
              finalOnRegisterFailed.onRegisterFailed(localPrefix);
            } catch (Throwable ex) {
              logger_.log(Level.SEVERE, "Error in onRegisterFailed", ex);
            }
          }
        });
      }
    };

    // Wrap callbacks to submit to the thread pool.
    final OnRegisterSuccess finalOnRegisterSuccess = onRegisterSuccess;
    final OnRegisterSuccess onRegisterSuccessSubmit =
        onRegisterSuccess == null ? null : new OnRegisterSuccess() {
      public void onRegisterSuccess(final Name localPrefix,
                                    final long localRegisteredPrefixId) {
        threadPool_.submit(new Runnable() {
          // Call the passed-in onRegisterSuccess.
          public void run() {
            // Need to catch and log exceptions at this async entry point.
            try {
              finalOnRegisterSuccess.onRegisterSuccess
                (localPrefix, localRegisteredPrefixId);
            } catch (Throwable ex) {
              logger_.log(Level.SEVERE, "Error in onRegisterSuccess", ex);
            }
          }
        });
      }
    };

    threadPool_.submit(new Runnable() {
      public void run() {
        // Need to catch and log exceptions at this async entry point.
        try {
          node_.registerPrefix
            (registeredPrefixId, prefix, onInterestSubmit, onRegisterFailedSubmit,
             onRegisterSuccessSubmit, flags, wireFormat, 
             commandKeyChain_, commandCertificateName_, ThreadPoolFace.this);
        } catch (Throwable ex) {
          logger_.log(Level.SEVERE, null, ex);
        }
      }
    });

    return registeredPrefixId;
  }

  /**
   * Submit a task to the thread pool to add an entry to the local interest
   * filter table to call the onInterest callback for a matching incoming
   * Interest. This method only modifies the library's local callback table and
   * does not register the prefix with the forwarder. It will always succeed.
   * To register a prefix with the forwarder, use registerPrefix.
   * @param filter The InterestFilter with a prefix and optional regex filter
   * used to match the name of an incoming Interest. This makes a copy of filter.
   * @param onInterest When an Interest is received which matches the filter,
   * this calls
   * onInterest.onInterest(prefix, interest, face, interestFilterId, filter).
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @return The interest filter ID which can be used with unsetInterestFilter.
   */
  public long
  setInterestFilter
    (final InterestFilter filter, final OnInterestCallback onInterest)
  {
    final long interestFilterId = node_.getNextEntryId();

        // Wrap callbacks to submit to the thread pool.
    final OnInterestCallback finalOnInterest = onInterest;
    final OnInterestCallback onInterestSubmit = new OnInterestCallback() {
      public void onInterest(final Name prefix, final Interest interest,
          final Face face, final long interestFilterId, final InterestFilter filter) {
        threadPool_.submit(new Runnable() {
          // Call the passed-in onInterest.
          public void run() {
            // Need to catch and log exceptions at this async entry point.
            try {
              finalOnInterest.onInterest
                (prefix, interest, face, interestFilterId, filter);
            } catch (Throwable ex) {
              logger_.log(Level.SEVERE, "Error in onInterest", ex);
            }
          }
        });
      }
    };

    threadPool_.submit(new Runnable() {
      public void run() {
        // Need to catch and log exceptions at this async entry point.
        try {
          node_.setInterestFilter
            (interestFilterId, filter, onInterestSubmit, ThreadPoolFace.this);
        } catch (Throwable ex) {
          logger_.log(Level.SEVERE, null, ex);
        }
      }
    });


    return interestFilterId;
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
