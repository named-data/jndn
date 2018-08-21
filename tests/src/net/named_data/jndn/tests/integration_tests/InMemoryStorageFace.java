/**
 * Copyright (C) 2018 Regents of the University of California.
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

package src.net.named_data.jndn.tests.integration_tests;

import java.io.IOException;
import java.util.ArrayList;
import net.named_data.jndn.Data;
import net.named_data.jndn.Face;
import net.named_data.jndn.ForwardingFlags;
import net.named_data.jndn.Interest;
import net.named_data.jndn.InterestFilter;
import net.named_data.jndn.Name;
import net.named_data.jndn.OnData;
import net.named_data.jndn.OnInterestCallback;
import net.named_data.jndn.OnNetworkNack;
import net.named_data.jndn.OnRegisterFailed;
import net.named_data.jndn.OnRegisterSuccess;
import net.named_data.jndn.OnTimeout;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.encoding.WireFormat;
import net.named_data.jndn.encrypt.InMemoryStoragePersistent;
import net.named_data.jndn.impl.DelayedCallTable;

/**
 * InMemoryStorageFace extends Face to hold an InMemoryStoragePersistent and
 * use it in expressInterest to instantly reply to an Interest. It also allows
 * one simple call to registerPrefix to remember the OnInterestCallback. This
 * also keeps a local DelayedCallTable (to use for callLater) so that you can
 * call its setNowOffsetMilliseconds_ for testing.
 */
public class InMemoryStorageFace extends Face {
  /**
   * Create an InMemoryStorageFace to use the given storage.
   * @param storage The InMemoryStoragePersistent used by expressInterest. If
   * the Data packet for the Interest is found, expressInterest immediately
   * calls onData, otherwise it immediately calls onTimeout.
   */
  public InMemoryStorageFace(InMemoryStoragePersistent storage)
  {
    super("localhost");

    storage_ = storage;
  }

  public long
  expressInterest
    (Interest interest, OnData onData, OnTimeout onTimeout,
     OnNetworkNack onNetworkNack, WireFormat wireFormat) throws IOException
  {
    sentInterests_.add(new Interest(interest));

    Data data = storage_.find(interest);
    if (data != null) {
      sentData_.add(new Data(data));
      onData.onData(interest, data);
    }
    else
      onTimeout.onTimeout(interest);

    return 0;
  }

  public long
  registerPrefix
    (Name prefix, OnInterestCallback onInterest,
     OnRegisterFailed onRegisterFailed, OnRegisterSuccess onRegisterSuccess,
     ForwardingFlags flags, WireFormat wireFormat)
    throws IOException, net.named_data.jndn.security.SecurityException
  {
    // Just save the callback. Assume there should be only one.
    if (registeredOnInterest_ != null)
      throw new Error("InMemoryStorageFace: Can only call registerPrefix once.");

    registeredPrefix_ = new Name(prefix);
    registeredOnInterest_ = onInterest;

    if (onRegisterSuccess != null)
      onRegisterSuccess.onRegisterSuccess(prefix, 0);
    return 0;
  }

  public void
  putData(Data data, WireFormat wireFormat) throws IOException
  {
    sentData_.add(new Data(data));
  }

  public void
  callLater(double delayMilliseconds, Runnable callback)
  {
    delayedCallTable_.callLater(delayMilliseconds, callback);
  }

  public void
  processEvents() throws IOException, EncodingException
  {
    delayedCallTable_.callTimedOut();
  }

  /**
   * If registerPrefix has been called and the Interest matches the saved
   * registeredPrefix_, call the saved registeredOnInterest_.
   * @param interest The Interest to receive and possibly call
   * registeredOnInterest_.
   */
  public void
  receive(Interest interest)
  {
    if (registeredOnInterest_ == null ||
        !registeredPrefix_.isPrefixOf(interest.getName()))
      return;

    registeredOnInterest_.onInterest
      (registeredPrefix_, interest, this, 0,
       new InterestFilter(registeredPrefix_));
  }

  public final ArrayList<Interest> sentInterests_ = new ArrayList<Interest>();
  public final ArrayList<Data> sentData_ = new ArrayList<Data>();

  private Name registeredPrefix_ = new Name();
  private OnInterestCallback registeredOnInterest_ = null;
  // Use delayedCallTable_ here so that we can call setNowOffsetMilliseconds_().
  public final DelayedCallTable delayedCallTable_ = new DelayedCallTable();
  private final InMemoryStoragePersistent storage_;
}
