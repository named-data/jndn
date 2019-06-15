/**
 * Copyright (C) 2015-2019 Regents of the University of California.
 *
 * @author: Ritik Kumar <rkumar1@cs.iitr.ac.in>
 * @author: From ndn-cxx util/segment-fetcher https://github.com/named-data/ndn-cxx
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

/**
 * RTTEstimator is a utility class which uses Round-Trip times to calculates retransmission timeout
 *
 * This class implements the "Mean-Deviation" RTT estimator, as discussed in RFC 6298,
 * with the modifications to RTO calculation described in RFC 7323 Appendix G.
 */

public class RttEstimator {

    public static class Options {

        /** weight of exponential moving average for smoothed RTT
         */
        public double alpha = 0.125;
        /** weight of exponential moving average for RTT variation
         */
        public double beta = 0.25;
        /** initial RTO value in milliseconds
         */
        public double initialRto = 1000.0;
        /** lower bound of RTO in milliseconds
         */
        public double minRto = 200.0;
        /** upper bound of RTO in milliseconds
         */
        public double maxRto = 60000.0;
        /** RTT vaiation multiplier used when calculating RTO
         */
        public int k = 4;
        /** RTO multiplier used in backoff operation
         */
        public int rtoBackoffMultiplier = 2;

    }

    /**
     * Creates an RTT estimator.
     *
     * Configures the RTT estimator with the default parameters.
     */
    public RttEstimator() {
        this(new Options());
    }

    /**
     * Create an RTT Estimator
     *
     * Configures the RTT Estimator
     * @param options_ Parameters for configuration.
     */
    RttEstimator(Options options_) {
        this.options_ = options_;
        rto_ = options_.initialRto;
    }

    /**
     * Record a new RTT measurement.
     *
     * @param rtt the sampled RTT
     * @param nExpectedSamples number of expected samples, must be greater than 0.
     *        It should be set to the current number of in-flight Interests. Please
     *        refer to Appendix G of RFC 7323 for details.
     * NOTE: Do not call this function with RTT samples from retransmitted Interests
     *       (per Karn's algorithm).
     */
    void
    addMeasurement(double rtt, int nExpectedSamples) {
        if (nRttSamples_ == 0) { // first measurement
            sRtt_ = rtt;
            rttVar_ = sRtt_ / 2;
        }
        else {
            double alpha = options_.alpha / nExpectedSamples;
            double beta = options_.beta / nExpectedSamples;
            rttVar_ = (1 - beta) * rttVar_ + beta * Math.abs(sRtt_ - rtt);
            sRtt_ = (1 - alpha) * sRtt_ + alpha * rtt;
        }

        rto_ = sRtt_ + options_.k * rttVar_;
        rto_ = clamp(rto_, options_.minRto, options_.maxRto);

        rttAvg_ = (nRttSamples_ * rttAvg_ + rtt) / (nRttSamples_ + 1);
        rttMax_ = Math.max(rtt, rttMax_);
        rttMin_ = Math.max(rtt, rttMin_);
        nRttSamples_++;
    }

    /**
     * Backoff RTO by a factor of Options.rtoBackoffMultiplier.
     */
    void
    backoffRto()
    {
        rto_ = clamp(rto_ * options_.rtoBackoffMultiplier,
                options_.minRto, options_.maxRto);
    }


    private static double clamp
    (double val, double min, double max) {
        return Math.max(min, Math.min(max, val));
    }

    /**
     * Returns the estimated RTO value.
     */
    double
    getEstimatedRto()
    {
        return rto_;
    }

    /**
     * Returns the minimum RTT observed.
     */
    double
    getMinRtt()
    {
        return rttMin_;
    }

    /**
     * Returns the maximum RTT observed.
     */
    double
    getMaxRtt()
    {
        return rttMax_;
    }

    /**
     * Returns the average RTT.
     */
    double
    getAvgRtt()
    {
        return rttAvg_;
    }

    private final Options options_;
    private double sRtt_ = Double.NaN; // smoothed round-trip time
    private double rttVar_ =  Double.NaN; // round-trip time variation
    private double rto_ = 0; // retransmission timeout
    private double rttMin_ = Double.MAX_VALUE;
    private double rttMax_ = Double.MIN_VALUE;
    private double rttAvg_ = 0.0;
    private long nRttSamples_ = 0; // number of RTT samples
}
