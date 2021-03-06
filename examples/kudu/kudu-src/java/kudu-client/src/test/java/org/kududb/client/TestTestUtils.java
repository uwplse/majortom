// Copyright (c) 2014, Cloudera, inc.
// Confidential Cloudera Information: Covered by NDA.
package org.kududb.client;

import org.junit.After;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Tests for non-trivial helper methods in TestUtils.
 */
public class TestTestUtils {

  public static final Logger LOG = LoggerFactory.getLogger(TestUtils.class);

  private Process proc;

  @After
  public void tearDown() {
    if (proc != null) {
      proc.destroy();
    }
  }

  /**
   * Starts a process that executes the "yes" command (which prints 'y' in a loop),
   * sends a SIGSTOP to the process, and ensures that SIGSTOP does indeed pause the process.
   * Afterwards, sends a SIGCONT to the process and ensures that the process resumes.
   */
  @Test(timeout = 2000)
  public void testPauseAndResume() throws Exception {
    ProcessBuilder processBuilder = new ProcessBuilder("yes");
    proc = processBuilder.start();
    LineCounterRunnable lineCounter = new LineCounterRunnable(proc.getInputStream());
    Thread thread = new Thread(lineCounter);
    thread.setDaemon(true);
    thread.start();
    TestUtils.pauseProcess(proc);
    long prevCount;
    do {
      prevCount = lineCounter.getCount();
      Thread.sleep(10);
    } while (prevCount != lineCounter.getCount());
    assertEquals(prevCount, lineCounter.getCount());
    TestUtils.resumeProcess(proc);
    do {
      prevCount = lineCounter.getCount();
      Thread.sleep(10);
    } while (prevCount == lineCounter.getCount());
    assertTrue(lineCounter.getCount() > prevCount);
  }

  /**
   * Counts the number of lines in a specified input stream.
   */
  static class LineCounterRunnable implements Runnable {
    private final AtomicLong counter;
    private final InputStream is;

    public LineCounterRunnable(InputStream is) {
      this.is = is;
      counter = new AtomicLong(0);
    }

    @Override
    public void run() {
      BufferedReader in = null;
      try {
        in = new BufferedReader(new InputStreamReader(is));
        while (in.readLine() != null) {
          counter.incrementAndGet();
        }
      } catch (Exception e) {
        LOG.error("Error while reading from the process", e);
      } finally {
        if (in != null) {
          try {
            in.close();
          } catch (IOException e) {
            LOG.error("Error closing the stream", e);
          }
        }
      }
    }

    public long getCount() {
      return counter.get();
    }
  }
}
