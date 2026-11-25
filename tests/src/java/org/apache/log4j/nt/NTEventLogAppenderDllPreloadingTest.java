/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.log4j.nt;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;


/**
 * Regression test for sonatype-2010-0053, DLL preloading in
 * {@link NTEventLogAppender}.
 *
 * <p>The appender resolved its native library only through
 * {@link System#loadLibrary(String)}, so a library planted in any directory
 * of the native library search path (on Windows this includes the current
 * working directory) was loaded in place of the genuine one.
 *
 * <p>This test must run in its own JVM whose <code>java.library.path</code>
 * is the single directory named by the
 * <code>log4j.test.nteventlog.planted.dir</code> system property, standing in
 * for such an attacker controlled location (see the
 * NTEventLogAppenderDllPreloading target of tests/build.xml). It plants
 * loadable libraries there under the names the appender looks up, configures
 * <code>log4j.nteventlog.dll.path</code> with the absolute path of the
 * trusted library and checks, through <code>/proc/self/maps</code>, that the
 * trusted library was mapped into the process and the planted ones never were.
 *
 * <p>Once the appender class is initialized, the
 * {@link NTEventLogAppenderDllPathTest} cases run in the same JVM.
 */
public class NTEventLogAppenderDllPreloadingTest extends TestCase {

  private static final String DLL_PATH_PROPERTY = "log4j.nteventlog.dll.path";

  private static final String PLANTED_DIR_PROPERTY =
      "log4j.test.nteventlog.planted.dir";

  public NTEventLogAppenderDllPreloadingTest(final String name) {
    super(name);
  }

  public static Test suite() {
    TestSuite suite = new TestSuite();
    suite.addTest(new NTEventLogAppenderDllPreloadingTest(
        "testConfiguredDllPathIsLoadedInsteadOfPlantedLibrary"));
    suite.addTestSuite(NTEventLogAppenderDllPathTest.class);
    return suite;
  }

  /**
   * With log4j.nteventlog.dll.path pointing to the trusted library, loading
   * the appender must not pick up libraries planted on the search path.
   */
  public void testConfiguredDllPathIsLoadedInsteadOfPlantedLibrary()
      throws Exception {
    String plantedDirName = System.getProperty(PLANTED_DIR_PROPERTY);
    assertNotNull(PLANTED_DIR_PROPERTY + " is not set", plantedDirName);
    File plantedDir = new File(plantedDirName).getCanonicalFile();
    assertTrue(plantedDir + " is not a directory", plantedDir.isDirectory());
    assertEquals(plantedDirName, System.getProperty("java.library.path"));

    File trusted = findLoadableLibrary();

    // Plant loadable libraries under every name the appender asks
    // System.loadLibrary for.
    String arch = System.getProperty("os.arch");
    File plantedArch = new File(plantedDir,
        System.mapLibraryName("NTEventLogAppender." + arch));
    File plantedDefault = new File(plantedDir,
        System.mapLibraryName("NTEventLogAppender"));
    copy(trusted, plantedArch);
    copy(trusted, plantedDefault);

    System.setProperty(DLL_PATH_PROPERTY, trusted.getAbsolutePath());
    try {
      Class.forName("org.apache.log4j.nt.NTEventLogAppender");
    } finally {
      System.getProperties().remove(DLL_PATH_PROPERTY);
    }

    String maps = readMappedFiles();
    assertTrue("planted library " + plantedArch + " was loaded",
        maps.indexOf(plantedArch.getCanonicalPath()) < 0);
    assertTrue("planted library " + plantedDefault + " was loaded",
        maps.indexOf(plantedDefault.getCanonicalPath()) < 0);
    assertTrue("configured library " + trusted + " was not loaded",
        maps.indexOf(trusted.getCanonicalPath()) >= 0);
  }

  /**
   * Finds a native library that can be loaded into this JVM without side
   * effects, to stand in for NTEventLogAppender.dll.
   */
  private static File findLoadableLibrary() throws IOException {
    String javaHome = System.getProperty("java.home");
    String arch = System.getProperty("os.arch");
    String[] candidates = new String[] {
        javaHome + "/lib/" + arch + "/libnpt.so",
        javaHome + "/lib/libnpt.so",
        "/lib/x86_64-linux-gnu/libz.so.1",
        "/usr/lib/x86_64-linux-gnu/libz.so.1",
        "/lib64/libz.so.1",
        "/usr/lib64/libz.so.1"
    };
    for (int i = 0; i < candidates.length; i++) {
      File candidate = new File(candidates[i]);
      if (candidate.isFile()) {
        return candidate.getCanonicalFile();
      }
    }
    fail("no native library found to stand in for NTEventLogAppender");
    return null;
  }

  private static void copy(final File from, final File to) throws IOException {
    InputStream in = new FileInputStream(from);
    try {
      OutputStream out = new FileOutputStream(to);
      try {
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) != -1) {
          out.write(buf, 0, n);
        }
      } finally {
        out.close();
      }
    } finally {
      in.close();
    }
  }

  /**
   * Returns the memory map of this process, which lists the path of every
   * shared library loaded into it.
   */
  private static String readMappedFiles() throws IOException {
    BufferedReader reader =
        new BufferedReader(new FileReader("/proc/self/maps"));
    try {
      StringBuffer buf = new StringBuffer();
      String line;
      while ((line = reader.readLine()) != null) {
        buf.append(line).append('\n');
      }
      return buf.toString();
    } finally {
      reader.close();
    }
  }
}
