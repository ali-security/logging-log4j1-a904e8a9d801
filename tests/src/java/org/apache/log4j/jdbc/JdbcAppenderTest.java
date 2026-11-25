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
package org.apache.log4j.jdbc;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import junit.framework.TestCase;

import org.apache.log4j.EnhancedPatternLayout;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.apache.log4j.MDC;
import org.apache.log4j.NDC;
import org.apache.log4j.PatternLayout;
import org.apache.log4j.PropertyConfigurator;
import org.apache.log4j.VectorErrorHandler;
import org.apache.log4j.xml.XLevel;

/**
 * Tests JDBCAppender against an in-memory H2 database, including the
 * SQL injection vectors of CVE-2022-23305.
 */
public class JdbcAppenderTest extends TestCase {

  private static final String H2_URL = "jdbc:h2:mem:test_db";

  private static final String INSERT_SQL =
    "insert into logs(level,location,message,message2) values('%p','%c','%m', ' %c %p %m')";

  private static final String LOCATION = "org.apache.log4j.jdbc.JdbcAppenderTest";

  /**
   * Closes the string literal of the statement and appends a second,
   * attacker-controlled row; the rest of the statement is commented out.
   */
  private static final String INJECTION_NEW_ROW = "a','b'),('X','X','X','X')--";

  /**
   * Closes the statement and stacks a second one that drops the log table.
   */
  private static final String INJECTION_DROP_TABLE = "a','b'); DROP TABLE logs; --";

  // Closing the last connection to "in-memory h2" removes the database
  // So we keep the connection during the test
  // The logger opens its own connection
  Connection con;

  Logger logger = Logger.getLogger(JdbcAppenderTest.class);

  public JdbcAppenderTest(final String name) {
    super(name);
  }

  protected void setUp() throws Exception {
    // Explicitly load the H2 driver
    Class.forName("org.h2.Driver");

    con = DriverManager.getConnection(H2_URL);
    Statement st = con.createStatement();
    try {
      st.execute(
        "create table logs(level varchar(100),location varchar(100),message varchar(100),message2 varchar(100))");
    } finally {
      st.close();
    }
  }

  protected void tearDown() throws Exception {
    // closes the appenders (and their connections) and drops the
    // programmatically added ones before the next test
    LogManager.resetConfiguration();
    con.close();
  }

  public void testVerifyJdbcBufferSize1() throws SQLException {
    PropertyConfigurator.configure("input/jdbc_h2_bufferSize1.properties");

    String oldThreadName = Thread.currentThread().getName();
    try {
      Thread.currentThread().setName("main");
      logger.debug("message with ' quote");
      assertEquals("batchSize=1, so messages should be added immediately",
        "DEBUG; org.apache.log4j.jdbc.JdbcAppenderTest; message with ' quote;  org.apache.log4j.jdbc.JdbcAppenderTest DEBUG message with ' quote\n",
        joinSorted(getMessagesFromDababase()));

      logger.fatal("message with \" quote");

      assertEquals("batchSize=1, so two messages should be in DB after two logging calls",
        "DEBUG; org.apache.log4j.jdbc.JdbcAppenderTest; message with ' quote;  org.apache.log4j.jdbc.JdbcAppenderTest DEBUG message with ' quote\n"
          + "FATAL; org.apache.log4j.jdbc.JdbcAppenderTest; message with \" quote;  org.apache.log4j.jdbc.JdbcAppenderTest FATAL message with \" quote\n",
        joinSorted(getMessagesFromDababase()));
    } finally {
      Thread.currentThread().setName(oldThreadName);
    }
  }

  public void testVerifyJdbcBufferSize2() throws SQLException {
    PropertyConfigurator.configure("input/jdbc_h2_bufferSize2.properties");

    String oldThreadName = Thread.currentThread().getName();
    try {
      Thread.currentThread().setName("main");
      logger.log(XLevel.TRACE, "xtrace message");
      logger.debug("message with ' quote");
      logger.info("message with \" quote");
      logger.warn("?");
      // bufferSize=2, so this messsage won't yet be stored to the db
      logger.error("m4");

      assertEquals(
        "DEBUG; org.apache.log4j.jdbc.JdbcAppenderTest; message with ' quote;  org.apache.log4j.jdbc.JdbcAppenderTest DEBUG message with ' quote\n"
          + "INFO; org.apache.log4j.jdbc.JdbcAppenderTest; message with \" quote;  org.apache.log4j.jdbc.JdbcAppenderTest INFO message with \" quote\n"
          + "TRACE; org.apache.log4j.jdbc.JdbcAppenderTest; xtrace message;  org.apache.log4j.jdbc.JdbcAppenderTest TRACE xtrace message\n"
          + "WARN; org.apache.log4j.jdbc.JdbcAppenderTest; ?;  org.apache.log4j.jdbc.JdbcAppenderTest WARN ?\n",
        joinSorted(getMessagesFromDababase()));

      logger.fatal("m5");

      assertEquals("Logging m5 message should trigger buffer flush for both m4 and m5",
        "DEBUG; org.apache.log4j.jdbc.JdbcAppenderTest; message with ' quote;  org.apache.log4j.jdbc.JdbcAppenderTest DEBUG message with ' quote\n"
          + "ERROR; org.apache.log4j.jdbc.JdbcAppenderTest; m4;  org.apache.log4j.jdbc.JdbcAppenderTest ERROR m4\n"
          + "FATAL; org.apache.log4j.jdbc.JdbcAppenderTest; m5;  org.apache.log4j.jdbc.JdbcAppenderTest FATAL m5\n"
          + "INFO; org.apache.log4j.jdbc.JdbcAppenderTest; message with \" quote;  org.apache.log4j.jdbc.JdbcAppenderTest INFO message with \" quote\n"
          + "TRACE; org.apache.log4j.jdbc.JdbcAppenderTest; xtrace message;  org.apache.log4j.jdbc.JdbcAppenderTest TRACE xtrace message\n"
          + "WARN; org.apache.log4j.jdbc.JdbcAppenderTest; ?;  org.apache.log4j.jdbc.JdbcAppenderTest WARN ?\n",
        joinSorted(getMessagesFromDababase()));
    } finally {
      Thread.currentThread().setName(oldThreadName);
    }
  }

  /**
   * A message must be stored as data, it must not be able to add rows.
   */
  public void testSqlInjectionInMessageCannotInsertRows() throws SQLException {
    PropertyConfigurator.configure("input/jdbc_h2_bufferSize1.properties");

    logger.debug(INJECTION_NEW_ROW);

    assertEquals("The message must be bound as a value, not spliced into the SQL",
      expectedRow("DEBUG", INJECTION_NEW_ROW),
      joinSorted(getMessagesFromDababase()));
  }

  /**
   * A message must be stored as data, it must not be able to run a
   * second statement.
   */
  public void testSqlInjectionInMessageCannotStackStatements() throws SQLException {
    PropertyConfigurator.configure("input/jdbc_h2_bufferSize2.properties");

    logger.info(INJECTION_DROP_TABLE);
    logger.warn(INJECTION_NEW_ROW);

    assertEquals("The messages must be bound as values, not spliced into the SQL",
      expectedRow("INFO", INJECTION_DROP_TABLE) + expectedRow("WARN", INJECTION_NEW_ROW),
      joinSorted(getMessagesFromDababase()));
  }

  /**
   * MDC and NDC values are as attacker-controlled as the message.
   */
  public void testSqlInjectionInMdcAndNdcIsNotExecuted() throws SQLException {
    JDBCAppender appender = createH2Appender();
    appender.setSql(
      "insert into logs(level,location,message,message2) values('%p','%c','%X{user}','%x')");
    appender.activateOptions();
    logger.addAppender(appender);

    MDC.put("user", INJECTION_NEW_ROW);
    NDC.push(INJECTION_DROP_TABLE);
    try {
      logger.info("mdc and ndc");
    } finally {
      NDC.remove();
      MDC.remove("user");
    }

    assertEquals("MDC and NDC values must be bound as values, not spliced into the SQL",
      "INFO; " + LOCATION + "; " + INJECTION_NEW_ROW + "; " + INJECTION_DROP_TABLE + "\n",
      joinSorted(getMessagesFromDababase()));
  }

  /**
   * An appender configured through its layout's ConversionPattern only
   * (no sql option, e.g. from a log4j.xml) is protected as well.
   */
  public void testLayoutConversionPatternIsParameterized() throws SQLException {
    JDBCAppender appender = createH2Appender();
    appender.setLayout(new PatternLayout(INSERT_SQL));
    appender.activateOptions();
    logger.addAppender(appender);

    logger.warn(INJECTION_NEW_ROW);

    assertEquals("The message must be bound as a value, not spliced into the SQL",
      expectedRow("WARN", INJECTION_NEW_ROW),
      joinSorted(getMessagesFromDababase()));
  }

  /**
   * An appender configured programmatically without calling
   * activateOptions keeps working, and is protected as well.
   */
  public void testWithoutActivateOptionsIsParameterized() throws SQLException {
    JDBCAppender appender = createH2Appender();
    appender.setSql(INSERT_SQL);
    logger.addAppender(appender);

    logger.error(INJECTION_NEW_ROW);

    assertEquals("The message must be bound as a value, not spliced into the SQL",
      expectedRow("ERROR", INJECTION_NEW_ROW),
      joinSorted(getMessagesFromDababase()));
  }

  /**
   * A layout other than PatternLayout would hand its formatted, unescaped
   * output to the database, so the appender must refuse to use it.
   */
  public void testNonPatternLayoutIsRejected() throws SQLException {
    JDBCAppender appender = createH2Appender();
    appender.setSql(INSERT_SQL);
    appender.setLayout(new EnhancedPatternLayout(INSERT_SQL));
    VectorErrorHandler errorHandler = new VectorErrorHandler();
    appender.setErrorHandler(errorHandler);
    appender.activateOptions();
    logger.addAppender(appender);

    logger.info(INJECTION_NEW_ROW);

    assertEquals("Nothing may be executed with a layout other than PatternLayout",
      "", joinSorted(getMessagesFromDababase()));
    assertEquals(1, errorHandler.size());
    assertTrue(errorHandler.getException(0) instanceof IllegalArgumentException);
  }

  private JDBCAppender createH2Appender() {
    JDBCAppender appender = new JDBCAppender();
    appender.setName("jdbc");
    appender.setDriver("org.h2.Driver");
    appender.setURL(H2_URL);
    appender.setUser("");
    appender.setPassword("");
    return appender;
  }

  private static String expectedRow(String level, String message) {
    return level + "; " + LOCATION + "; " + message + ";  " + LOCATION + " " + level + " " + message + "\n";
  }

  private static String joinSorted(List list) {
    Collections.sort(list);
    StringBuffer sb = new StringBuffer();
    for (int i = 0; i < list.size(); i++) {
      String s = (String) list.get(i);
      sb.append(s).append('\n');
    }
    return sb.toString();
  }

  private List getMessagesFromDababase() throws SQLException {
    List res = new ArrayList();
    PreparedStatement ps = con.prepareStatement("select level,location,message,message2 from logs");
    try {
      ResultSet rs = ps.executeQuery();
      try {
        while (rs.next()) {
          res.add(rs.getString(1) + "; " + rs.getString(2) + "; " + rs.getString(3) + "; " + rs.getString(4));
        }
      } finally {
        rs.close();
      }
    } finally {
      ps.close();
    }
    return res;
  }
}
