/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2008, Red Hat Middleware LLC, and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors. 
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.jboss.test.security.test.xacml.attriblocators;

import java.io.InputStream;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;

import junit.framework.TestCase;

import org.jboss.security.xacml.core.JBossPDP;
import org.jboss.security.xacml.interfaces.PolicyDecisionPoint;
import org.jboss.security.xacml.interfaces.ResponseContext;
import org.jboss.security.xacml.interfaces.XACMLConstants; 
import org.jboss.test.security.xacml.factories.util.XACMLTestUtil;

/**
 * Unit test the <code>DatabaseAttributeLocator</code>
 * @author Anil.Saldhana@redhat.com
 * @since Mar 1, 2010
 */
public class DatabaseAttributeLocatorUnitTestCase extends TestCase
{ 
   @Override
   protected void setUp() throws Exception
   {  
      Connection connection = null;
      try
      {
         Class.forName("org.hsqldb.jdbcDriver");
      }
      catch (ClassNotFoundException e)
      {
         throw new RuntimeException("DB Driver not found:",e);
      }
      try
      {
         connection = DriverManager.getConnection("jdbc:hsqldb:target/XACMLDBAttributeLocator");
      }
      catch (SQLException e)
      {
         throw new RuntimeException("Cannot get DB Connection:",e);
      }
      
      Statement statement = null; 
      
      try
      {
         statement = connection.createStatement();
         statement.executeUpdate("DROP TABLE IF EXISTS resource;");
         statement.executeUpdate("CREATE TABLE resource(name VARCHAR, owner_id VARCHAR, account_status VARCHAR)");
         PreparedStatement prep = connection.prepareStatement(
         "INSERT INTO resource VALUES (?, ?, ?);");

         prep.setString(1, "John Smith");
         prep.setString(2, "123456");
         prep.setString(3, "Active");
         prep.addBatch();
         connection.setAutoCommit(false);
         prep.executeBatch();
         connection.setAutoCommit(true); 
      }
      catch (SQLException e)
      {
         throw new RuntimeException("SQL Exception in setting up DB:", e);
      }

      try
      { 
         statement.close(); 
      }
      catch (SQLException e)
      {
         throw new RuntimeException("SQL Exception in closing DB connections:", e);
      } 
      
      try
      {
         statement = connection.createStatement();
         statement.executeUpdate("DROP TABLE IF EXISTS subject;");
         statement.executeUpdate("CREATE TABLE subject(name VARCHAR, subject_id VARCHAR)");
         PreparedStatement prep = connection.prepareStatement(
         "INSERT INTO subject VALUES (?, ?);");

         prep.setString(1, "John Smith");
         prep.setString(2, "123456"); 
         prep.addBatch();
         connection.setAutoCommit(false);
         prep.executeBatch();
         connection.setAutoCommit(true); 
      }
      catch (SQLException e)
      {
         throw new RuntimeException("SQL Exception in setting up DB:", e);
      }

      try
      { 
         statement.close();
         connection.close();
      }
      catch (SQLException e)
      {
         throw new RuntimeException("SQL Exception in closing DB connections:", e);
      } 
      
      
   } 

   public void testPDPUsingDatabaseResourceAttributeLocator() throws Exception
   { 
      ClassLoader tcl = Thread.currentThread().getContextClassLoader();

      InputStream is = tcl.getResourceAsStream("locators/attrib/db_resource_attrib_locator-config.xml");
      assertNotNull("Inputstream is not null?", is);
      PolicyDecisionPoint pdp = new JBossPDP(is);
      ResponseContext response = XACMLTestUtil.getResponse(pdp,"locators/attrib/attribLocatorResourceAttribute-request.xml"); 
      int decision = response.getDecision();
      assertEquals("PERMIT?", XACMLConstants.DECISION_PERMIT,decision);
   }
   
   public void testPDPUsingDatabaseSubjectAttributeLocator() throws Exception
   { 
      ClassLoader tcl = Thread.currentThread().getContextClassLoader();

      InputStream is = tcl.getResourceAsStream("locators/attrib/db_subject_attrib_locator-config.xml");
      assertNotNull("Inputstream is not null?", is);
      PolicyDecisionPoint pdp = new JBossPDP(is);
      ResponseContext response = XACMLTestUtil.getResponse(pdp,"locators/attrib/attribLocatorSubjectAttribute-request.xml"); 
      int decision = response.getDecision();
      assertEquals("PERMIT?", XACMLConstants.DECISION_PERMIT,decision);
   }
}