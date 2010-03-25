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
package org.jboss.security.xacml.locators.attrib;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.sql.DataSource;

import org.jboss.security.xacml.locators.AttributeLocator;
import org.jboss.security.xacml.sunxacml.EvaluationCtx;
import org.jboss.security.xacml.sunxacml.attr.BagAttribute;
import org.jboss.security.xacml.sunxacml.cond.EvaluationResult;
import org.jboss.security.xacml.util.JBossXACMLUtil;

/**
 * An attribute locator that gets the attributes from the DB
 * <p>
 * <b>NOTE:</b> Subclasses should try to override the {@link #getColumnValue(URI, EvaluationCtx)}
 * method if the DB is not a true RDBMS
 * </p> 
 * @author Anil.Saldhana@redhat.com
 * @since Mar 1, 2010
 */
public abstract class DatabaseAttributeLocator extends AttributeLocator
{   
   private static Logger log = Logger.getLogger(DatabaseAttributeLocator.class.getName());
   
   //JNDI name to look for the data source
   protected String dsJNDIName = null;
   
   //Name of the file containing the DB connection information for jdbc
   protected String dbFileName = null;
   
   //The Prepared Statement SQL
   protected String sqlStatement = null;
   
   //The Prepared Statement plugin Value
   protected String preparedStatementValue = null;
   
   //The data type of the prepared statement plugin value
   protected String valueDataType = null;
   
   //Column Name to be returned as part of the sql statement
   protected String columnName = null;
   
   //Constants
   public static final String DS_JNDI_NAME = "DATASOURCE_JNDI_NAME";
   
   public static final String DB_FILE_NAME = "DATABASE_FILE_NAME";
   
   public DatabaseAttributeLocator()
   { 
      this.attributeDesignatorSupported = true;
      this.attributeSelectorSupported = true;
      
      this.designatorTypes.add(Integer.valueOf(0));
      this.designatorTypes.add(Integer.valueOf(1));
      this.designatorTypes.add(Integer.valueOf(2));
   }  
   
   @SuppressWarnings("unchecked")
   @Override
   public EvaluationResult findAttribute(URI attributeType, URI attributeId, URI issuer, URI subjectCategory,
         EvaluationCtx context, int designatorType)
   { 
      if(ids.contains(attributeId) == false) 
      {
         if(attributeType != null)
            return new EvaluationResult(BagAttribute.createEmptyBag(attributeType));
         else

            return new EvaluationResult(BagAttribute.createEmptyBag(attributeId)); 
      }

      Object columnValue = getColumnValue(attributeType, context);
      
      Set bagSet = new HashSet();
      bagSet.add(JBossXACMLUtil.getAttributeValue(columnValue));
      
      return new EvaluationResult(new BagAttribute(attributeType, bagSet)); 
   }  


   @Override
   protected void usePassedOption(String optionTag, String optionValue)
   { 
      super.usePassedOption(optionTag, optionValue);
      
      if(DS_JNDI_NAME.equals(optionTag))
      {
         this.dsJNDIName = optionValue;
      } 
      if(DB_FILE_NAME.equals(optionTag))
      {
         this.dbFileName = optionValue;
      }
      if("sql".equals(optionTag))
      {
         this.sqlStatement = optionValue;
      }
      if("preparedStatementValue".equals(optionTag))
      {
         this.preparedStatementValue = optionValue;
      }
      if("valueDataType".equals(optionTag))
      {
         this.valueDataType = optionValue;
      } 
      if("columnName".equals(optionTag))
      {
         this.columnName = optionValue;
      }
   } 
   
   protected Connection getConnection()
   {
      Connection connection = null;
      if(dsJNDIName != null)
      {
         try
         {
            Context ctx = new InitialContext();
            DataSource ds = (DataSource) ctx.lookup(dsJNDIName);
            connection = ds.getConnection(); 
         }
         catch(Exception e)
         {
            if(log.isLoggable(Level.FINE))
               log.fine("Error looking up connection via Datasource:" + e.getLocalizedMessage()); 
         }
      }
      if(connection == null && dbFileName != null)
      {
         Properties props = new Properties();
         ClassLoader tcl = SecurityActions.getContextClassLoader();
         try
         {
            props.load(tcl.getResourceAsStream(dbFileName));
         }
         catch (IOException e)
         {
            throw new RuntimeException("Error loading DB file", e);
         }
         
         try
         {
            Class.forName(props.getProperty("driverName"));
         }
         catch (ClassNotFoundException e)
         {
            throw new RuntimeException("DB Driver not found:",e);
         }
         try
         {
            connection = DriverManager.getConnection(props.getProperty("connectionURL"));
         }
         catch (SQLException e)
         {
            throw new RuntimeException("Cannot get DB Connection:",e);
         }
      } 
      return connection;
   }
   
   /**
    * Get the value of the attribute we are interested in
    * @param attributeType
    * @param context
    * @return
    */
   protected Object getColumnValue(URI attributeType, EvaluationCtx context)
   {
      Object columnValue = null;
      
      //Do DB stuff here
      Connection connection = getConnection(); 
      
      PreparedStatement statement = null;
      ResultSet resultSet = null; 
      
      try
      {     
         statement = connection.prepareStatement(sqlStatement);
         
         Object pluginValue = null;
         try
         {
            pluginValue = getPreparedStatementPluginValue(context, attributeType);
         }
         catch (URISyntaxException e)
         {
           throw new RuntimeException(e);
         }
         statement.setObject(1, pluginValue);

         statement.addBatch();
         connection.setAutoCommit(false);
         resultSet = statement.executeQuery(); 
         connection.setAutoCommit(true);  

         while (resultSet.next()) 
         {
            columnValue = resultSet.getObject(columnName); 
            break;
         }
      }
      catch (SQLException e)
      {
         throw new RuntimeException(e);
      }
      finally
      {
         try
         {
            if(resultSet != null)
               resultSet.close();
         }
         catch (SQLException e)
         {}
         
         try
         { 
            if(statement != null)
               statement.close();
         }
         catch (SQLException e)
         {}
         
         try
         { 
            if(connection != null)
               connection.close();
         }
         catch (SQLException e)
         { 
         }         
      }  
      
      return columnValue; 
   }
   
   /**
    * <p>
    * Get the value to be plugged into the PreparedStatement using the <code>EvaluationCtx</code>
    * </p>
    * @param evaluationCtx
    * @param attributeType
    * @return
    * @throws URISyntaxException
    */
   protected abstract Object getPreparedStatementPluginValue(EvaluationCtx evaluationCtx, URI attributeType) throws URISyntaxException; 
}