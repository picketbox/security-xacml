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

import java.net.URI;
import java.net.URISyntaxException;

import org.jboss.security.xacml.sunxacml.EvaluationCtx;
import org.jboss.security.xacml.sunxacml.cond.EvaluationResult;

/**
 * Locates an attribute about Environment from the DB
 *   
 * An example of the Locator configuration is here:
 * 
 * &lt;ns:Locator Name="org.jboss.security.xacml.locators.attrib.DatabaseEnvAttributeLocator"&gt;   <br/>
      &lt;ns:Option Name="DATABASE_FILE_NAME"&gt;data_stores/db.properties&lt;/ns:Option&gt;  <br/>
      &lt;ns:Option Name="sql"&gt;SELECT account_status FROM resource where owner_id=?;&lt;/ns:Option&gt; <br/>  
      &lt;ns:Option Name="attributeSupportedId"&gt;urn:xacml:2.0:interop:example:resource:account-status&lt;/ns:Option&gt; <br/> 
      &lt;ns:Option Name="preparedStatementValue"&gt;urn:xacml:2.0:interop:example:resource:owner-id&lt;/ns:Option&gt;  <br/>
      &lt;ns:Option Name="valueDataType"&gt;http://www.w3.org/2001/XMLSchema#string&lt;/ns:Option&gt;   <br/>
      &lt;ns:Option Name="columnName"&gt;account_status&lt;/ns:Option&gt; <br/>
    &lt;/ns:Locator&gt; <br/>
    
 * @author Anil.Saldhana@redhat.com
 * @since Mar 2, 2010
 */
public class DatabaseEnvAttributeLocator extends DatabaseAttributeLocator
{
   protected Object getPreparedStatementPluginValue(EvaluationCtx evaluationCtx, URI attributeType) throws URISyntaxException
   {    
      EvaluationResult evalResult = evaluationCtx.getEnvironmentAttribute(new URI(valueDataType), new URI(preparedStatementValue), null);
      
      return this.getAttributeValue(evalResult, attributeType); 
   } 
}