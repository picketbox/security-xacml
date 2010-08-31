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
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

import org.jboss.security.xacml.sunxacml.EvaluationCtx;
import org.jboss.security.xacml.sunxacml.attr.AttributeValue;
import org.jboss.security.xacml.sunxacml.attr.BagAttribute;
import org.jboss.security.xacml.sunxacml.cond.EvaluationResult;
import org.jboss.security.xacml.util.JBossXACMLUtil;

/**
 * File System based attribute locator.
 * <br/>
 * <br/>
 * This attribute locator should be used for those rare cases where in you have 
 * one or two attributes that your pdp needs and you do not have other ways of providing
 * it to the PDP such as in request, ldap or db.
 * <br/>
 * <br/>
 * This Locator requires an XML conforming to the Java Properties DTD.  An example is shown below:<br/>
 * 
 * 
 * &lt;?xml version="1.0" encoding="UTF-8"?&gt; <br/>
&lt;!DOCTYPE properties SYSTEM "http://java.sun.com/dtd/properties.dtd"&gt;<br/>
&lt;properties&gt;<br/>
&lt;entry key="urn:xacml:2.0:interop:example:resource:account-status">Active&lt;/entry&gt;<br/>
&lt;entry key="urn:oasis:names:tc:xacml:1.0:subject:subject-id">123456&lt;/entry&gt;<br/>
&lt;/properties&gt;<br/>

 * <br/>
 * <br/>
 * The Module Options are shown as below:
 * <br/>
 * <br/>
 * &lt;ns:Locator Name="org.jboss.security.xacml.locators.attrib.FileSystemAttributeLocator"&gt;   <br/>
      &lt;ns:Option Name="fileName"&gt;locators/attrib/filesystemAttrib.properties&lt;/ns:Option&gt; <br/>
      &lt;ns:Option Name="attributeSupportedId"&gt;urn:xacml:2.0:interop:example:resource:account-status,urn:oasis:names:tc:xacml:1.0:subject:subject-id&lt;/ns:Option&gt;<br/>
    &lt;/ns:Locator&gt;<br/>
 * <br/>
 * <br/>
 * <br/>
 * 
 * fileName:  Name of XML file that conforms to Java Properties XML DTD format on the class path. <br/>
 * attributeSupportedID:  the URI namespaces of attributes that this locator supports.<br/>
 * <br/>
 * @author Anil.Saldhana@redhat.com
 * @since Aug 31, 2010
 */
public class FileSystemAttributeLocator extends StorageAttributeLocator
{
   private Properties properties = new Properties();
   
   public static final String FILE_NAME = "fileName";
    
   @Override
   protected void usePassedOption(String optionTag, String optionValue)
   {   
      super.usePassedOption(optionTag, optionValue);
      
      if( optionTag.equalsIgnoreCase( FILE_NAME ) )
      {
         ClassLoader tcl = SecurityActions.getContextClassLoader();
         InputStream is = tcl.getResourceAsStream( optionValue );
         if( is == null )
         {
            throw new RuntimeException( "Unable to load " + FILE_NAME + " using the context classloader. Does the file exist?" );
         }
            
         try
         {
            properties.loadFromXML( is );
         }
         catch (IOException e)
         {
            throw new RuntimeException( "Unable to load " + FILE_NAME , e );
         }
      } 
   }
    

   @Override
   public EvaluationResult findAttribute(URI attributeType, URI attributeId, URI issuer, URI subjectCategory,
         EvaluationCtx context, int designatorType)
   {
      Set<AttributeValue> bagSet = new HashSet<AttributeValue>();
      
      if( properties.size() > 0 )
      {
         attributeValue = properties.getProperty( attributeId.toASCIIString() );
         bagSet.add( JBossXACMLUtil.getAttributeValue( attributeValue ) );
      } 
      else
      {
         if(attributeType != null)
            return new EvaluationResult(BagAttribute.createEmptyBag(attributeType));
         else 
            return new EvaluationResult(BagAttribute.createEmptyBag(attributeId)); 
      } 
      return new EvaluationResult( new BagAttribute( attributeType, bagSet ));  
   }

   @Override
   protected Object getSubstituteValue(URI attributeType, EvaluationCtx context) throws URISyntaxException
   {
      throw new RuntimeException( "Not Applicable for this locator" );
   } 
}