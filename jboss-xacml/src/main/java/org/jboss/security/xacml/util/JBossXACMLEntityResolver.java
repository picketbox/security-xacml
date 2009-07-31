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
package org.jboss.security.xacml.util;

import java.io.InputStream;
import java.io.Reader;
import java.util.HashMap;
import java.util.Map;

import org.w3c.dom.ls.LSInput;
import org.w3c.dom.ls.LSResourceResolver;

/**
 * An LSResource Resolver for schema validation
 * @author Anil.Saldhana@redhat.com
 * @since July 31, 2009
 */
public class JBossXACMLEntityResolver implements LSResourceResolver
{
   private static Map<String, LSInput> lsmap = new HashMap<String,LSInput>(); 
   
   private static Map<String, String> schemaLocationMap = new HashMap<String,String>();
   
   static
   {
      schemaLocationMap.put("urn:oasis:names:tc:xacml:2.0:policy:schema:os", 
            "schema/access_control-xacml-2.0-policy-schema-os.xsd");
      schemaLocationMap.put("urn:oasis:names:tc:xacml:2.0:context:schema:os", 
      "schema/access_control-xacml-2.0-context-schema-os.xsd");
     
      schemaLocationMap.put("http://www.w3.org/TR/2002/REC-xmlenc-core-20021210/xenc-schema.xsd",
             "schema/w3c/xmlenc/xenc-schema.xsd"); 
      schemaLocationMap.put("datatypes.dtd",
             "schema/w3c/xmlschema/datatypes.dtd");
      schemaLocationMap.put("http://www.w3.org/2001/XMLSchema.dtd",
             "schema/w3c/xmlschema/XMLSchema.dtd");
   }
   
   public LSInput resolveResource(String type, 
         String namespaceURI, final String publicId, 
         final String systemId, final String baseURI)
   {   
      LSInput lsi = lsmap.get(systemId);
      if(lsi == null)
      {
         ClassLoader tcl = SecurityActions.getContextClassLoader(); 
         String loc = schemaLocationMap.get(systemId);
         if(loc == null)
            return null;
         
         final InputStream is = tcl.getResourceAsStream(loc); 
         if(is == null)
            System.out.println("inputstream is null for "+ loc);
         lsi = new LSInput()
         {
            public String getBaseURI()
            {
               return baseURI;
            }

            public InputStream getByteStream()
            {
               return is;
            }

            public boolean getCertifiedText()
            { 
               return false;
            }

            public Reader getCharacterStream()
            { 
               return null;
            }

            public String getEncoding()
            { 
               return null;
            }

            public String getPublicId()
            {
               return publicId;
            }

            public String getStringData()
            { 
               return null;
            }

            public String getSystemId()
            {
               return systemId;
            }

            public void setBaseURI(String baseURI)
            {
            }

            public void setByteStream(InputStream byteStream)
            {
            }

            public void setCertifiedText(boolean certifiedText)
            {
            }

            public void setCharacterStream(Reader characterStream)
            {
            }

            public void setEncoding(String encoding)
            {
            }

            public void setPublicId(String publicId)
            {
            }

            public void setStringData(String stringData)
            {
            }

            public void setSystemId(String systemId)
            {
            }
        };

        lsmap.put(systemId, lsi);
      }
      return lsi;
   }

}