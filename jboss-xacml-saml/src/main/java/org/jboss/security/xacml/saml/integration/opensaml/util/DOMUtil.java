/*
  * JBoss, Home of Professional Open Source
  * Copyright 2007, JBoss Inc., and individual contributors as indicated
  * by the @authors tag. See the copyright.txt in the distribution for a
  * full listing of individual contributors.
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
package org.jboss.security.xacml.saml.integration.opensaml.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;

import org.opensaml.xml.parse.BasicParserPool;
import org.w3c.dom.Document;
 
/**
 *  DOM util class
 *  @author Anil.Saldhana@redhat.com
 *  @since  Mar 27, 2008 
 *  @version $Revision$
 */
public class DOMUtil
{ 
   /**
    * Parse an XML file
    * @param xmlFile
    * @param validating should we validate?
    * @return
    * @throws Exception
    */
   public static Document parse(File xmlFile, boolean validating) throws Exception
   {
      FileInputStream fis = null;
      
      try 
      { 
         fis = new FileInputStream(xmlFile);
         return parse(fis,validating); 
     } 
     catch (Exception e) 
     {
         throw e;
     }
     finally
     {
        if(fis != null)
           fis.close();
     }
   }
   
   /**
    * Parse an xml file
    * @param is
    * @param validating validate?
    * @return
    * @throws Exception
    */
   public static Document parse(InputStream is, boolean validating)
   throws Exception
   {
      BasicParserPool parser = new BasicParserPool(); 
      parser.setNamespaceAware(true);
      return parser.parse(is); 
   }
}