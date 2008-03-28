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
package org.jboss.security.xacml.saml.integration.opensaml.request;

import java.io.File;

import org.jboss.security.xacml.saml.integration.opensaml.util.DOMUtil;
import org.jboss.security.xacml.saml.integration.opensaml.util.SAML2Util;
import org.opensaml.common.SAMLObject;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
 
/**
 *  Represents a SAML Request
 *  @author Anil.Saldhana@redhat.com
 *  @since  Mar 27, 2008 
 *  @version $Revision$
 */
public class SAMLRequest
{ 
   public SAMLObject getSAMLRequest(String requestFile) throws Exception
   {
      Document document = DOMUtil.parse(new File(requestFile), true);
      if(document == null)
         throw new IllegalStateException("Document parsed is null");
      
      SAML2Util util = new SAML2Util();
      Element docElement = document.getDocumentElement();
      if(docElement == null)
         throw new IllegalStateException("Document Element is null");
      return (SAMLObject) util.toXMLObject(docElement);
   }
}