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
package org.jboss.security.xacml.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import org.jboss.security.xacml.factories.RequestResponseContextFactory;
import org.jboss.security.xacml.interfaces.ResponseContext;
import org.jboss.security.xacml.sunxacml.ctx.ResponseCtx;
import org.w3c.dom.Element;
import org.w3c.dom.Node;


/**
 *  Utility methods for JBossXACML
 *  @author Anil.Saldhana@redhat.com
 *  @since  Apr 3, 2008 
 *  @version $Revision$
 */
public class JBossXACMLUtil
{
   public static Element getResponseContextElement(ResponseContext response) throws Exception
   {
      Node node = response.getDocumentElement();
      if(node instanceof Element)
         return (Element) node;
      
      Element element = null;
      if(element == null)
      {
         ByteArrayOutputStream baos = new ByteArrayOutputStream(); 
         response.marshall(baos); 
         
         byte[] resp = baos.toByteArray();
         System.out.println("RESPONSE:"+new String(resp));
         ByteArrayInputStream bis = new ByteArrayInputStream(resp); 
         
         ResponseContext newRC = RequestResponseContextFactory.createResponseContext();
         newRC.readResponse(bis);
         element = (Element) newRC.getDocumentElement(); 
      }
      return element;
   }

}