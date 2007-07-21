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
package org.jboss.security.xacml.core;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.HashMap;
import java.util.Map;

import javax.xml.bind.JAXB;
import javax.xml.bind.JAXBElement;
import javax.xml.parsers.DocumentBuilderFactory;

import org.jboss.security.xacml.core.model.context.ObjectFactory;
import org.jboss.security.xacml.core.model.context.RequestType;
import org.jboss.security.xacml.interfaces.ContextMapOp;
import org.jboss.security.xacml.interfaces.RequestContext;
import org.jboss.security.xacml.interfaces.XACMLConstants;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import com.sun.xacml.ctx.RequestCtx;

//$Id$

/**
 *  Implementation of the RequestContext interface
 *  @author Anil.Saldhana@redhat.com
 *  @since  Jul 6, 2007 
 *  @version $Revision$
 */
public class JBossRequestContext implements RequestContext, ContextMapOp
{
   private Map<String,Object> map = new HashMap<String,Object>();

   /**
    * @see ContextMapOp#get(String)
    */
   public <T> T get(String key)
   {
     return (T) map.get(key);
   }

   /**
    * @see ContextMapOp#set(String, Object)
    */
   public <T> void set(String key, T obj)
   {
     map.put(key, obj);
   }
   
   /**
    * @see RequestContext#setRequest(RequestType)
    */
   public void setRequest(RequestType requestType) throws IOException
   {
      JAXBElement<RequestType> requestJAXB = new ObjectFactory().createRequest(requestType);
      ByteArrayOutputStream baos = new ByteArrayOutputStream(); 
      JAXB.marshal(requestJAXB, baos);
      ByteArrayInputStream bis = new ByteArrayInputStream(baos.toByteArray()); 
      readRequest(bis);  
   }

   /**
    * @see RequestContext#readRequest(InputStream)
    */
   public void readRequest(InputStream is) throws IOException
   { 
      try
      {
         RequestCtx request = RequestCtx.getInstance(getRequest(is));
         set(XACMLConstants.REQUEST_CTX, request);
      }
      catch (Exception e)
      {
         throw new RuntimeException(e);
      }
   } 
 
   /**
    * @see RequestContext#marshall(OutputStream)
    */
   public void marshall(OutputStream os) throws IOException
   {
      RequestCtx storedRequest = get(XACMLConstants.REQUEST_CTX);    
      if(storedRequest != null)
         storedRequest.encode(os);
   }

   private Node getRequest(InputStream is) throws Exception
   {
      String contextSchema = "urn:oasis:names:tc:xacml:2.0:context:schema:os"; 
      DocumentBuilderFactory factory =
         DocumentBuilderFactory.newInstance();
      factory.setNamespaceAware(true);
      factory.setIgnoringComments(true); 
      Document doc = factory.newDocumentBuilder().parse(is);
      NodeList nodes = doc.getElementsByTagNameNS(contextSchema, "Request");  
      return nodes.item(0);  
   }

}
