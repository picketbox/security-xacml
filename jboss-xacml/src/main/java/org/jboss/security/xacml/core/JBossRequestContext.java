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
import org.jboss.security.xacml.sunxacml.ctx.RequestCtx;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 *  Implementation of the RequestContext interface
 *  @author Anil.Saldhana@redhat.com
 *  @since  Jul 6, 2007 
 *  @version $Revision$
 */
public class JBossRequestContext implements RequestContext
{
   private Map<String, Object> map = new HashMap<String, Object>();
   
   private Node documentElement = null;

   /**
    * @see ContextMapOp#get(String)
    */
   @SuppressWarnings("unchecked")
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
    * @see RequestContext#getDocumentElement()
    */
   public Node getDocumentElement()
   {
      return documentElement;
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
         Node root = getRequest(is);
         this.documentElement = root;
         
         if (root == null)
            throw new IllegalStateException("Root node read from the input stream is null");
         RequestCtx request = RequestCtx.getInstance(root);
         set(XACMLConstants.REQUEST_CTX, request);
      }
      catch (Exception e)
      {
         throw new RuntimeException(e);
      }
   }

   /**
    * @see RequestContext#readRequest(Node)
    */
   public void readRequest(Node node) throws IOException
   {
      this.documentElement = node;
      if(node == null)
         throw new IllegalArgumentException("node is null");
      
      try
      {
         RequestCtx request = RequestCtx.getInstance(node);
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
      if (storedRequest != null)
         storedRequest.encode(os);
   }

   /**
    * @see ElementMappingType#asElement(Document)
    */
   public Element asElement(Document root)
   { 
      throw new RuntimeException("SECURITY-176");
   }
   
   
   private Node getRequest(InputStream is) throws Exception
   {
      String contextSchema = "urn:oasis:names:tc:xacml:2.0:context:schema:os";
      DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
      factory.setNamespaceAware(true);
      factory.setIgnoringComments(true);
      Document doc = factory.newDocumentBuilder().parse(is);
      NodeList nodes = doc.getElementsByTagNameNS(contextSchema, "Request");
      return nodes.item(0);
   }

   

}
