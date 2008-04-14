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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import javax.xml.parsers.DocumentBuilderFactory;

import org.jboss.security.xacml.core.model.context.ObjectFactory;
import org.jboss.security.xacml.core.model.context.ResultType;
import org.jboss.security.xacml.core.model.context.StatusCodeType;
import org.jboss.security.xacml.core.model.context.StatusType;
import org.jboss.security.xacml.core.model.policy.EffectType;
import org.jboss.security.xacml.core.model.policy.ObligationType;
import org.jboss.security.xacml.core.model.policy.ObligationsType;
import org.jboss.security.xacml.interfaces.ContextMapOp;
import org.jboss.security.xacml.interfaces.ElementMappingType;
import org.jboss.security.xacml.interfaces.ResponseContext;
import org.jboss.security.xacml.interfaces.XACMLConstants;
import org.jboss.security.xacml.sunxacml.Indenter;
import org.jboss.security.xacml.sunxacml.Obligation;
import org.jboss.security.xacml.sunxacml.ParsingException;
import org.jboss.security.xacml.sunxacml.ctx.ResponseCtx;
import org.jboss.security.xacml.sunxacml.ctx.Result;
import org.jboss.security.xacml.sunxacml.ctx.Status;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 *  Implementation of the ResponseContext interface
 *  @author Anil.Saldhana@redhat.com
 *  @since  Jul 6, 2007 
 *  @version $Revision$
 */
public class JBossResponseContext implements ResponseContext
{
   private int decision = XACMLConstants.DECISION_DENY;

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
    * @see ResponseContext#getDecision()
    */
   @SuppressWarnings("unchecked")
   public int getDecision()
   {
      ResponseCtx response = (ResponseCtx) map.get(XACMLConstants.RESPONSE_CTX);
      if (response != null)
      {
         Set<Result> results = response.getResults();
         Result res = results.iterator().next();
         decision = res.getDecision();
      }
      return decision;

   }
   
   /**
    * @see ResponseContext#getResult()
    */
   @SuppressWarnings("unchecked")
   public ResultType getResult()
   {
      ObjectFactory objectFactory = new ObjectFactory(); 
      ResultType resultType = objectFactory.createResultType();
      ResponseCtx response = (ResponseCtx) map.get(XACMLConstants.RESPONSE_CTX);
      if (response != null)
      {
         //Resource ID
         Result result = (Result) response.getResults().iterator().next(); 
         resultType.setResourceId(result.getResource());
         
         //Status
         Status status = result.getStatus();
         StatusType statusType = objectFactory.createStatusType();
         StatusCodeType statusCodeType = objectFactory.createStatusCodeType();
         statusCodeType.setValue(status.getMessage()); 
         statusType.setStatusCode(statusCodeType);
         
         //Obligations
         Set<Obligation> obligationsSet = result.getObligations();
         if(obligationsSet != null)
         {
            for(Obligation obl:obligationsSet)
            {
               ObligationType obType = new ObligationType();
               obType.setObligationId(obl.getId().toASCIIString());
               obType.setFulfillOn(EffectType.fromValue(Result.DECISIONS[obl.getFulfillOn()]));
            
               ObligationsType obligationsType = new ObligationsType();
               obligationsType.getObligation().add(obType);
               resultType.setObligations(obligationsType);  
            }
         }
      }
      return resultType; 
   }
   
   /**
    * @see ResponseContext#getDocumentElement()
    */
   public Node getDocumentElement()
   { 
      return documentElement;
   }

   /**
    * @see ResponseContext#marshall(OutputStream)
    */
   public void marshall(OutputStream os) throws IOException
   {
      ResponseCtx storedResponse = get(XACMLConstants.RESPONSE_CTX);
      if (storedResponse != null)
         storedResponse.encode(os,new Indenter(0), XACMLConstants.CONTEXT_SCHEMA);
   }
   
   /**
    * @see ResponseContext#readResponse(InputStream)
    */
   public void readResponse(InputStream is) throws Exception
   {   
      readResponse(getResponse(is));
   }

   /**
    * @see ResponseContext#readResponse(Node)
    */
   public void readResponse(Node node) throws IOException
   {
      if(node == null)
         throw new IllegalArgumentException("node is null");
      
      this.documentElement = node;
      
      ResponseCtx responseCtx;
      try
      {
         responseCtx = ResponseCtx.getInstance(node);
         set(XACMLConstants.RESPONSE_CTX, responseCtx);
      }
      catch (ParsingException e)
      {
         throw new RuntimeException(e);
      }
   }
   
   /**
    * @see ElementMappingType#asElement(Document)
    */
   public Element asElement(Document root)
   { 
      throw new RuntimeException("SECURITY-177");
   }
   
   private Node getResponse(InputStream is) throws Exception
   {
      String contextSchema = XACMLConstants.CONTEXT_SCHEMA;
      DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
      factory.setNamespaceAware(true);
      factory.setIgnoringComments(true);
      Document doc = factory.newDocumentBuilder().parse(is);
      NodeList nodes = doc.getElementsByTagNameNS(contextSchema, "Response");
      if(nodes.getLength() == 0)
      {
         nodes = doc.getElementsByTagName("Response");
      }
      return nodes.item(0);
   }
}