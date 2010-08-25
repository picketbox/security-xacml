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
package org.jboss.test.security.xacml.locators;

import java.net.URI;

import org.jboss.security.xacml.locators.AttributeLocator;
import org.jboss.security.xacml.sunxacml.EvaluationCtx;
import org.jboss.security.xacml.sunxacml.cond.EvaluationResult;
import org.w3c.dom.Node;

/**
 * Test Attribute Locator
 * @author Anil.Saldhana@redhat.com
 * @since Mar 19, 2009
 */
@org.junit.Ignore
public class TestAttributeLocator extends AttributeLocator
{ 
   @Override
   public EvaluationResult findAttribute(String contextPath, Node namespaceNode, URI attributeType,
         EvaluationCtx context, String xpathVersion)
   {
      validate();
      return super.findAttribute(contextPath, namespaceNode, attributeType, context, xpathVersion);
   }

   @Override
   public EvaluationResult findAttribute(URI attributeType, URI attributeId, URI issuer, URI subjectCategory,
         EvaluationCtx context, int designatorType)
   {
      validate();
      return super.findAttribute(attributeType, attributeId, issuer, subjectCategory, context, designatorType);
   }
   
   private void validate()
   {
      try
      { 
         if("test-attrib".equals(this.getIdentifier()) == false)
            throw new RuntimeException("Identifier is wrong in TestAttributeLocator"); 
        
         String uri = "urn:oasis:names:tc:xacml:1.0:subject:subject-id";
         if(this.getSupportedIds().contains(new URI(uri)) == false)
            throw new RuntimeException(uri + " not in supported types");  
      } 
      catch(Exception e)
      {
         throw new RuntimeException(e);
      }
      
   }
}