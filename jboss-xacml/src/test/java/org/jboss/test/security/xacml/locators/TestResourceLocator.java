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

import org.jboss.security.xacml.locators.ResourceLocator;
import org.jboss.security.xacml.sunxacml.EvaluationCtx;
import org.jboss.security.xacml.sunxacml.attr.AttributeValue;
import org.jboss.security.xacml.sunxacml.finder.ResourceFinderResult;

/**
 * Test Resource locator
 * @author Anil.Saldhana@redhat.com
 * @since Mar 19, 2009
 */
public class TestResourceLocator extends ResourceLocator
{

   @Override
   public ResourceFinderResult findChildResources(AttributeValue parentResourceId, EvaluationCtx context)
   {
      validate();
      return super.findChildResources(parentResourceId, context);
   }

   @Override
   public ResourceFinderResult findDescendantResources(AttributeValue parentResourceId, EvaluationCtx context)
   {
      validate();
      return super.findDescendantResources(parentResourceId, context);
   }
   
   private void validate()
   {
      try
      { 
         if("test-attrib".equals(this.getIdentifier()) == false)
            throw new RuntimeException("Identifier is wrong in TestResourceLocator"); 
         
      } 
      catch(Exception e)
      {
         throw new RuntimeException(e);
      }
   }
}