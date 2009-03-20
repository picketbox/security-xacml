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
package org.jboss.security.xacml.locators;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.jboss.security.xacml.interfaces.AbstractLocator;
import org.jboss.security.xacml.jaxb.Option;
import org.jboss.security.xacml.sunxacml.finder.ResourceFinderModule;

/**
 * Resource Finder Module
 * 
 * The following methods need to be overridden in your locator
 * @see ResourceFinderModule#findChildResources(org.jboss.security.xacml.sunxacml.attr.AttributeValue, org.jboss.security.xacml.sunxacml.EvaluationCtx)
 * @see ResourceFinderModule#findDescendantResources(org.jboss.security.xacml.sunxacml.attr.AttributeValue, org.jboss.security.xacml.sunxacml.EvaluationCtx)
 * 
 * @author Anil.Saldhana@redhat.com
 * @since Mar 19, 2009
 */
public class ResourceLocator extends ResourceFinderModule implements AbstractLocator
{
   private String identifier = null;

   private boolean resourceChildSupported = true;

   private boolean resourceDescendantSupported = true; 

   private List<Option> options = new ArrayList<Option>();

   private Map<String,Object> map = new HashMap<String,Object>();

   public void setOptions(List<Option> options)
   {
      this.options = options;
      try
      {
         processOptions();
      }
      catch (Exception e)
      {
         throw new RuntimeException(e);
      }
   }

   @SuppressWarnings("unchecked")
   public <T> T get(String key)
   {
      return (T) this.map.get(key);   
   }

   public <T> void set(String key, T obj)
   {
      this.map.put(key, obj);     
   } 


   @Override
   public String getIdentifier()
   {
      if(identifier == null)
         return super.getIdentifier();
      return this.identifier;
   }


   @Override
   public boolean isChildSupported()
   {
      return this.resourceChildSupported;
   }

   @Override
   public boolean isDescendantSupported()
   {
      return this.resourceDescendantSupported;
   }

   private void processOptions() throws Exception
   {
      for(Option option:options)
      {
         String tag = option.getName();
         List<Object> values = option.getContent();

         String value = (String) values.get(0); 

         if(AbstractLocator.IDENTIFIER_TAG.equals(tag))
         {
            this.identifier = value;
         }
         else if(AbstractLocator.RESOURCE_CHILD_SUPPORTED_TAG.equals(tag))
         {
            this.resourceChildSupported = Boolean.parseBoolean(value);
         }
         else if(AbstractLocator.RESOURCE_DESCENDANT_SUPPORTED_TAG.equals(tag))
         {
            this.resourceDescendantSupported = Boolean.parseBoolean(value);
         } 
      }
   } 
}
