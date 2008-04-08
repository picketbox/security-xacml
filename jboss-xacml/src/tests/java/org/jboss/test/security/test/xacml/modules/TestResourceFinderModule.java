/*
  * JBoss, Home of Professional Open Source
  * Copyright 2005, JBoss Inc., and individual contributors as indicated
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
package org.jboss.test.security.test.xacml.modules;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashSet;

import org.jboss.security.xacml.sunxacml.EvaluationCtx;
import org.jboss.security.xacml.sunxacml.attr.AnyURIAttribute;
import org.jboss.security.xacml.sunxacml.attr.AttributeValue;
import org.jboss.security.xacml.sunxacml.finder.ResourceFinderModule;
import org.jboss.security.xacml.sunxacml.finder.ResourceFinderResult;

//$Id: TestResourceFinderModule.java 45389 2006-05-30 21:29:37Z asaldhana $

/**
 *  Resource Finder Module for testing purposes
 *  @author <a href="mailto:Anil.Saldhana@jboss.org">Anil Saldhana</a>
 *  @since  May 26, 2006 
 *  @version $Revision: 45389 $
 */
public class TestResourceFinderModule extends ResourceFinderModule
{

   /**
    * Default constructor.
    */
   public TestResourceFinderModule()
   {
   }

   /**
    * @see ResourceFinderModule#isChildSupported()
    *
    * @return true
    */
   public boolean isChildSupported()
   {
      return true;
   }

   /**
    * @see ResourceFinderModule#isDescendantSupported()
    *
    * @return true
    */
   public boolean isDescendantSupported()
   {
      return true;
   }

   /**
    * @see ResourceFinderModule#findChildResources(com.sun.xacml.attr.AttributeValue, 
    *                com.sun.xacml.EvaluationCtx)  
    */
   public ResourceFinderResult findChildResources(AttributeValue root, EvaluationCtx context)
   {
      //Validate the root 
      if (preValidateRequest(root) == false)
         return new ResourceFinderResult();

      // add the root to the set of resolved resources
      HashSet set = new HashSet();
      set.add(root);

      // add the other resources, which are defined by the conformance tests
      try
      {
         set.add(new AnyURIAttribute(new URI("urn:root:child1")));
         set.add(new AnyURIAttribute(new URI("urn:root:child2")));
      }
      catch (URISyntaxException ex)
      {
      }

      return new ResourceFinderResult(set);
   }

   /**
    * @see ResourceFinderModule#findDescendantResources(com.sun.xacml.attr.AttributeValue, 
    *             com.sun.xacml.EvaluationCtx) 
    */
   public ResourceFinderResult findDescendantResources(AttributeValue root, EvaluationCtx context)
   {
      // Validate the root 
      if (preValidateRequest(root) == false)
         return new ResourceFinderResult();

      // add the root to the set of resolved resources
      HashSet set = new HashSet();
      set.add(root);

      // add the other resources, which are defined by the conformance tests
      try
      {
         set.add(new AnyURIAttribute(new URI("urn:root:child1")));
         set.add(new AnyURIAttribute(new URI("urn:root:child1:descendant1")));
         set.add(new AnyURIAttribute(new URI("urn:root:child1:descendant2")));
         set.add(new AnyURIAttribute(new URI("urn:root:child2")));
         set.add(new AnyURIAttribute(new URI("urn:root:child2:descendant1")));
         set.add(new AnyURIAttribute(new URI("urn:root:child2:descendant2")));
      }
      catch (URISyntaxException ex)
      {
      }
      return new ResourceFinderResult(set);
   }

   /**
    * Verify the root
    */
   private boolean preValidateRequest(AttributeValue root)
   {
      String rootType = root.getType().toString();

      //Check that the resource-id for the root is a URI
      if (AnyURIAttribute.identifier.equals(rootType) == false)
         return false;

      AnyURIAttribute uriRoot = (AnyURIAttribute) root;

      //Is root == urn:root?
      if ("urn:root".equals(uriRoot.toString()) == false)
         return false;

      return true;
   }

}
