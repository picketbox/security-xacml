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
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import org.jboss.security.xacml.sunxacml.EvaluationCtx;
import org.jboss.security.xacml.sunxacml.attr.AttributeDesignator;
import org.jboss.security.xacml.sunxacml.attr.BagAttribute;
import org.jboss.security.xacml.sunxacml.attr.StringAttribute;
import org.jboss.security.xacml.sunxacml.cond.EvaluationResult;
import org.jboss.security.xacml.sunxacml.ctx.Status;
import org.jboss.security.xacml.sunxacml.finder.AttributeFinderModule;

//$Id: TestRoleAttributeFinderModule.java 58115 2006-11-04 08:42:14Z scott.stark@jboss.org $

/**
 *  An attribute finder module for testing that only deals with the
 *  role identifier called as
 *  "urn:oasis:names:tc:xacml:1.0:example:attribute:role"
 *  @author <a href="mailto:Anil.Saldhana@jboss.org">Anil Saldhana</a>
 *  @since  May 26, 2006 
 *  @version $Revision: 58115 $
 */

public class TestRoleAttributeFinderModule extends AttributeFinderModule
{
   /**
    * XACML Identifier supported by this module
    */
   public static final String ROLE_IDENTIFIER = "urn:oasis:names:tc:xacml:1.0:example:attribute:role";

   // subject-id standard identifier
   private static URI SUBJECT_IDENTIFIER = null;

   private static URI SUBJECT_SOMEATTRIBUTE_IDENTIFIER = null;

   // initialize the standard subject identifier
   static
   {
      try
      {
         SUBJECT_IDENTIFIER = new URI("urn:oasis:names:tc:xacml:1.0:subject:subject-id");
         SUBJECT_SOMEATTRIBUTE_IDENTIFIER = new URI("urn:oasis:names:tc:xacml:2.0:jboss-test:some-attribute");
      }
      catch (URISyntaxException ex)
      {
      }
   };

   /**
    * Default constructor.
    */
   public TestRoleAttributeFinderModule()
   {

   }

   /**
    * @see AttributeFinderModule#isDesignatorSupported()
    *
    * @return true
    */
   public boolean isDesignatorSupported()
   {
      return true;
   }

   /**
    * @see AttributeFinderModule#getSupportedDesignatorTypes()
    * Returns only <code>SUBJECT_TARGET</code> since this module only
    * supports Subject attributes.
    *
    * @return a <code>Set</code> with an <code>Integer</code> of value
    *         <code>AttributeDesignator.SUBJECT_TARGET</code>
    */
   public Set getSupportedDesignatorTypes()
   {
      Set set = new HashSet();
      set.add(new Integer(AttributeDesignator.SUBJECT_TARGET));
      return set;
   }

   /**
    * @see AttributeFinderModule#getSupportedIds()
    *
    * @return a <code>Set</code> containing <code>ROLE_IDENTIFIER</code>
    */
   public Set getSupportedIds()
   {
      Set set = new HashSet();
      set.add(ROLE_IDENTIFIER);
      return set;
   }

   /**
    * Supports the retrieval of exactly one kind of attribute.
    */
   public EvaluationResult findAttribute(URI attributeType, URI attributeId, URI issuer, URI subjectLogger,
         EvaluationCtx context, int designatorType)
   {
      // Check the identifier 
      if (!attributeId.toString().equals(ROLE_IDENTIFIER))
         return new EvaluationResult(BagAttribute.createEmptyBag(attributeType));

      // Did they ask for a String??
      if (!attributeType.toString().equals(StringAttribute.identifier))
         return new EvaluationResult(BagAttribute.createEmptyBag(attributeType));

      // Retrieve the subject identifer from the context
      EvaluationResult result = context.getSubjectAttribute(attributeType, SUBJECT_IDENTIFIER, issuer, subjectLogger);
      if (result.indeterminate())
         return result;

      // Check that we succeeded in getting the subject identifier
      BagAttribute bag = (BagAttribute) (result.getAttributeValue());
      if (bag.isEmpty())
      {
         ArrayList code = new ArrayList();
         code.add(Status.STATUS_MISSING_ATTRIBUTE);
         Status status = new Status(code, "missing subject-id");
         return new EvaluationResult(status);
      }

      // Finally search for the subject with the role-mapping defined,
      // and if there is a match, add their role
      BagAttribute returnBag = null;
      Iterator it = bag.iterator();
      while (it.hasNext())
      {
         StringAttribute attr = (StringAttribute) (it.next());
         if (attr.getValue().equals("Anil Saldhana"))
         {
            Set set = new HashSet();
            set.add(new StringAttribute("Developer"));
            returnBag = new BagAttribute(attributeType, set);
            break;
         }
      }

      return new EvaluationResult(returnBag);
   }
}
