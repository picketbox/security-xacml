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
package org.jboss.test.security.test.xacml;

import java.net.URI;
import java.util.HashSet;
import java.util.Set;

import junit.framework.TestCase;

import org.jboss.security.xacml.sunxacml.attr.StringAttribute;
import org.jboss.security.xacml.sunxacml.ctx.Attribute;
import org.jboss.security.xacml.sunxacml.ctx.RequestCtx;
import org.jboss.security.xacml.sunxacml.ctx.Subject;

//$Id: XACMLRequestCreationUnitTestCase.java 45705 2006-06-20 17:30:10Z asaldhana $

/**
 *  Test creation of XACML Requests
 *  @author <a href="mailto:Anil.Saldhana@jboss.org">Anil Saldhana</a>
 *  @since  Jun 20, 2006 
 *  @version $Revision: 45705 $
 */
public class XACMLRequestCreationUnitTestCase extends TestCase
{
   private static final boolean DEBUG = true;

   public XACMLRequestCreationUnitTestCase(String name)
   {
      super(name);
   }

   public void testCreationOfRequest() throws Exception
   {
      //refer to the src/resources/security/xacml/test1/request.xml

      //Create the subject set
      URI subjectAttrUri = new URI("urn:oasis:names:tc:xacml:1.0:subject:subject-id");
      Set subjectAttributeValues = new HashSet();
      subjectAttributeValues.add(new StringAttribute("Anil Saldhana"));
      Attribute subjectAttr = new Attribute(subjectAttrUri, new URI(StringAttribute.identifier), null, null,
            subjectAttributeValues);
      Set subjectAttrSet = new HashSet();
      subjectAttrSet.add(subjectAttr);
      Set subjectSet = new HashSet();
      subjectSet.add(new Subject(subjectAttrSet));

      //Create the resource set
      URI resourceUri = new URI("urn:oasis:names:tc:xacml:1.0:resource:resource-id");
      Set resourceAttributeValues = new HashSet();
      resourceAttributeValues.add(new StringAttribute("http://jboss.com/developers/payroll/anilsaldhana"));
      Attribute resourceAttr = new Attribute(resourceUri, new URI(StringAttribute.identifier), null, null,
            resourceAttributeValues);
      Set resourceSet = new HashSet();
      resourceSet.add(resourceAttr);

      //Create the action set
      URI actionUri = new URI("urn:oasis:names:tc:xacml:1.0:action:action-id");
      Set actionAttributeValues = new HashSet();
      actionAttributeValues.add(new StringAttribute("read"));
      Attribute actionAttr = new Attribute(actionUri, new URI(StringAttribute.identifier), null, null,
            actionAttributeValues);
      Set actionSet = new HashSet();
      actionSet.add(actionAttr);

      //Create the environment set
      Set environSet = new HashSet();

      RequestCtx request = new RequestCtx(subjectSet, resourceSet, actionSet, environSet);
      assertNotNull("XACML Request != null", request);

      //Log the request for viewing
      if (DEBUG)
         XACMLUtil.logRequest(request);

      //Test the request contents
      Set subjects = request.getSubjects();
      assertTrue("We have one subject?", subjects.size() == 1);
      Subject subj = (Subject) (subjects.iterator().next());
      assertNotNull("Subject != null", subj);
      assertEquals("Attributes in subject match", subjectAttr, (Attribute) (subj.getAttributes().iterator().next()));

      //Test the resource attributes
      Set resources = request.getResource();
      assertTrue("# of resources = 1", resources.size() == 1);
      assertEquals("Attributes in resources match", resourceAttr, (Attribute) (resources.iterator().next()));

      //Test the action attributes
      Set actions = request.getAction();
      assertTrue("# of actions = 1", actions.size() == 1);
      assertEquals("Attributes in actions match", actionAttr, (Attribute) (actions.iterator().next()));
   }
}
