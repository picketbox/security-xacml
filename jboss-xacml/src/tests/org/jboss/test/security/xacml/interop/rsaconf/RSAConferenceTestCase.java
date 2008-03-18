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
package org.jboss.test.security.xacml.interop.rsaconf;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

import junit.framework.TestCase;

import org.jboss.security.xacml.interfaces.RequestContext;

/**
 * A RSAConferenceTestCase.
 * 
 * @author Marcus Moyses
 * @since Mar 18, 2008
 */
public class RSAConferenceTestCase extends TestCase
{

   public void testRequest1() throws Exception
   {
      Principal doctor = new Principal()
      {
         public String getName()
         {
            return "Dr. Alice";
         }
      };

      List<String> permissions = new ArrayList<String>();
      permissions.add("urn:oasis:names:tc:xacml:interop:hl7:prd-003");
      permissions.add("urn:oasis:names:tc:xacml:interop:hl7:prd-005");
      permissions.add("urn:oasis:names:tc:xacml:interop:hl7:prd-006");
      permissions.add("urn:oasis:names:tc:xacml:interop:hl7:prd-009");
      permissions.add("urn:oasis:names:tc:xacml:interop:hl7:prd-010");
      permissions.add("urn:oasis:names:tc:xacml:interop:hl7:prd-012");
      permissions.add("urn:oasis:names:tc:xacml:interop:hl7:prd-017");

      String patient = "Anthony Gurrola";

      List<String> confidentialityCodes = new ArrayList<String>();
      confidentialityCodes.add("CDA");
      confidentialityCodes.add("N");

      List<String> consentedIds = new ArrayList<String>();
      consentedIds.add("Dr. Alice");

      String resourceType = "urn:oasis:names:tc:xacml:interop:resource:hl7-medical-record";

      RequestContext request = Util.createRequestWithHL7Permissions(doctor, permissions, patient, confidentialityCodes,
            consentedIds, resourceType);

      request.marshall(System.out);
   }

   public void testRequest2() throws Exception
   {
      Principal doctor = new Principal()
      {
         public String getName()
         {
            return "Dr. Alice";
         }
      };

      List<String> roles = new ArrayList<String>();
      roles.add("urn:oasis:names:tc:xacml:interop:role:physician");

      String patient = "Anthony Gurrola";

      List<String> confidentialityCodes = new ArrayList<String>();
      confidentialityCodes.add("CDA");
      confidentialityCodes.add("U");

      List<String> consentedIds = new ArrayList<String>();
      consentedIds.add("Dr. Alice");

      String resourceType = "urn:oasis:names:tc:xacml:interop:resource:hl7-medical-record";

      RequestContext request = Util.createRequestWithNormalRoles(doctor, roles, patient, confidentialityCodes,
            consentedIds, resourceType);

      request.marshall(System.out);
   }
}
