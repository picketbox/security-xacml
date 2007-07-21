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
package org.jboss.security.xacml.interfaces;

//$Id$

/**
 *  Constants
 *  @author Anil.Saldhana@redhat.com
 *  @since  Jul 6, 2007 
 *  @version $Revision$
 */
public interface XACMLConstants
{
   String UNDERLYING_POLICY = "underlying_policy";
   String POLICY_FINDER = "policy_finder";
   String POLICY_FINDER_MODULE = "policy_finder_module";
   String REQUEST_CTX = "request_ctx";
   String RESPONSE_CTX = "response_ctx";
   
   String CONTEXT_SCHEMA = "urn:oasis:names:tc:xacml:2.0:context:schema:os";
   
   //Identifiers
   String ACTION_IDENTIFIER = "urn:oasis:names:tc:xacml:1.0:action:action-id";
   String CURRENT_TIME_IDENTIFIER = "urn:oasis:names:tc:xacml:1.0:environment:current-time";
   String RESOURCE_IDENTIFIER = "urn:oasis:names:tc:xacml:1.0:resource:resource-id";
   String SUBJECT_IDENTIFIER = "urn:oasis:names:tc:xacml:1.0:subject:subject-id";
   String SUBJECT_ROLE_IDENTIFIER = "urn:oasis:names:tc:xacml:2.0:subject:role";
   
   //Functions
   String FUNCTION_ANYURI_EQUALS = "urn:oasis:names:tc:xacml:1.0:function:anyURI-equal";
   String FUNCTION_STRING_EQUAL = "urn:oasis:names:tc:xacml:1.0:function:string-equal";
   String FUNCTION_STRING_IS_IN = "urn:oasis:names:tc:xacml:1.0:function:string-is-in";
   String FUNCTION_STRING_ONE_AND_ONLY = "urn:oasis:names:tc:xacml:1.0:function:string-one-and-only";
   
   /**
    * The decision to permit the request
    */
   public static final int DECISION_PERMIT = 0;

   /**
    * The decision to deny the request
    */
   public static final int DECISION_DENY = 1;

   /**
    * The decision that a decision about the request cannot be made
    */
   public static final int DECISION_INDETERMINATE = 2;

   /**
    * The decision that nothing applied to us
    */
   public static final int DECISION_NOT_APPLICABLE = 3;
}
