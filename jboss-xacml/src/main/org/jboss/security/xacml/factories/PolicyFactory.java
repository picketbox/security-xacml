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
package org.jboss.security.xacml.factories;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.reflect.Constructor; 

import javax.xml.bind.JAXB;
import javax.xml.bind.JAXBElement;

import org.jboss.security.xacml.bridge.JBossPolicyFinder;
import org.jboss.security.xacml.core.JBossXACMLPolicy;
import org.jboss.security.xacml.core.SecurityActions;
import org.jboss.security.xacml.core.model.policy.ObjectFactory;
import org.jboss.security.xacml.core.model.policy.PolicyType;
import org.jboss.security.xacml.interfaces.XACMLPolicy; 
 

//$Id$

/**
 *  A Policy Factory that creates XACML Policy
 *  or Policy Sets
 *  @author Anil.Saldhana@redhat.com
 *  @since  Jul 5, 2007 
 *  @version $Revision$
 */
public class PolicyFactory
{ 
   public static Class<?> constructingClass = JBossXACMLPolicy.class;
   
   public static void setConstructingClass(Class<?> clazz)
   {
     if(XACMLPolicy.class.isAssignableFrom(clazz) == false)
        throw new RuntimeException("clazz is not of type XACMLPolicy");
     constructingClass = clazz;
   }
   
   public static void setConstructingClass(String fqn)
   {
      ClassLoader tcl = SecurityActions.getContextClassLoader(); 
      try
      {
         setConstructingClass(tcl.loadClass(fqn)); 
      }
      catch (Exception e)
      {
         throw new RuntimeException(e);
      }
   }
   
   
   public static XACMLPolicy createPolicySet(InputStream policySetFile)
   throws Exception
   { 
      return (XACMLPolicy) getCtr().newInstance(new Object[]{policySetFile, 
                                                             XACMLPolicy.POLICYSET});
   }
   
   public static XACMLPolicy createPolicySet(InputStream policySetFile,
         JBossPolicyFinder theFinder)
   throws Exception
   { 
      return (XACMLPolicy) getCtrWithFinder().newInstance(new Object[]{policySetFile, 
                                                             XACMLPolicy.POLICYSET,
                                                             theFinder});
   }
   
   public static XACMLPolicy createPolicy(InputStream policyFile)
   throws Exception
   { 
      return (XACMLPolicy) getCtr().newInstance(new Object[]
                                                  {
                                                     policyFile, 
                                                     XACMLPolicy.POLICY
                                                  }
                                           );
   }
   
   public static XACMLPolicy createPolicy(PolicyType policyFile)
   throws Exception
   { 
      JAXBElement<PolicyType> jaxbPolicy = new ObjectFactory().createPolicy(policyFile);
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      JAXB.marshal(jaxbPolicy, baos);
      ByteArrayInputStream bis = new ByteArrayInputStream(baos.toByteArray());
      return (XACMLPolicy) getCtr().newInstance(new Object[]
                                                  { bis, 
                                                     XACMLPolicy.POLICY
                                                  }
                                           );
   }
   
   @SuppressWarnings("unchecked")
   private static Constructor<XACMLPolicy> getCtr() throws  Exception 
   {
      return (Constructor<XACMLPolicy>) constructingClass.getConstructor(new Class[] {
                                                          InputStream.class, 
                                                          Integer.TYPE });
   }
   
   @SuppressWarnings("unchecked")
   private static Constructor<XACMLPolicy> getCtrWithFinder() throws  Exception 
   {
      return (Constructor<XACMLPolicy>) constructingClass.getConstructor(new Class[] {
                                                          InputStream.class, 
                                                          Integer.TYPE ,
                                                          JBossPolicyFinder.class});
   }
}
