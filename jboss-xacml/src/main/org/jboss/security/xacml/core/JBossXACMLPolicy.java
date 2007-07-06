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

import java.io.InputStream;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import org.jboss.security.xacml.interfaces.XACMLPolicy;
import org.jboss.security.xacml.util.XACMLPolicyUtil;

import com.sun.xacml.AbstractPolicy;
import com.sun.xacml.finder.PolicyFinder;

//$Id$

/**
 *  JBossXACML Policy
 *  @author Anil.Saldhana@redhat.com
 *  @since  Jul 6, 2007 
 *  @version $Revision$
 */
public class JBossXACMLPolicy implements XACMLPolicy
{
   //The base SunXACML Policy
   private AbstractPolicy policy = null;
   private PolicyFinder policyFinder = new PolicyFinder();
   private List<XACMLPolicy> enclosingPolicies = new ArrayList<XACMLPolicy>();
   
   private int policyType = XACMLPolicy.POLICY;
   
   public JBossXACMLPolicy(URL url, int type) throws Exception
   {
      this(url.openStream(), type);
   }
   
   public JBossXACMLPolicy(InputStream is, int type) throws Exception
   {
      XACMLPolicyUtil xpu = new XACMLPolicyUtil();
      this.policyType = type;
      if(type == XACMLPolicy.POLICYSET)
      {
         policy = xpu.createPolicySet(is, policyFinder); 
      }
      else
         if(type == XACMLPolicy.POLICY)
         {
            policy = xpu.createPolicy(is); 
         }
         else
            throw new RuntimeException("Unknown type");
   }
   
   public int getType()
   {
      return this.policyType;
   }

   public void setEnclosingPolicies(List<XACMLPolicy> policies)
   { 
      enclosingPolicies.addAll(policies);
   }

   public List<XACMLPolicy> getEnclosingPolicies()
   { 
      return enclosingPolicies;
   } 
}
