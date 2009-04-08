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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.jboss.security.xacml.bridge.JBossPolicyFinder;
import org.jboss.security.xacml.interfaces.ContextMapOp;
import org.jboss.security.xacml.interfaces.XACMLConstants;
import org.jboss.security.xacml.interfaces.XACMLPolicy;
import org.jboss.security.xacml.sunxacml.AbstractPolicy;
import org.jboss.security.xacml.util.XACMLPolicyUtil;

/**
 *  JBossXACML Policy
 *  @author Anil.Saldhana@redhat.com
 *  @since  Jul 6, 2007 
 *  @version $Revision$
 */
public class JBossXACMLPolicy implements XACMLPolicy, ContextMapOp
{
   private JBossPolicyFinder finder = new JBossPolicyFinder();

   private List<XACMLPolicy> enclosingPolicies = new ArrayList<XACMLPolicy>();

   private int policyType = XACMLPolicy.POLICY;

   private Map<String, Object> map = new HashMap<String, Object>();

   /**
    * Construct a JBossXACMLPolicy  
    * @param url url to the policy file
    * @param type type (Policy or PolicySet) 
    * @throws Exception
    * @see XACMLConstants
    */
   public JBossXACMLPolicy(URL url, int type) throws Exception
   {
      this(url.openStream(), type);
   }

   /**
    * Construct a JBossXACMLPolicy
    * @param is Inputstream to the policy file
    * @param type type (Policy or PolicySet)
    * @throws Exception
    * @see XACMLConstants
    */
   public JBossXACMLPolicy(InputStream is, int type) throws Exception
   {
      AbstractPolicy policy = null;
      XACMLPolicyUtil xpu = new XACMLPolicyUtil();
      this.policyType = type;
      if (type == XACMLPolicy.POLICYSET)
      {
         policy = xpu.createPolicySet(is, finder);
         map.put(XACMLConstants.POLICY_FINDER, finder);
      }
      else if (type == XACMLPolicy.POLICY)
      {
         policy = xpu.createPolicy(is);
      }
      else
         throw new RuntimeException("Unknown type");

      map.put(XACMLConstants.UNDERLYING_POLICY, policy);
   }

   /**
    * Construct a JBossXACMLPolicy instance
    * @param is Inputstream to the policy/policyset file
    * @param type policy or policyset
    * @param theFinder PolicySet processing needs this
    * @throws Exception
    * @see XACMLConstants
    */
   public JBossXACMLPolicy(InputStream is, int type, JBossPolicyFinder theFinder) throws Exception
   {
      AbstractPolicy policy = null;
      XACMLPolicyUtil xpu = new XACMLPolicyUtil();
      this.policyType = type;
      if (type == XACMLPolicy.POLICYSET)
      {
         if (theFinder == null)
            throw new IllegalArgumentException("policy finder is null");
         this.finder = theFinder;
         policy = xpu.createPolicySet(is, theFinder);
         map.put(XACMLConstants.POLICY_FINDER, theFinder);
      }
      else if (type == XACMLPolicy.POLICY)
      {
         policy = xpu.createPolicy(is);
      }
      else
         throw new RuntimeException("Unknown type");

      map.put(XACMLConstants.UNDERLYING_POLICY, policy);
   }

   /**
    * @see XACMLPolicy#getType()
    * @see XACMLConstants
    */
   public int getType()
   {
      return this.policyType;
   }

   /**
    * @see XACMLPolicy#setEnclosingPolicies(List)
    */
   public void setEnclosingPolicies(List<XACMLPolicy> policies)
   {
      enclosingPolicies.addAll(policies);
   }

   /**
    * @see XACMLPolicy#getEnclosingPolicies()
    */
   public List<XACMLPolicy> getEnclosingPolicies()
   {
      return enclosingPolicies;
   }

   /**
    * @see ContextMapOp#get(String)
    */
   @SuppressWarnings("unchecked")
   public <T> T get(String key)
   {
      return (T) map.get(key);
   }

   /**
    * @see ContextMapOp#set(String, Object)
    */
   public <T> void set(String key, T obj)
   {
      map.put(key, obj);
   }
}
