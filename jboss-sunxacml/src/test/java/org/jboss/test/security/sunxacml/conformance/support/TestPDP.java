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
package org.jboss.test.security.sunxacml.conformance.support;

import java.io.FileInputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.jboss.security.xacml.sunxacml.PDP;
import org.jboss.security.xacml.sunxacml.PDPConfig;
import org.jboss.security.xacml.sunxacml.combine.PermitOverridesPolicyAlg;
import org.jboss.security.xacml.sunxacml.ctx.RequestCtx;
import org.jboss.security.xacml.sunxacml.ctx.ResponseCtx;
import org.jboss.security.xacml.sunxacml.finder.AttributeFinder;
import org.jboss.security.xacml.sunxacml.finder.AttributeFinderModule;
import org.jboss.security.xacml.sunxacml.finder.PolicyFinder;
import org.jboss.security.xacml.sunxacml.finder.PolicyFinderModule;
import org.jboss.security.xacml.sunxacml.finder.impl.CurrentEnvModule;
import org.jboss.security.xacml.sunxacml.finder.impl.SelectorModule;
import org.jboss.security.xacml.sunxacml.support.finder.StaticPolicyFinderModule;
import org.jboss.security.xacml.sunxacml.support.finder.StaticRefPolicyFinderModule;
import org.jboss.security.xacml.sunxacml.support.finder.URLPolicyFinderModule;

/**
 * PDP for the conformance Tests
 * @author Anil.Saldhana@redhat.com
 * @since Mar 24, 2009
 */
public class TestPDP
{ 
   private PDP pdp = null;
  
   private PolicyFinder policyFinder = null;
   private AttributeFinder attributeFinder = null;
   
   @SuppressWarnings("unchecked")
   public TestPDP(String[] policies)
   {
      List policyList = Arrays.asList(policies);
      StaticPolicyFinderModule staticModule = null;
      try
      {
         staticModule = new StaticPolicyFinderModule(PermitOverridesPolicyAlg.algId, policyList);
      }
      catch (Exception e)
      {
         throw new RuntimeException(e);
      } 
      StaticRefPolicyFinderModule staticRefModule = new StaticRefPolicyFinderModule(policyList);

      URLPolicyFinderModule urlModule = new URLPolicyFinderModule();

      policyFinder = new PolicyFinder();
      Set policyModules = new HashSet();
      policyModules.add(staticModule);
      policyModules.add(staticRefModule);
      policyModules.add(urlModule);
      policyFinder.setModules(policyModules);

      CurrentEnvModule envAttributeModule = new CurrentEnvModule();
      SelectorModule selectorAttributeModule = new SelectorModule();

      attributeFinder = new AttributeFinder();
      List attributeModules = new ArrayList();
      attributeModules.add(envAttributeModule);
      attributeModules.add(selectorAttributeModule);
      attributeFinder.setModules(attributeModules); 
   }
   
   @SuppressWarnings("unchecked")
   public void addAttributeFinderModule(AttributeFinderModule afm)
   {
      List modules = attributeFinder.getModules();
      modules.add(afm);
      attributeFinder.setModules(modules);
   }
   
   @SuppressWarnings("unchecked")
   public void addPolicyFinderModule(PolicyFinderModule pfm)
   {
      Set modules = policyFinder.getModules();
      modules.add(pfm);
      policyFinder.setModules(modules);
   }
   
   public void clearPolicyModules()
   {
      Set modules = new HashSet();
      policyFinder.setModules(modules);
   }
   
   public void createInternalPDP()
   {
      pdp = new PDP(new PDPConfig(attributeFinder, policyFinder, null));  
   }
   
   public ResponseCtx evaluate(String requestFile) throws Exception
   {
      InputStream is = new FileInputStream(requestFile);
      RequestCtx request = RequestCtx.getInstance(is);
      return pdp.evaluate(request);
   }
}