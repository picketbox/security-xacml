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
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.xml.XMLConstants;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.Unmarshaller;
import javax.xml.stream.XMLStreamReader;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import org.jboss.security.xacml.bridge.JBossPolicyFinder;
import org.jboss.security.xacml.factories.PolicyFactory;
import org.jboss.security.xacml.factories.RequestResponseContextFactory;
import org.jboss.security.xacml.interfaces.PolicyDecisionPoint;
import org.jboss.security.xacml.interfaces.PolicyLocator;
import org.jboss.security.xacml.interfaces.RequestContext;
import org.jboss.security.xacml.interfaces.ResponseContext;
import org.jboss.security.xacml.interfaces.XACMLConstants;
import org.jboss.security.xacml.interfaces.XACMLPolicy;
import org.jboss.security.xacml.jaxb.LocatorType;
import org.jboss.security.xacml.jaxb.LocatorsType;
import org.jboss.security.xacml.jaxb.PDP;
import org.jboss.security.xacml.jaxb.PoliciesType;
import org.jboss.security.xacml.jaxb.PolicySetType;
import org.jboss.security.xacml.jaxb.PolicyType;
import org.jboss.security.xacml.sunxacml.PDPConfig;
import org.jboss.security.xacml.sunxacml.ctx.RequestCtx;
import org.jboss.security.xacml.sunxacml.ctx.ResponseCtx;
import org.jboss.security.xacml.sunxacml.finder.AttributeFinder;
import org.jboss.security.xacml.sunxacml.finder.AttributeFinderModule;
import org.jboss.security.xacml.sunxacml.finder.PolicyFinderModule;
import org.jboss.security.xacml.sunxacml.finder.impl.CurrentEnvModule;
import org.jboss.security.xacml.sunxacml.finder.impl.SelectorModule;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;

/**
 *  PDP for JBoss XACML
 *  @author Anil.Saldhana@redhat.com
 *  @since  Jul 6, 2007 
 *  @version $Revision$
 */
public class JBossPDP implements PolicyDecisionPoint
{
   private Unmarshaller unmarshaller = null;

   private Set<PolicyLocator> locators = new HashSet<PolicyLocator>();

   private Set<XACMLPolicy> policies = new HashSet<XACMLPolicy>();

   private JBossPolicyFinder policyFinder = new JBossPolicyFinder();

   /**
    * CTR
    */
   public JBossPDP()
   {
   }

   /**
    * Create a PDP
    * @param configFile Inputstream for the JBossXACML Config File
    */
   public JBossPDP(InputStream configFile)
   {
      createValidatingUnMarshaller();
      try
      {
         JAXBElement<?> jxb = (JAXBElement<?>) unmarshaller.unmarshal(configFile);
         bootstrap((PDP) jxb.getValue());
      }
      catch (Exception e)
      {
         throw new RuntimeException(e);
      }
   }

   /**
    * Create a PDP
    * @param configFile InputSource for the JBossXACML Config File
    */
   public JBossPDP(InputSource configFile)
   {
      createValidatingUnMarshaller();
      try
      {
         JAXBElement<?> jxb = (JAXBElement<?>) unmarshaller.unmarshal(configFile);
         bootstrap((PDP) jxb.getValue());
      }
      catch (Exception e)
      {
         throw new RuntimeException(e);
      }
   }

   /**
    * Create a PDP
    * @param configFile Parsed Node for the JBossXACML Config File
    */
   public JBossPDP(Node configFile)
   {
      createValidatingUnMarshaller();
      try
      {
         JAXBElement<?> jxb = (JAXBElement<?>) unmarshaller.unmarshal(configFile);
         bootstrap((PDP) jxb.getValue());
      }
      catch (Exception e)
      {
         throw new RuntimeException(e);
      }
   }

   /**
    * Create a PDP
    * @param configFile XMLStreamReader for the JBossXACML Config File
    */
   public JBossPDP(XMLStreamReader configFile)
   {
      createValidatingUnMarshaller();
      try
      {
         JAXBElement<?> jxb = (JAXBElement<?>) unmarshaller.unmarshal(configFile);
         bootstrap((PDP) jxb.getValue());
      }
      catch (Exception e)
      {
         throw new RuntimeException(e);
      }
   }

   /**
    * Create a PDP
    * @param configFileURL URL of the JBossXACML Config File
    */
   public JBossPDP(URL configFileURL)
   {
      createValidatingUnMarshaller();
      try
      {
         JAXBElement<?> jxb = (JAXBElement<?>) unmarshaller.unmarshal(configFileURL.openStream());
         bootstrap((PDP) jxb.getValue());
      }
      catch (Exception e)
      {
         throw new RuntimeException(e);
      }
   }

   /**
    * @see PolicyDecisionPoint#setLocators(Set)
    */
   public void setLocators(Set<PolicyLocator> locators)
   {
      this.locators = locators;
   }

   /**
    * @see PolicyDecisionPoint#setPolicies(Set)
    */
   public void setPolicies(Set<XACMLPolicy> policies)
   {
      this.policies = policies;
   }

   /**
    * @see PolicyDecisionPoint#evaluate(RequestContext)
    */
   @SuppressWarnings("unchecked")
   public ResponseContext evaluate(RequestContext request)
   {
      HashSet<PolicyFinderModule> policyModules = new HashSet<PolicyFinderModule>();
      //Go through the Locators
      for (PolicyLocator locator : locators)
      {
         List finderModulesList = (List) locator.get(XACMLConstants.POLICY_FINDER_MODULE);
         if (finderModulesList == null)
            throw new IllegalStateException("Locator " + locator.getClass().getName() + " has no policy finder modules");
         policyModules.addAll(finderModulesList);
      }
      policyFinder.setModules(policyModules);

      AttributeFinder attributeFinder = new AttributeFinder();
      List<AttributeFinderModule> attributeModules = new ArrayList<AttributeFinderModule>();
      attributeModules.add(new CurrentEnvModule());
      attributeModules.add(new SelectorModule());
      attributeFinder.setModules(attributeModules);

      org.jboss.security.xacml.sunxacml.PDP pdp = new org.jboss.security.xacml.sunxacml.PDP(new PDPConfig(
            attributeFinder, policyFinder, null));
      RequestCtx req = (RequestCtx) request.get(XACMLConstants.REQUEST_CTX);
      if (req == null)
         throw new IllegalStateException("Request Context does not contain a request");

      ResponseCtx resp = pdp.evaluate(req);

      ResponseContext response = RequestResponseContextFactory.createResponseContext();
      response.set(XACMLConstants.RESPONSE_CTX, resp);
      return response;
   }

   private void bootstrap(PDP pdp) throws Exception
   {
      PoliciesType policiesType = pdp.getPolicies();
      List<PolicySetType> pset = policiesType.getPolicySet();

      this.addPolicySets(pset, true);

      //Take care of additional policies
      List<XACMLPolicy> policyList = this.addPolicies(policiesType.getPolicy());
      policies.addAll(policyList);

      //Take care of the locators
      LocatorsType locatorsType = pdp.getLocators();
      List<LocatorType> locs = locatorsType.getLocator();
      for (LocatorType lt : locs)
      {
         PolicyLocator pl = (PolicyLocator) loadClass(lt.getName()).newInstance();
         pl.setPolicies(policies);
         this.locators.add(pl);
      }
   }

   private List<XACMLPolicy> addPolicySets(List<PolicySetType> policySets, boolean topLevel) throws Exception
   {
      List<XACMLPolicy> list = new ArrayList<XACMLPolicy>();

      for (PolicySetType pst : policySets)
      {
         String loc = pst.getLocation();
         XACMLPolicy policySet = PolicyFactory.createPolicySet(getInputStream(loc), policyFinder);
         list.add(policySet);

         List<XACMLPolicy> policyList = this.addPolicies(pst.getPolicy());
         policySet.setEnclosingPolicies(policyList);

         List<PolicySetType> pset = pst.getPolicySet();
         if (pset != null)
            policySet.getEnclosingPolicies().addAll(this.addPolicySets(pset, false));

         if (topLevel)
            policies.add(policySet);
      }

      return list;
   }

   private List<XACMLPolicy> addPolicies(List<PolicyType> policies) throws Exception
   {
      List<XACMLPolicy> policyList = new ArrayList<XACMLPolicy>();
      for (PolicyType pt : policies)
      {
         policyList.add(PolicyFactory.createPolicy(getInputStream(pt.getLocation())));
      }

      return policyList;
   }

   private void createValidatingUnMarshaller()
   {
      try
      {
         JAXBContext jc = JAXBContext.newInstance("org.jboss.security.xacml.jaxb");;
         unmarshaller = jc.createUnmarshaller();
         //Validate against schema
         ClassLoader tcl = SecurityActions.getContextClassLoader();
         URL schemaURL = tcl.getResource("schema/jbossxacml-2.0.xsd");
         if(schemaURL == null)
            throw new IllegalStateException("Schema URL is null:" + "schema/jbossxacml-2.0.xsd");
         SchemaFactory scFact = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
         Schema schema = scFact.newSchema(schemaURL);
         unmarshaller.setSchema(schema);
      }
      catch (Exception jxb)
      {
         throw new RuntimeException(jxb);
      }
   }

   private InputStream getInputStream(String loc)
   {
      InputStream is = null;
      //Try URL
      try
      {
         URL url = new URL(loc);
         is = url.openStream();
      }
      catch (Exception e)
      {
      }
      if (is == null)
      {
         ClassLoader tcl = SecurityActions.getContextClassLoader();
         is = tcl.getResourceAsStream(loc);
      }
      if (is == null)
         throw new RuntimeException("Null Inputstream for " + loc);
      return is;
   }

   private Class<?> loadClass(String fqn) throws Exception
   {
      ClassLoader tcl = SecurityActions.getContextClassLoader();
      return tcl.loadClass(fqn);
   }
}
