/*******************************************************************************
 * Copyright (c) 2015, 2024 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 *
 * Contributors:
 *     IBM Corporation - initial API and implementation
 *******************************************************************************/
package com.ibm.ws.security.authorization.jacc.ejb.impl;

import java.security.AccessController;
import java.security.Permission;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.HashMap;
import java.util.List;

import javax.ejb.EnterpriseBean;
import javax.ejb.SessionContext;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.security.auth.Subject;
import javax.security.jacc.PolicyContext;

import com.ibm.websphere.ras.Tr;
import com.ibm.websphere.ras.TraceComponent;
import com.ibm.ws.ffdc.annotation.FFDCIgnore;
import com.ibm.ws.security.authorization.jacc.common.PolicyContextHandlerImpl;
import com.ibm.ws.security.authorization.jacc.common.PolicyProxy;
import com.ibm.ws.security.authorization.jacc.ejb.EJBSecurityValidator;

public class EJBSecurityValidatorImpl implements EJBSecurityValidator {
    private static final TraceComponent tc = Tr.register(EJBSecurityValidatorImpl.class);

    /** Keys for Java / Jakarta EE 8 and lower. */
    private static String[] jaccHandlerKeyArrayEe8 = new String[] { "javax.security.auth.Subject.container", "javax.ejb.EnterpriseBean", "javax.ejb.arguments",
                                                                    "javax.xml.soap.SOAPMessage" };

    /** Keys for Jakarta EE 9 and higher. */
    private static String[] jaccHandlerKeyArrayEe9 = new String[] { "javax.security.auth.Subject.container", "jakarta.ejb.EnterpriseBean", "jakarta.ejb.arguments",
                                                                    "jakarta.xml.soap.SOAPMessage" };

    private static PolicyContextHandlerImpl pch = PolicyContextHandlerImpl.getInstance();

    /**
     * Are we running with <code>jakarta.ejb.*</code> packages? This will indicate we are running with (at least) Jakarta EE 9.
     *
     * This check may seem silly on the surface, but the packages are transformed at build time to swap the <code>javax.ejb.*</code> packages with
     * <code>jakarta.ejb.*</code>.
     */
    private static boolean isEENineOrHigher = SessionContext.class.getCanonicalName().startsWith("jakarta.ejb");

    public EJBSecurityValidatorImpl() {
    }

    @Override
    public boolean checkResourceConstraints(String contextId, List<Object> methodParameters, Object bean, Permission ejbPerm, Subject subject, PolicyProxy policyProxy) {
        boolean result = false;
        final String fci = contextId;
        final HashMap<String, Object> ho = new HashMap<String, Object>();
        final Subject s = subject;
        final Object[] ma = null;

        /*
         * TODO Doesn't seem to handle EJB-3.0 annotated beans.
         */
        EnterpriseBean eb = null;
        if (bean != null) {
            try {
                eb = (EnterpriseBean) bean;
            } catch (ClassCastException cce) {
                Tr.error(tc, "JACC_EJB_SPI_PARAMETER_ERROR", new Object[] { bean.getClass().getName(), "checkResourceConstraints", "EnterpriseBean" });
                return false;
            }
        }
        final EnterpriseBean b = eb;
        if (methodParameters != null && methodParameters.size() > 0) {
            methodParameters.toArray(new Object[methodParameters.size()]);
        }
        final Permission p = ejbPerm;
        try {
            result = checkMethodConstraints(fci, ma, b, p, s, ho, policyProxy);
        } catch (PrivilegedActionException pae) {
            Tr.error(tc, "JACC_EJB_IMPLIES_FAILURE", new Object[] { contextId, pae.getException() });
        } // Moved resetHandlerInfo to postInvoke.
        return result;
    }

    private boolean checkMethodConstraints(final String contextId,
                                           final Object[] methodParameters,
                                           final EnterpriseBean bean,
                                           final Permission permission,
                                           final Subject subject,
                                           final HashMap<String, Object> handlerObjects,
                                           final PolicyProxy policyProxy) throws PrivilegedActionException {
        Boolean result = Boolean.FALSE;
        result = AccessController.doPrivileged(
                                               new PrivilegedExceptionAction<Boolean>() {
                                                   @Override
                                                   public Boolean run() throws javax.security.jacc.PolicyContextException {
                                                       PolicyContext.setContextID(contextId);

                                                       if (tc.isDebugEnabled())
                                                           Tr.debug(tc, "Registering JACC context handlers");

                                                       for (String key : jaccHandlerKeyArrayEe8) {
                                                           PolicyContext.registerHandler(key, pch, true);
                                                       }
                                                       for (String key : jaccHandlerKeyArrayEe9) {
                                                           PolicyContext.registerHandler(key, pch, true);
                                                       }

                                                       handlerObjects.put(jaccHandlerKeyArrayEe8[0], subject);
                                                       handlerObjects.put(jaccHandlerKeyArrayEe8[1], bean);
                                                       handlerObjects.put(jaccHandlerKeyArrayEe8[2], methodParameters);

                                                       handlerObjects.put(jaccHandlerKeyArrayEe9[0], subject);
                                                       handlerObjects.put(jaccHandlerKeyArrayEe9[1], bean);
                                                       handlerObjects.put(jaccHandlerKeyArrayEe9[2], methodParameters);

                                                       /*
                                                        * EE 8 and below support JAX-RPC MessageContext. EE 9 removed this support.
                                                        */
                                                       if (!isEENineOrHigher) {
                                                           Object mc = null;
                                                           try {
                                                               InitialContext ic = new InitialContext();
                                                               mc = getMessageContext(ic);
                                                           } catch (NamingException e) {
                                                               if (tc.isDebugEnabled())
                                                                   Tr.debug(tc, "NamingException is caught. Ignoring.", e);
                                                           }
                                                           if (mc != null) {
                                                               if (tc.isDebugEnabled())
                                                                   Tr.debug(tc, "javax.xml.soap.SOAPMessage is set: ", mc);
                                                               handlerObjects.put(jaccHandlerKeyArrayEe8[3], mc);
                                                           }
                                                       }

                                                       if (tc.isDebugEnabled())
                                                           Tr.debug(tc, "Setting JACC handler data");
                                                       PolicyContext.setHandlerData(handlerObjects);
                                                       if (tc.isDebugEnabled())
                                                           Tr.debug(tc, "Calling JACC implies. subject : " + subject);
                                                       return policyProxy.implies(contextId, subject, permission);
                                                   }
                                               });
        return result.booleanValue();
    }

    @FFDCIgnore({ NamingException.class, IllegalStateException.class })
    public Object getMessageContext(Context c) {
        Object mc = null;
        try {
            SessionContext sc = (SessionContext) c.lookup("java:comp/EJBContext");
            if (sc != null) {
                mc = sc.getMessageContext();
            }
        } catch (NamingException ne) {
            if (tc.isDebugEnabled())
                Tr.debug(tc, "NamingException is caught. Safe to ignore.", ne);
        } catch (IllegalStateException ise) {
            if (tc.isDebugEnabled())
                Tr.debug(tc, "IllegalStateException is caught. Safe to ignore.", ise);
        }
        return mc;
    }
}
