/*******************************************************************************
 * Copyright (c) 2014 IBM Corporation and others.
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
package com.ibm.ws.sib.utils.ras;

import com.ibm.ws.sib.utils.ras.SibTr.Suppressor;

/* ************************************************************************** */
/**
 * A Trace suppressor that suppresses every message with the same key
 *
 */
/* ************************************************************************** */
public class AllAfterFirstSuppressor extends AbstractSuppressor implements Suppressor
{
  /* -------------------------------------------------------------------------- */
  /* suppress method
  /* -------------------------------------------------------------------------- */
  /**
   * @see com.ibm.ws.sib.utils.ras.SibTr.Suppressor#suppress(java.lang.String, java.lang.String)
   * @param msgkey The message key
   * @param formattedMessage The formatted message resolved for language and inserts
   * @return true if the message should be suppressor
   */
  public synchronized SibTr.Suppressor.Decision suppress(String msgkey, String formattedMessage)
  {
    return super.suppress(msgkey,null);
  }
}
