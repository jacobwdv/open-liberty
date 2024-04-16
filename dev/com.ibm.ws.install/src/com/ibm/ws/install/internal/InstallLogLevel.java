package com.ibm.ws.install.internal;

import java.util.logging.Level;

public class InstallLogLevel extends Level {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	/**
	 * A FeatureUtility debug level that has a lower value than FINEST. This allows us to 
	 * provide logging at a lower level for debug / problem determination. 
	 */
	public static final Level FEATUREUTILITY_DEBUG = new InstallLogLevel("FEATUREUTILITY_DEBUG",
			Level.FINEST.intValue() - 100);

	protected InstallLogLevel(String name, int value) {
		super(name, value);
	}
}
