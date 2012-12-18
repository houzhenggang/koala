package org.koala.util;

import java.security.Provider;
import java.security.Security;
import java.util.HashSet;
import java.util.Set;

public class SecurityTool {
	public static Set<String> findServiceTypes() {
		Set<String> result = new HashSet<String>();
		Provider[] providers = Security.getProviders();
		for (Provider provider : providers) {
			Set<Object> sets = provider.keySet();
			for (Object keyObj : sets) {
				if (keyObj instanceof String) {
					String key = ((String) keyObj).split(" ")[0];
					if (key.startsWith("Alg.Alias.")) {
						key = key.substring(10);
					}
					int position = key.indexOf(".");
					result.add(key.substring(0, position));
				}
			}
		}
		return result;
	}

	public static Set<String> findCryptoImpls(String serviceType) {
		Set<String> result = new HashSet<String>();
		Provider[] providers = Security.getProviders();
		for (Provider provider : providers) {
			Set<Object> sets = provider.keySet();
			for (Object keyObj : sets) {
				if (keyObj instanceof String) {
					String key = ((String) keyObj).split(" ")[0];
					if (key.startsWith(serviceType + ".")) {
						result.add(key.substring(serviceType.length() + 1));
					} else if (key.startsWith("Alg.Alias." + serviceType + ".")) {
						result.add(key.substring(serviceType.length() + 11));

					}
				}
			}
		}
		return result;
	}

}
