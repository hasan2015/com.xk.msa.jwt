package com.xk.msa.jwt.security.auth.jwt.verifier;
 
/**
 * 
 * @author yanhaixun
 * @date 2017年3月18日 下午12:20:49
 *
 */
public interface TokenVerifier {
    public boolean verify(String jti);
}
