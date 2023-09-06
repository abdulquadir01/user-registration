package com.aq.userregistration.constant;

public final class AppConstants {

    private AppConstants(){
//        private constructor will not allow to make object of this class
    }

    public final static int TOKEN_VALIDITY_IN_MS = 1000 * 60 * 60;
    public final static int TOKEN_VALIDITY_IN_SEC = 60 * 60;
    public final String[] AUTHORIZED_URL = {"/api/v1/auth/**"};

    //Token types
    public enum TokenType {
        BEARER
    }

}
