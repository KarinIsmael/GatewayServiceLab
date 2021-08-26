import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class JWTJavaWithPublicPrivateKey {

    public static void main(String[] args) {

        System.out.println("generating keys");
        KeyPair rsaKeys = null;

        try {
            rsaKeys = getRSAKeys();
        } catch (Exception e) {
            e.printStackTrace();
        }
        PublicKey publicKey = rsaKeys.getPublic();
        PrivateKey privateKey = rsaKeys.getPrivate();

        System.out.println("generated keys");

        String token = generateToken(privateKey);
        System.out.println("Generated Token:\n" + token);

        verifyToken(token, publicKey);
    }

    public static String generateToken(PrivateKey privateKey) {
        String token = null;
        try {
            Map<String, Object> claims = new HashMap<>();

            claims.put("id", "xxx");
            claims.put("role", "user");
            claims.put("created", new Date());

            token = Jwts.builder().setClaims(claims).signWith(SignatureAlgorithm.RS512, privateKey).compact();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return token;
    }

    private static void verifyToken(String token, PublicKey publicKey) {
        Claims claims;
        try {
            claims = Jwts.parser().setSigningKey(publicKey).parseClaimsJws(token).getBody();
            System.out.println(claims.get("id"));
            System.out.println(claims.get("role"));
        } catch (Exception e) {
            claims = null;
        }
    }

    private static KeyPair getRSAKeys() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

}
