package com.example.ecom.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

public class JwtUtil {

    public static final String SECRET="f3n4jn6jruf65656563n46jnjru6fjuhh6f3n46jnjruf65656563n4jnjr6ufjuhh65nrfgjnrnf6866juhthnrfgjnrn5nrfgjnrnf6866juhyhhjn6rfgjnrn";

    //generate jwt token

    public String generateToken(String userName){

     Map<String,Object> claims=new HashMap<>();
     return createToken(claims,userName);
    }

    private String createToken(Map<String,Object> claims,String userName){
return Jwts.builder()
        .setClaims(claims)
        .setSubject(userName)
        .setIssuedAt(new Date(System.currentTimeMillis()))
        .setExpiration(new Date(System.currentTimeMillis()+1000*60*30)) //30 min
        .signWith(getsignKey(), SignatureAlgorithm.HS256).compact();
    }

    private Key getsignKey(){
        byte[] keybytes= Decoders.BASE64.decode(SECRET);
        return Keys.hmacShaKeyFor(keybytes);
    }

    public String extractUserName(String token){
        return  extractClaim(token, Claims::getSubject);
    }
    public <T> T extractClaim(String token, Function<Claims,T>claimsResolver){
        final Claims claims=extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token){
       return Jwts.parserBuilder().setSigningKey(getsignKey()).build().parseClaimsJws(token).getBody();
    }

    private Boolean isTokenExpired(String token){
        return extractExpiration(token).before(new Date());
    }
public Date extractExpiration(String token){
      return extractClaim(token,Claims::getExpiration);
}
public Boolean validateToken(String token, UserDetails userDetails){
        final String username=extractUserName(token);
        return(username.equals(userDetails.getUsername()) && !isTokenExpired(token));
}

}
