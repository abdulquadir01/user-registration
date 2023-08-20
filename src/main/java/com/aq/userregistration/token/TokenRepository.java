package com.aq.userregistration.token;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;


public interface TokenRepository extends JpaRepository<Token, Long> {

    @Query("""
        select t from Token t inner join User u on t.user.id = u.id
        where u.id = :userId and (t.isExpired = false or t.isRevoked = false)
    """)
    List<Token> findAllValidTokensByUser(Long userId);


    Optional<Token> findByAccessToken(String token);

}
