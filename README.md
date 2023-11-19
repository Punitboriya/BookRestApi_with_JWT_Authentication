# BookRestApi_with_JWT_Authentication
Example of Rest APIwith JWT Authentication
JWT Authentication with Spring Boot 3.0

We will see how to configure InMemory user and jwt authentication using latest spring boot 3.0.
We will create one protected endpoint and try to secure endpoint using spring boot security.
Create new Spring Boot Project
Go to spring initializer and create new project with dependencies
add the following dependencies

For Web
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
</dependency>

Lombok
<dependency>
    <groupId>org.projectlombok</groupId>
    <artifactId>lombok</artifactId>
    <optional>true</optional>
</dependency>
-----------------------------------------------------------------------------------------------------
--------------your project--------------------
check unprotectd any apis ,you can access  
now add dependency For security

<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
update project
magic -- now check  any apis - you cant access, its form base login page username and password.
username = user
password = see in cosole 
-----------------------------------------------------------------------------------------------------

--costomize username password:
add system.property:
spring.security.user.name=Punit
spring.security.user.password=Punit@123

now you can access api by this username and password. 

-----------------------------------------------------------------------------------------------------
Create InMemory user with UserDetailService Bean : 
first remove that username and password gave in system.property

Create UserDetailService bean and write the InMemory user implementation
Create CustomConfig class and create bean and also create two important bean PasswordEncoder and 
AuthenticationManager so that we can use later.

 

@Configuration
public class MyConfig {

	@Bean
	public UserDetailsService userDetailsService() {
		UserDetails user1 = User.builder().username("Punit").password(passwordEncoder().encode("Urja"))
				.roles("ADMIN").build();
		UserDetails user2 = User.builder().username("Urja").password(passwordEncoder().encode("Punit"))
				.roles("ADMIN").build();
		
//u can give n number of users here must see custructor of InMemoryUserDetailsManager
		return new InMemoryUserDetailsManager(user1,user2);
	}

//@Bean Indicates that a method produces a bean to be managed by the Spring container.
/*The Spring container plays a crucial role in promoting loose coupling and making the application more maintainable and testable. 
It allows developers to focus on writing business logic while delegating the responsibility of managing the object lifecycle to the container.
Additionally, the container supports features like dependency injection, which simplifies the process of wiring together components in an application.
Dependency Injection (DI): It's a pattern where the dependencies of a component are supplied from the outside rather than created by the component itself.*/
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
}

	
Now we can login with given username and password by default spring security provide form login .
open browser and open and test any apis
when login form is prompted just login with username and password as given .
-------------	
//see the curent user
//in controller add one method

@GetMapping("/current-user")
	public String getLoggedInUser(Principal principal){
		System.out.println(principal.getName());
		return principal.getName();
	}
-------------
JWT Authentication Flow 


For JWT

![JWT_Auth](https://github.com/Punitboriya/BookRestApi_with_JWT_Authentication/assets/126247444/824ed122-c09d-4f79-8acc-bd9e64bf3372)





 <!-- https://mvnrepository.com/artifact/io.jsonwebtoken/jjwt-api -->
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-api</artifactId>
    <version>0.11.5</version>
</dependency>

 <!-- https://mvnrepository.com/artifact/io.jsonwebtoken/jjwt-impl -->
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-impl</artifactId>
    <version>0.11.5</version>
    <scope>runtime</scope>
</dependency>

<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-jackson</artifactId> <!-- or jjwt-gson if Gson is preferred -->
    <version>0.11.5</version>
    <scope>runtime</scope>
</dependency>


Steps to implement jwt token:
1)  Make sure spring-boot-starter-security is there in pom.xml

2)  Create Class JWTAthenticationEntryPoint that implement AuthenticationEntryPoint. 
Method of this class is called whenever as exception is thrown due to unauthenticated user trying to access the resource that required authentication.

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;
import java.io.PrintWriter;

@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        PrintWriter writer = response.getWriter();
        writer.println("Access Denied !! " + authException.getMessage());
    }
}
3) Create JWTHelper  class This class contains method related to perform operations with jwt token like generateToken, validateToken etc.

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtHelper {

    //requirement :
    public static final long JWT_TOKEN_VALIDITY = 5 * 60 * 60;

    //    public static final long JWT_TOKEN_VALIDITY =  60;
    private String secret = "afafasfafafasfasfasfafacasdasfasxASFACASDFACASDFASFASFDAFASFASDAADSCSDFADCVSGCFVADXCcadwavfsfarvf";

    //retrieve username from jwt token
    public String getUsernameFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    //retrieve expiration date from jwt token
    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    //for retrieveing any information from token we will need the secret key
    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
    }

    //check if the token has expired
    private Boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }

    //generate token for user
    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        return doGenerateToken(claims, userDetails.getUsername());
    }

    //while creating the token -
    //1. Define  claims of the token, like Issuer, Expiration, Subject, and the ID
    //2. Sign the JWT using the HS512 algorithm and secret key.
    //3. According to JWS Compact Serialization(https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-3.1)
    //   compaction of the JWT to a URL-safe string
    private String doGenerateToken(Map<String, Object> claims, String subject) {

        return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY * 1000))
                .signWith(SignatureAlgorithm.HS512, secret).compact();
    }

    //validate token
    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = getUsernameFromToken(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
}

Create End Point to be secured
@RestController
public class HomeController {

    Logger logger = LoggerFactory.getLogger(HomeController.class);

    @RequestMapping("/test")
    public String test() {
        this.logger.warn("This is working message");
        return "Testing message";
    }


}
Use can create the same that we developed in video.

4) Create JWTAuthenticationFilter that extends OncePerRequestFilter and override method and write the logic to check the token that is comming in header. We have to write 5 important logic

Get Token from request
Validate Token
GetUsername from token
Load user associated with this token
set authentication

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private Logger logger = LoggerFactory.getLogger(OncePerRequestFilter.class);
    @Autowired
    private JwtHelper jwtHelper;


    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

//        try {
//            Thread.sleep(500);
//        } catch (InterruptedException e) {
//            throw new RuntimeException(e);
//        }
        //Authorization

        String requestHeader = request.getHeader("Authorization");
        //Bearer 2352345235sdfrsfgsdfsdf		

        logger.info(" Header :  {}", requestHeader);
/*method of a logger to log an informational message. 
The message is a string that includes a placeholder {} which will be replaced by the value of requestHeader when the log statement is executed. 
This is a common practice to include dynamic values in log messages without concatenating strings directly.*/
        String username = null;
        String token = null;
		
//in requestHeader somthing AND srart with Bearer 
        if (requestHeader != null && requestHeader.startsWith("Bearer")) {
            //looking good
            token = requestHeader.substring(7);
            try {

                username = this.jwtHelper.getUsernameFromToken(token);

            } catch (IllegalArgumentException e) {
                logger.info("Illegal Argument while fetching the username !!");
                e.printStackTrace();
            } catch (ExpiredJwtException e) {
                logger.info("Given jwt token is expired !!");
                e.printStackTrace();
            } catch (MalformedJwtException e) {
                logger.info("Some changed has done in token !! Invalid Token");
                e.printStackTrace();
            } catch (Exception e) {
                e.printStackTrace();
            }

        } else {
            logger.info("Invalid Header Value !! ");
        }

 //in username somthing AND User is not Autorized till now so set Authorization
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            //fetch user detail from username
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
            Boolean validateToken = this.jwtHelper.validateToken(token, userDetails);
            if (validateToken) {

                //set the authentication
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);

            } else {
                logger.info("Validation fails !!");
            }
		}
        filterChain.doFilter(request, response);
    }
}
5) Configure spring security in configuration file:

import com.restapi.book.security.JWTAuthenticationFilter;
import com.restapi.book.security.JwtAuthenticationEntryPoint;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.net.http.HttpResponse;

@Configuration
public class SecurityConfig {
    @Autowired
    private JwtAuthenticationEntryPoint point;
    @Autowired
    private JWTAuthenticationFilter filter;
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			http.
                csrf().disable().
                cors().disable().
                authorizeHttpRequests().requestMatchers("/home/**").authenticated().
                requestMatchers("/auth/login").permitAll().anyRequest().authenticated().and().
                exceptionHandling(e -> e.authenticationEntryPoint(point)).
                sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        http.addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}

6) Create JWTRequest and JWTResponse to receive request data and send Login success response.
import lombok.Data;
@Data
public class JWTRequest {
    private String email;
    private String password;
}
import lombok.Data;
@Data
public class JWTResponse {
    private String username;
    private String jwtToken;
}

7)  Create login api to accept username and password and return token if username and password is correct.

//first make bean of AuthenticationManager in MyConfig
@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration builder) throws Exception {
		return builder.getAuthenticationManager();
}
@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private UserDetailsService userDetailsService;//user information featch(email and password)

    @Autowired
    private AuthenticationManager manager;//authenticate that email and password


    @Autowired
    private JwtHelper helper;//do JWT token create 

    private Logger logger = LoggerFactory.getLogger(AuthController.class);


    @PostMapping("/login")
    public ResponseEntity<JwtResponse> login(@RequestBody JwtRequest request) {

        this.doAuthenticate(request.getEmail(), request.getPassword());

        UserDetails userDetails = userDetailsService.loadUserByUsername(request.getEmail());
        String token = this.helper.generateToken(userDetails);

        JwtResponse response = JwtResponse.builder()
                .jwtToken(token)
                .username(userDetails.getUsername()).build();
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    private void doAuthenticate(String email, String password) {

        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(email, password);
        try {
            manager.authenticate(authentication);
        } catch (BadCredentialsException e) {
            throw new BadCredentialsException(" Invalid Username or Password  !!");
        }
    }
    @ExceptionHandler(BadCredentialsException.class)
    public String exceptionHandler() {
        return "Credentials Invalid !!";
    }
}

8) Test Application.

Post : http://localhost:9093/auth/login
{
    "email":"Punit",
    "password":"Urja"
}
Output:
{
    "username": "Punit",
    "jwtToken": "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJQdW5pdCIsImlhdCI6MTcwMDMyOTk3MiwiZXhwIjoxNzAwMzQ3OTcyfQ.HT8pH_5R4c90HS5mPhdetqQ_didetm3Vm5vK2r_2hxb1V6r-jkUf8adq4N4sg-H5fPlBrokzxCpQ5v3g0h9qWg"
}

GET : http://localhost:9093/books 
Header : Key = Authorization ,value =Bearer eyJhbGciOiJIUzUxMiJ9.yJzdWIiOiJQdW5pdCIsImlhdCI6MTcwMDMyOTk3MiwiZXhwIjoxNzAwMzQ
3OTcyfQ.HT8pH_5R4c90HS5mPhdetqQ_didetm3Vm5vK2r_2hxb1V6r-jkUf8adq4N4sg-H5fPlBrokzxCpQ5v3g0h9qWg

output:
[
    {
        "id": "e4decd2e-8dd8-4cb6-874b-060ee7065e4a",
        "title": "Java",
        "author": "Punit"
    },
    {
        "id": "72d47ebe-a885-4f3b-a420-9b264d75a999",
        "title": "c++",
        "author": "Raj"
    },
    {
        "id": "d8a305fe-8d91-40d2-8870-770015943a55",
        "title": "python",
        "author": "Manish"
    },
    {
        "id": "e79db233-4d83-484b-90b6-f0ea7f727218",
        "title": "spring",
        "author": "Aaliya"
    }
]
