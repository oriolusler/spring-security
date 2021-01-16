package com.orso.security.config;

import com.google.auth.oauth2.GoogleCredentials;
import com.google.firebase.FirebaseApp;
import com.google.firebase.FirebaseOptions;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.FileInputStream;
import java.io.IOException;

@Configuration
public class FirebaseConfig {
    @Bean
    FirebaseApp createFireBaseApp() throws IOException {
        FileInputStream serviceAccount =
                new FileInputStream("/home/oriol/code/projects/borrowApp/firebase-adminsdk.json");


        FirebaseOptions options = new FirebaseOptions.Builder()
                .setCredentials(GoogleCredentials.fromStream(serviceAccount))
                .setDatabaseUrl("https://signin-a16b6.firebaseio.com")
                .build();

        return FirebaseApp.initializeApp(options);
    }

}