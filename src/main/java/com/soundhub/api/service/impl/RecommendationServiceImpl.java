package com.soundhub.api.service.impl;

import com.soundhub.api.service.RecommendationService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.List;
import java.util.UUID;

@Service
@Slf4j
public class RecommendationServiceImpl implements RecommendationService {
    @Value("${recommendation.url}")
    private String recommendationApi;

    @Override
    public List<UUID> getUsers(UUID user) {
        log.info("recommendUsers[1]: searching friends for user with id: {}", user);
        final String uri = recommendationApi + "/" + user;
        RestTemplate restTemplate = new RestTemplate();

        return restTemplate.getForObject(uri, List.class);
    }
}

