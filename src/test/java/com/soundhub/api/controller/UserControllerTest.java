package com.soundhub.api.controller;

import com.soundhub.api.BaseTest;
import com.soundhub.api.dto.UserCompatibilityDto;
import com.soundhub.api.dto.UserDto;
import com.soundhub.api.dto.request.CompatibleUsersRequest;
import com.soundhub.api.dto.response.CompatibleUsersResponse;
import com.soundhub.api.exception.ResourceNotFoundException;
import com.soundhub.api.model.User;
import com.soundhub.api.service.RecommendationService;
import com.soundhub.api.service.UserService;
import com.soundhub.api.util.mappers.UserMapper;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@Slf4j
@SpringBootTest
@ExtendWith(SpringExtension.class)
public class UserControllerTest extends BaseTest {

    @Mock
    private UserService userService;

    @Mock
    private UserMapper userMapper;

    @Mock
    private RecommendationService recommendationService;

    @InjectMocks
    private UserController userController;

    @BeforeEach
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        userId = UUID.randomUUID();
        user = User.builder()
                .id(userId)
                .email("vasya.pupkin@gmail.com")
                .password("testPassword")
                .firstName("Vasya")
                .lastName("Pupkin")
                .birthday(LocalDate.of(2000, 5, 15))
                .build();

        userDto = UserDto.builder()
                .id(userId)
                .email("vasya.pupkin@gmail.com")
                .password("testPassword")
                .firstName("Vasya")
                .lastName("Pupkin")
                .birthday(LocalDate.of(2000, 5, 15))
                .build();
    }

    @Test
    public void testGetUser_returnUserDto() {
        log.debug("testGetUser_returnUserDto[1]: start test");
        when(userService.getUserById(userId)).thenReturn(user);
        when(userMapper.userToUserDto(user)).thenReturn(userDto);

        ResponseEntity<UserDto> response = userController.getUser(userId);
        log.debug("testGetUser_returnUserDto[2]: response: {}", response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(userDto, response.getBody());

        verify(userService, times(1)).getUserById(userId);
        verify(userMapper, times(1)).userToUserDto(user);
    }

    @Test
    public void testGetUser_nonExistentUser_returnNotFound() {
        log.debug("testGetUser_nonExistentUser_returnNotFound[1]: start test");
        when(userService.getUserById(userId)).thenThrow(new ResourceNotFoundException("user", "userId", userId));

        Exception exception = assertThrows(ResourceNotFoundException.class, () -> {
            ResponseEntity<UserDto> response = userController.getUser(userId);
            log.debug("testGetUser_nonExistentUser_returnNotFound[2]: response: {}", response);
            assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
            assertNull(response.getBody());
        });
        verify(userService, times(1)).getUserById(userId);
    }

    @Test
    public void testUpdateUserWithFile_returnUpdatedUser() throws IOException {
        log.debug("testUpdateUser_returnUpdatedUser[1]: start test");
        MultipartFile file = mock(MultipartFile.class);
        when(userService.updateUser(eq(userId), eq(userDto), eq(file))).thenReturn(userDto);

        ResponseEntity<UserDto> response = userController.updateUser(userId, userDto, file);
        log.debug("testUpdateUserWithFile_returnUpdatedUser[2]: response: {}", response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(userDto, response.getBody());

        verify(userService, times(1)).updateUser(eq(userId), eq(userDto), eq(file));
    }

    @Test
    public void testUpdateUserWithFile_returnUserNotFound() throws IOException {
        log.debug("testUpdateUserWithFile_returnUserNotFound[1]: start test");
        MultipartFile file = mock(MultipartFile.class);
        when(userService.updateUser(eq(userId), eq(userDto), eq(file))).thenThrow(new ResourceNotFoundException("User", "id", userId));

        assertThrows(ResourceNotFoundException.class, () -> {
            ResponseEntity<UserDto> response = userController.updateUser(userId, userDto, file);
            log.debug("testUpdateUserWithFile_returnUserNotFound[2]: response: {}", response);
            assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
            assertNull(response.getBody());
        });
        verify(userService, times(1)).updateUser(eq(userId), eq(userDto), eq(file));
    }

    @Test
    public void testUpdateUserWithoutFile_returnUpdatedUser() throws IOException {
        log.debug("testUpdateUserWithoutFile_returnUpdatedUser[1]: start test");
        when(userService.updateUser(eq(userId), eq(userDto), isNull())).thenReturn(userDto);

        ResponseEntity<UserDto> response = userController.updateUser(userId, userDto, null);
        log.debug("testUpdateUserWithoutFile_returnUpdatedUser[2]: response: {}", response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(userDto, response.getBody());

        verify(userService, times(1)).updateUser(eq(userId), eq(userDto), isNull());
    }

    @Test
    public void testDeleteUser_returnUserId() throws IOException {
        log.debug("testDeleteUser_returnUserId[1]: start test");
        when(userService.deleteUser(userId)).thenReturn(userId);

        ResponseEntity<UUID> response = userController.deleteUser(userId);
        log.debug("testDeleteUser_returnUserId[2]: response: {}", response);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(userId, response.getBody());
        verify(userService, times(1)).deleteUser(userId);
    }

    @Test
    public void testDeleteUser_returnNotFound() throws IOException {
        log.debug("testDeleteUser_returnNotFound[1]: start test");
        when(userService.deleteUser(userId)).thenThrow(new ResourceNotFoundException("user", "userId", userId));

        Exception exception = assertThrows(ResourceNotFoundException.class, () -> {
            ResponseEntity<UUID> response = userController.deleteUser(userId);
            log.debug("testDeleteUser_returnNotFound[2]: response: {}", response);
            assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
            assertNull(response.getBody());
        });
        verify(userService, times(1)).deleteUser(userId);
    }

    @Test
    public void testGetCurrentUser_returnCurrentUser() {
        log.debug("testGetCurrentUser_returnCurrentUser[1]: start test");
        when(userService.getCurrentUser()).thenReturn(user);

        ResponseEntity<User> response = userController.getCurrentUser();
        log.debug("testGetCurrentUser_returnCurrentUser[2]: response: {}", response);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(user, response.getBody());
        verify(userService, times(1)).getCurrentUser();
    }

    @Test
    public void testAddFriend() throws IOException {
        log.debug("testAddFriend[1]: start test");
        when(userService.addFriend(userId)).thenReturn(user);

        ResponseEntity<User> response = userController.addFriend(userId);
        log.debug("testAddFriend[2]: response: {}", response);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(user, response.getBody());
        verify(userService, times(1)).addFriend(userId);
    }

    @Test
    public void testDeleteFriend() throws IOException {
        log.debug("testDeleteFriend[1]: start test");
        when(userService.deleteFriend(userId)).thenReturn(user);

        ResponseEntity<User> response = userController.deleteFriend(userId);
        log.debug("testDeleteFriend[2]: response: {}", response);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(user, response.getBody());
        verify(userService, times(1)).deleteFriend(userId);
    }

    @Test
    public void testGetRecommendedFriends() {
        log.debug("testGetRecommendedFriends[1]: start test");
        List<User> rawFriends = new ArrayList<>();
        rawFriends.add(user);
        user.setFriends(List.of(user));
        List<UUID> ids = List.of(userId);

        when(userService.getCurrentUser()).thenReturn(user);
        when(recommendationService.getUsers(userId)).thenReturn(ids);
        when(userService.getUsersByIds(ids)).thenReturn(rawFriends);

        ResponseEntity<List<User>> response = userController.getRecommendedFriends();
        log.debug("testGetRecommendedFriends[2]: response: {}", response.getBody());

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertTrue(response.getBody().isEmpty());
        verify(userService, times(1)).getCurrentUser();
        verify(recommendationService, times(1)).getUsers(userId);
        verify(userService, times(1)).getUsersByIds(ids);
    }

    @Test
    public void testGetUserFriendsById() {
        log.debug("testGetUserFriendsById[1]: start test");
        List<User> friends = List.of(user);

        when(userService.getUserFriendsById(userId)).thenReturn(friends);

        ResponseEntity<List<User>> response = userController.getUserFriendsById(userId);
        log.debug("testGetUserFriendsById[2]: response: {}", response);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(friends, response.getBody());
        verify(userService, times(1)).getUserFriendsById(userId);
    }

    @Test
    public void testSearchUsersByFullName() {
        log.debug("testSearchUsersByFullName[1]: start test");
        List<User> users = List.of(user);

        when(userService.searchByFullName("John")).thenReturn(users);

        ResponseEntity<List<User>> response = userController.searchUsersByFullName("John");
        log.debug("testSearchUsersByFullName[2]: response: {}", response);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(users, response.getBody());
        verify(userService, times(1)).searchByFullName("John");
    }

    @Test
    public void testToggleUserOnline() {
        log.debug("testToggleUserOnline[1]: start test");
        when(userService.toggleUserOnline()).thenReturn(user);

        ResponseEntity<User> response = userController.toggleUserOnline();
        log.debug("testToggleUserOnline[2]: response: {}", response);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(user, response.getBody());
        verify(userService, times(1)).toggleUserOnline();
    }

    @Test
    public void testFindCompatibilityPercentage() {
        log.debug("testFindCompatibilityPercentage[1]: start test");
        List<UUID> userIds = List.of(userId);
        CompatibleUsersResponse compatibleUsersResponse = CompatibleUsersResponse.builder()
                .userCompatibilities(List.of(UserCompatibilityDto.builder()
                        .user(user)
                        .compatibility(95.5f)
                        .build())).build();

        when(userService.findCompatibilityPercentage(userIds)).thenReturn(compatibleUsersResponse);

        ResponseEntity<CompatibleUsersResponse> response = userController.findCompatibilityPercentage(CompatibleUsersRequest.builder()
                .listUsersCompareWith(userIds).build());
        log.debug("testFindCompatibilityPercentage[2]: response: {}", response);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(compatibleUsersResponse, response.getBody());
        verify(userService, times(1)).findCompatibilityPercentage(userIds);
    }

    @Test
    public void testAddFriendNotFound() throws IOException {
        log.debug("testAddFriendNotFound[1]: start test");
        when(userService.addFriend(userId)).thenThrow(new ResourceNotFoundException("User", "id", userId));

        Exception exception = assertThrows(ResourceNotFoundException.class, () -> {
            ResponseEntity<User> response = userController.addFriend(userId);
            log.debug("testAddFriendNotFound[2]: response: {}", response);
            assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
            assertNull(response.getBody());
        });

        verify(userService, times(1)).addFriend(userId);
    }

    @Test
    public void testDeleteFriendNotFound() throws IOException {
        log.debug("testDeleteFriendNotFound[1]: start test");
        when(userService.deleteFriend(userId)).thenThrow(new ResourceNotFoundException("User", "id", userId));

        Exception exception = assertThrows(ResourceNotFoundException.class, () -> {
            ResponseEntity<User> response = userController.deleteFriend(userId);
            log.debug("testDeleteFriendNotFound[2]: response: {}", response);
            assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
            assertNull(response.getBody());
        });

        verify(userService, times(1)).deleteFriend(userId);
    }

    @Test
    public void testGetRecommendedFriendsNotFound() throws Exception {
        log.debug("testGetRecommendedFriendsNotFound[1]: start test");
        when(userService.getCurrentUser()).thenThrow(new ResourceNotFoundException("User", "id", userId));

        assertThrows(ResourceNotFoundException.class, () -> {
            ResponseEntity<List<User>> response = userController.getRecommendedFriends();
            log.debug("testGetRecommendedFriendsNotFound[2]: response: {}", response);
            assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
            assertNull(response.getBody());
        });

        verify(userService, times(1)).getCurrentUser();
    }

    @Test
    public void testGetUserFriendsByIdNotFound() {
        log.debug("testGetUserFriendsByIdNotFound[1]: start test");
        assertThrows(ResourceNotFoundException.class, () -> {
            when(userService.getUserFriendsById(userId)).thenThrow(new ResourceNotFoundException("User", "id", userId));

            ResponseEntity<List<User>> response = userController.getUserFriendsById(userId);
            log.debug("testGetUserFriendsByIdNotFound[2]: response: {}", response);
            assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
            assertNull(response.getBody());
        });

        verify(userService, times(1)).getUserFriendsById(userId);
    }

    @Test
    public void testSearchUsersByFullNameNotFound() {
        log.debug("testSearchUsersByFullNameNotFound[1]: start test");
        when(userService.searchByFullName("NonExistentName")).thenReturn(new ArrayList<>());

        ResponseEntity<List<User>> response = userController.searchUsersByFullName("NonExistentName");
        log.debug("testSearchUsersByFullNameNotFound[2]: response: {}", response);

        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        assertNull(response.getBody());
        verify(userService, times(1)).searchByFullName("NonExistentName");
    }

    @Test
    public void testToggleUserOnlineNotFound() {
        log.debug("testToggleUserOnlineNotFound[1]: start test");
        assertThrows(ResourceNotFoundException.class, () -> {
            when(userService.toggleUserOnline()).thenThrow(new ResourceNotFoundException("User", "id", userId));

            ResponseEntity<User> response = userController.toggleUserOnline();
            log.debug("testToggleUserOnlineNotFound[2]: response: {}", response);
            assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
            assertNull(response.getBody());
        });

        verify(userService, times(1)).toggleUserOnline();
    }

    @Test
    public void testFindCompatibilityPercentageNotFound() {
        log.debug("testFindCompatibilityPercentageNotFound[1]: start test");
        List<UUID> userIds = List.of(userId);
        assertThrows(ResourceNotFoundException.class, () -> {
            when(userService.findCompatibilityPercentage(userIds)).thenThrow(new ResourceNotFoundException("User", "id", userId));

            ResponseEntity<CompatibleUsersResponse> response = userController.findCompatibilityPercentage(CompatibleUsersRequest.builder()
                    .listUsersCompareWith(userIds).build());
            log.debug("testFindCompatibilityPercentageNotFound[2]: response: {}", response);
            assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
            assertNull(response.getBody());
        });

        verify(userService, times(1)).findCompatibilityPercentage(userIds);
    }
}
