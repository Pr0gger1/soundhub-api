package com.soundhub.api.service.impl;

import com.soundhub.api.Constants;
import com.soundhub.api.dto.PostDto;
import com.soundhub.api.exception.ApiException;
import com.soundhub.api.exception.ResourceNotFoundException;
import com.soundhub.api.model.Post;
import com.soundhub.api.model.User;
import com.soundhub.api.repository.PostRepository;
import com.soundhub.api.repository.UserRepository;
import com.soundhub.api.service.FileService;
import com.soundhub.api.service.PostService;
import com.soundhub.api.service.UserService;
import com.soundhub.api.util.mappers.PostMapper;
import com.soundhub.api.util.mappers.UserMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.util.*;

@Service
@Slf4j
public class PostServiceImpl implements PostService {
    @Autowired
    private PostRepository postRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserService userService;

    @Autowired
    private FileService fileService;

    @Autowired
    private UserMapper userMapper;

    @Autowired
    private PostMapper postMapper;

    @Value("postPictures/")
    private String path;

    @Value("${base.url}")
    private String baseUrl;

    @Override
    public PostDto addPost(PostDto postDto, List<MultipartFile> files) {
        User author = userService.getCurrentUser();
        List<String> fileNames;
        List<String> postImageUrl = new ArrayList<>();
        if (files != null) {
            fileNames = fileService.uploadFileList(path, files);
            fileNames.forEach(f -> postImageUrl.add((f == null) ? null : baseUrl + Constants.FILE_PATH_PART + f));
        }

        Post post = Post.builder()
                .author(author)
                .publishDate(LocalDateTime.now())
                .content(postDto.getContent())
                .images(postImageUrl)
                .build();

        log.info("addPost[1]: Adding post {}", post);
        postDto = postMapper.toPostDto(postRepository.save(post));
        return postDto;
    }

    @Override
    public Post toggleLike(UUID postId, User user) {
        Post post = postRepository.findById(postId)
                .orElseThrow(() -> new ResourceNotFoundException(Constants.POST_RESOURCE_NAME, Constants.ID_FIELD, postId));
        Set<User> likes = post.getLikes();
        boolean isChanged;
        isChanged = (likes.contains(user)) ? likes.remove(user) : likes.add(user);
        log.info("toggleLike[1]: Toggled like successfully: {}", isChanged);
        if (isChanged) {
            postRepository.save(post);
        }
        return post;
    }

    @Override
    public PostDto getPostById(UUID postId) {
        log.info("getPostById[1]: Getting post by ID {}", postId);
        return postMapper.toPostDto(postRepository.findById(postId)
                .orElseThrow(() -> new ResourceNotFoundException(Constants.POST_RESOURCE_NAME, Constants.ID_FIELD, postId)));
    }

    @Override
    public UUID deletePost(UUID postId) {
        Post post = postRepository.findById(postId)
                .orElseThrow(() -> new ResourceNotFoundException(Constants.POST_RESOURCE_NAME, Constants.ID_FIELD, postId));
        if (!userService.getCurrentUser().equals(post.getAuthor())) {
            throw new ApiException(HttpStatus.FORBIDDEN, Constants.PERMISSION_MESSAGE);
        }
        List<String> postImages = post.getImages();
        List<String> postImagesUrls = new ArrayList<>();
        postImages.forEach(f -> postImagesUrls.add(f.substring(f.lastIndexOf("/") + 1)));
        log.info("deletePost[1]: Getting the post images urls {}", postImagesUrls);
        postImagesUrls.forEach(f -> {
            try {
                Files.deleteIfExists(Paths.get(path + File.separator + f));
            } catch (IOException e) {
                throw new ApiException(HttpStatus.BAD_REQUEST, e.getMessage());
            }
        });
        postRepository.delete(post);
        log.info("deletePost[2]: Images was successfully deleted from the disk. Post ID {} deleted", postId);
        return post.getId();
    }

    @Override
    public PostDto updatePost(UUID postId, PostDto postDto) {
        Post post = postRepository.findById(postId)
                .orElseThrow(() -> new ResourceNotFoundException(Constants.POST_RESOURCE_NAME, Constants.ID_FIELD, postId));
        if (!userService.getCurrentUser().equals(post.getAuthor())) {
            throw new ApiException(HttpStatus.FORBIDDEN, Constants.PERMISSION_MESSAGE);
        }
        log.debug("updatePost[1]: Updating post without files replacing ID {}", postId);
        postMapper.updatePostFromDto(postDto, post);
        postRepository.save(post);
        return postMapper.toPostDto(post);
    }

    @Override
    public PostDto updatePost(UUID postId, PostDto postDto, List<MultipartFile> files, List<String> replaceFilesUrls) throws IOException {
        Post post = postRepository.findById(postId)
                .orElseThrow(() -> new ResourceNotFoundException(Constants.POST_RESOURCE_NAME, Constants.ID_FIELD, postId));
        if (!userService.getCurrentUser().equals(post.getAuthor())) {
            throw new ApiException(HttpStatus.FORBIDDEN, Constants.PERMISSION_MESSAGE);
        }
        List<String> postImages = new ArrayList<>(post.getImages());
        postImages.addAll(addNewFiles(files));
        deleteReplacingFiles(replaceFilesUrls, postImages);
        postDto.setImages(postImages);
        log.debug("updatePost[1]: Updating post: files after insert {}", postImages);
        postMapper.updatePostFromDto(postDto, post);
        postRepository.save(post);
        return postMapper.toPostDto(post);
    }

    private List<String> addNewFiles(List<MultipartFile> files) {
        List<String> updatedFileNamesUrls = new ArrayList<>();
        if (!(files == null)) {
            List<String> updatedFileNames = fileService.uploadFileList(path, files);
            updatedFileNames.forEach(f -> updatedFileNamesUrls.add((f == null) ? null : baseUrl + Constants.FILE_PATH_PART + f));
        }
        log.debug("addNewFiles[1]: Files added {} (if empty, no files to add)", updatedFileNamesUrls);
        return updatedFileNamesUrls;
    }

    private void deleteReplacingFiles(List<String> replaceFilesUrls, List<String> postImages) {
        if (!(replaceFilesUrls == null)) {
            replaceFilesUrls.forEach(f -> {
                try {
                    Files.deleteIfExists(Paths.get(path + File.separator + f.substring(f.lastIndexOf("/") + 1)));
                    postImages.remove(f);
                    log.debug("deleteReplacingFiles[1]: Files deleted {}", f);
                } catch (IOException e) {
                    throw new ApiException(HttpStatus.BAD_REQUEST, e.getMessage());
                }
            });
            log.debug("deleteReplacingFiles[2]: Files remain {}", postImages);
        }
    }

    @Override
    public List<Post> getPostsByAuthor(UUID authorId) {
        User user = userService.getUserById(authorId);
        log.info("getPostsByAuthor[1]: User entity was requested {}", user);
        return postRepository.findAllByAuthor(user);
    }
}
