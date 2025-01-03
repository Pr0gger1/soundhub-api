package com.soundhub.api.service.impl;

import com.soundhub.api.Constants;
import com.soundhub.api.exception.ApiException;
import com.soundhub.api.exception.ResourceNotFoundException;
import com.soundhub.api.service.FileService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

@Service
@Slf4j
public class FileServiceImpl implements FileService {
    private final String resourcesPath;
    private final String staticFolder;

    public FileServiceImpl(
        @Value("${project.resources.path}")
        String resourcesPath,
        @Value("${project.staticFolder}")
        String staticFolder
    ) {
        this.resourcesPath = resourcesPath;
        this.staticFolder = staticFolder;
    }

    private void createFolderIfNotExists(File folder) throws ApiException {
        if (!folder.exists()) {
            boolean isFolderCreated = folder.mkdir();

            if (!isFolderCreated) {
                throw new ApiException(
                        HttpStatus.INTERNAL_SERVER_ERROR,
                        String.format(Constants.CREATE_STATIC_DIR_ERROR, folder)
                );
            }
        }
    }

    @Override
    public String uploadFile(String path, MultipartFile multipartFile) throws IOException {
        log.debug("uploadFile[1]: multipart file is {}", multipartFile);
        if (multipartFile == null || multipartFile.isEmpty() || path == null) {
            throw new ApiException(HttpStatus.BAD_REQUEST, Constants.INVALID_MULTIPART);
        }

        String fileName = multipartFile.getOriginalFilename();

        String uuidFilename = UUID.randomUUID() + "_" + fileName;
        File fileFolder = getStaticPath(path).toFile();
        File staticResourcesPath = Paths.get(resourcesPath, staticFolder).toFile();

        if (Objects.equals(path, staticFolder)) {
            fileFolder = staticResourcesPath;
        }

        Path filePath = Paths.get(fileFolder.getAbsolutePath(), uuidFilename);
        log.debug("uploadFile[1]: resources path: {}", resourcesPath);
        log.debug("uploadFile[2]: static folder: {}", staticFolder);

        createFolderIfNotExists(staticResourcesPath);
        createFolderIfNotExists(fileFolder);

        log.debug("uploadFile[1]: {}", resourcesPath);
        log.debug("uploadFile[2]: {}", fileFolder);

        try {
            Files.copy(multipartFile.getInputStream(), filePath);

            return uuidFilename;
        }
        catch (IOException e) {
            throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, Constants.SAVE_STATIC_ERROR);
        }
    }

    @Override
    public List<String> uploadFileList(String path, List<MultipartFile> multipartFile) {
        List<String> names = new ArrayList<>();
        multipartFile.parallelStream().forEach(file -> {
            try {
                names.add(uploadFile(path, file));
            } catch (IOException e) {
                throw new ApiException(HttpStatus.BAD_REQUEST, e.getMessage());
            }
        });
        return names;
    }

    @Override
    public InputStream getResourceFile(String path, String filename) {
        File staticFile = getStaticFilePath(path, filename).toFile();
        try { return new FileInputStream(staticFile); }
        catch (FileNotFoundException e) {
            throw new ResourceNotFoundException(String.format(Constants.FILE_NOT_FOUND, filename));
        }
    }

    @Override
    public Path getStaticPath(String path) {
        return Paths.get(resourcesPath, staticFolder, path);
    }

    @Override
    public Path getStaticFilePath(String folder, String filename) {
        File staticFile = getStaticPath(folder)
                .toFile();

        log.debug("getStaticFilePath[1]: {}", staticFile.getAbsolutePath());

        if (!staticFile.exists())
            throw new ResourceNotFoundException(String.format(Constants.FILE_NOT_FOUND, staticFile.getName()));

        return Paths.get(staticFile.getAbsolutePath(), filename);
    }
}
