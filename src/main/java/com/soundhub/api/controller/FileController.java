package com.soundhub.api.controller;

import com.soundhub.api.service.FileService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StreamUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

@RestController
@RequestMapping("api/v1/files")
@Slf4j
public class FileController {
    @Autowired
    private FileService fileService;

    @Value("${project.staticFolder}")
    private String staticFolder = "static/";

    @PostMapping("/upload")
    public ResponseEntity<String> uploadFileHandler(@RequestPart MultipartFile file) throws IOException {
        log.debug("uploadFileHandler[1]: received file is {}", file.getOriginalFilename());

        String fileName = fileService.uploadFile(staticFolder, file);
        log.debug("uploadFileHandler[2]: received file is {}", staticFolder);

        return ResponseEntity.ok("File was uploaded: " + fileName);
    }

    @GetMapping("/{filename}")
    public void serveFileHandler(
            @PathVariable String filename,
            @RequestParam String folderName,
            HttpServletResponse httpServletResponse
    ) throws IOException {
        InputStream resourceFile = fileService.getResourceFile(folderName, filename);
        httpServletResponse.setContentType(MediaType.ALL_VALUE);
        StreamUtils.copy(resourceFile, httpServletResponse.getOutputStream());
    }

    @PostMapping("/upload/files")
    public ResponseEntity<List<String>> uploadListFilesHandler(@RequestPart List<MultipartFile> files) {
        List<String> fileNames = fileService.uploadFileList(staticFolder, files);
        return ResponseEntity.ok(fileNames);
    }
}
