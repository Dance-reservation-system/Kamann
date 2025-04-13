package pl.kamann.controllers.instructor;

import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import pl.kamann.dtos.UserDetailsDto;
import pl.kamann.services.instructor.InstructorAccountService;

@RestController
@RequestMapping("/api/v1/instructor/account")
@RequiredArgsConstructor
@Tag(name = "5. instructor account controller", description = "Control instructor accounts.")
public class InstructorAccountController {

    private final InstructorAccountService instructorAccountController;

    @GetMapping
    public ResponseEntity<UserDetailsDto> getInstructorDetails() {
        return ResponseEntity.ok(instructorAccountController.getInstructorDetails());
    }
}
