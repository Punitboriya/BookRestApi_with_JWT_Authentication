package com.restapi.book.controller;

import com.restapi.book.entities.Book;
import com.restapi.book.service.BookService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.List;
import java.util.Optional;

@RestController
public class BookController {

//	@GetMapping("/books")
//	public Book getBooks() {
//		Book book = new Book();
//		book.setId(1);
//		book.setTitle("JAVA");
//		book.setAuthor("ABC");
//		return book;
//	}

    @Autowired
    private BookService bookService;

    @GetMapping("/books")
    public ResponseEntity<List<Book>> getBooks() {

        List<Book> list = bookService.getAllBooks();
        if (list.size() <= 0) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
        return ResponseEntity.of(Optional.of(list));
    }

    @GetMapping("/books/{id}")
    public ResponseEntity<Book> getBook(@PathVariable("id") int id) {
        Book book = this.bookService.getBookByID(id);
        if (book == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
        return ResponseEntity.of(Optional.of(book));
    }

    @PostMapping("/books")
    public ResponseEntity<Book> addBook(@RequestBody Book book) {

        Book bk = null;
        try {
            bk = this.bookService.addBook(book);
            return ResponseEntity.status(HttpStatus.CREATED).build();

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();

        }
    }

    @DeleteMapping("/books/{bid}")
    public ResponseEntity<Book> deleteBook(@PathVariable("bid") String id) {
        try {
            this.bookService.deleteBook(id);
            return ResponseEntity.status(HttpStatus.OK).build();

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @PutMapping("/books/{bid}")

    public ResponseEntity<Book> updateBook(@RequestBody Book book, @PathVariable("bid") int id) {
        try {
            this.bookService.updateBook(book, id);
//			return ResponseEntity.status(HttpStatus.OK).build();
            return ResponseEntity.ok().body(book);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @GetMapping("/current-user")
    public String getLoggedInUser(Principal principal) {
        System.out.println(principal.getName());
        return principal.getName();
    }
}
