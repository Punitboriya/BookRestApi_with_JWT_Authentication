package com.restapi.book.service;

import com.restapi.book.entities.Book;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Component
public class BookService {

    private static List<Book> list = new ArrayList<>();

    static {
        list.add(new Book(UUID.randomUUID().toString(), "Java", "Punit"));
        list.add(new Book(UUID.randomUUID().toString(), "c++", "Raj"));
        list.add(new Book(UUID.randomUUID().toString(), "python", "Manish"));
        list.add(new Book(UUID.randomUUID().toString(), "spring", "Aaliya"));
    }

    //	Get All Books
    public List<Book> getAllBooks() {
        return list;
    }

    //	Get Book By Id
    public Book getBookByID(int id) {
        Book bk = null;
        try {
            bk = list.stream().filter(e -> e.getId().equals(id)).findFirst().get();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return bk;
    }

    //	Add a Book
    public Book addBook(Book b) {
        list.add(b);
        return b;
    }

    //	Delete Book
    public void deleteBook(String id) {
        list = list.stream().filter(e -> !e.getId().equals(id)).collect(Collectors.toList());
    }


    //	Update Book
    public void updateBook(Book book, int bid) {
        list.stream().map(b -> {
            if (b.getId().equals(bid)) {
                b.setTitle(book.getTitle());
                b.setAuthor(book.getAuthor());
            }
            return b;
        }).collect(Collectors.toList());
    }
}
