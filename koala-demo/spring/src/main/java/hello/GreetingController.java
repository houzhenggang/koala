package hello;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.client.RestTemplate;

import java.util.concurrent.atomic.AtomicLong;

@Controller
public class GreetingController {

    private static final String template = "Hello, %s!";
    private final AtomicLong counter = new AtomicLong();

    @RequestMapping("/greeting")
    @ResponseBody
    public Greeting greeting(@RequestParam(value = "name", required = false, defaultValue = "World") String name) {
        return new Greeting(counter.incrementAndGet(), String.format(template, name));
    }

    @RequestMapping("/index")
    public String index(@RequestParam(value = "nmame", required = false, defaultValue = "Html") String name, Model model) {
        model.addAttribute("name", name);
        return "index";
    }

    @RequestMapping("/demo/hello")
    public void demo(@RequestParam(value = "nmame", required = false, defaultValue = "Html") String name, Model model) {
        RestTemplate restTemplate = new RestTemplate();
//		Page page = restTemplate.getForObject("http://graph.facebook.com/gopivotal", Page.class);
        Page page = restTemplate.getForObject("http://127.0.0.1:8080/demo/greeting?name=User", Page.class);
        System.out.println("Name:    " + page.getName());
        System.out.println("About:   " + page.getAbout());
        System.out.println("Id:   " + page.getId());
        System.out.println("Link: " + page.getLink());
        System.out.println("Content: " + page.getContent());
        model.addAttribute("name", name);
    }
}