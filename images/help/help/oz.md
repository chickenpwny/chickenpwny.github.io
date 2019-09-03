    Modified from the Debian original for Ubuntu
    Last updated: 2014-03-19
so nmap reveals two ports, its running node js on an apache 2014 box, ssh seems up todate though. initial go buster scans didn't give much on the serfuce but after enumerating support it revealed some more directories. 

oh, wow, very clean and neat webpage.

 ![webpage-support](C:\Users\charl\OneDrive\Pictures\hackthebox\help\webpage-support.PNG)

tried uploading a php reverse shell got some kind of filtering. 

php, php5 aren't allowed. one last test for file types because captcha blows

could fuz the api which might be the easiest thing to do. like in mischief where you could bypass all that mobojumbo just by fuzzing possible functions

### Gobuster

=====================================================                                       

/index.html (Status: 200)                                                                           
/support (Status: 301)                                                                              
/javascript (Status: 301) 

#### support

=====================================================                                       
/images (Status: 301)                                                                               
/uploads (Status: 301)                                                                              
/css (Status: 301)                                                                                 
/includes (Status: 301)                                                                            
/js (Status: 301)                                                                                  
/views (Status: 301)

/controllers (Status: 301)

=====================================================                                       



