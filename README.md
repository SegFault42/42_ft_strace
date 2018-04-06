### Config SSH permissions
	
	$ ssh-keygen -t rsa -C "ft_strace"

 When you are prompted :

	Enter file in which to save the key (/Users/*****/.ssh/id_rsa):

- type : /Users/YOUR_USERNAME/.ssh/id_rsa_strace
- Do not enter passphrase

--

	$ cp ~/.ssh/id_rsa_strace .id_rsa
	$ cp ~/.ssh/id_rsa_strace.pub .id_rsa.pub

then go to github.com and add the content of id_rsa.pub in your github profile 

### Install

	$ git clone https://github.com/SegFault42/42_ft_strace
	$ cd 42_ft_strace
	$ docker build -t strace .
	$ docker run --security-opt seccomp:unconfined -it strace:latest zsh


### Help

All syscall define are here :  /usr/include/x86_64-linux-gnu/bits/syscall.h
