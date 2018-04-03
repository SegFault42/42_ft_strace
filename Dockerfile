FROM ubuntu:latest

RUN apt-get update && apt-get install -y zsh git vim strace curl wget

RUN wget https://github.com/robbyrussell/oh-my-zsh/raw/master/tools/install.sh -O - | bash || true

RUN git clone https://github.com/reversTeam/Sublivim.git /tmp/subl

RUN cd /tmp/subl && sh /tmp/subl/installer.sh

WORKDIR /root
