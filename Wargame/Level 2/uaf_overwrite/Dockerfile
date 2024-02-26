FROM ubuntu:18.04@sha256:ceed028aae0eac7db9dd33bd89c14d5a9991d73443b0de24ba0db250f47491d2

ENV user uaf_overwrite
ENV chall_port 7182
ENV PATH="${PATH}:/usr/local/lib/python3.6/dist-packages/bin"
ENV LC_CTYPE=C.UTF-8

RUN apt-get update
RUN apt-get -y install socat
RUN apt install -y \
    gcc \
    git \
    python3 \
    python3-pip \
    ruby \
    sudo \
    tmux \
    vim \
    wget

RUN adduser $user

ADD flag /home/$user/flag
ADD $user /home/$user/$user

RUN chown -R root:root /home/$user
RUN chown root:$user /home/$user/flag
RUN chown root:$user /home/$user/$user

RUN chmod 755 /home/$user/$user
RUN chmod 440 /home/$user/flag

# install pwndbg
WORKDIR /root
RUN git clone https://github.com/pwndbg/pwndbg
WORKDIR /root/pwndbg
RUN git checkout 2023.03.19
RUN ./setup.sh

# install pwntools
RUN pip3 install --upgrade pip
RUN pip3 install pwntools

# install one_gadget command
RUN gem install one_gadget

WORKDIR /home/$user
USER $user
EXPOSE $chall_port
CMD while :; do socat -T 30 TCP-LISTEN:$chall_port,reuseaddr,fork EXEC:/home/$user/$user ; done
