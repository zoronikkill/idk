export ZSH="$HOME/.oh-my-zsh"
plugins=(git zsh-autosuggestions)
source $ZSH/oh-my-zsh.sh


alias ls='ls -Gh --color=auto'
alias la='ls -lAh --color=auto'

export PS1='%n %F{1}::%f %F{2}%~%f %F{4}'$'\U00BB''%f '
export EDITOR='vim'

export VIRTUAL_ENV_DISABLE_PROMPT=1
source ~/myenv/bin/activate

command_not_found_handler() {
    /usr/share/command-not-found/command-not-found "$1"
    return $?
}

alias gcc='gcc -masm=intel'
alias g++='g++ -masm=intel'
alias clang='clang -masm=intel'
alias clang++='clang++ -masm=intel'
