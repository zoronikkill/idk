export ZSH="$HOME/.oh-my-zsh"
plugins=(git zsh-autosuggestions command-not-found)
source $ZSH/oh-my-zsh.sh


alias ls='ls -Gh --color=auto'
alias la='ls -lAh --color=auto'
#alias vim='nvim'

export PS1='%n %F{1}::%f %F{2}%~%f %F{4}'$'\U00BB''%f '
export EDITOR='vim'

export VIRTUAL_ENV_DISABLE_PROMPT=1
source ~/myenv/bin/activate

alias gcc='gcc -masm=intel'
alias g++='g++ -masm=intel'
alias clang='clang -masm=intel'
alias clang++='clang++ -masm=intel'

export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"  # This loads nvm
[ -s "$NVM_DIR/bash_completion" ] && \. "$NVM_DIR/bash_completion"  # This loads nvm bash_completion

eval "$(gh copilot alias -- bash)"
