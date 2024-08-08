set number

inoremap <C-h> <Left>
inoremap <C-j> <Down>
inoremap <C-k> <Up>
inoremap <C-l> <Right>

set undofile
set undodir=~/.vim/undodir
set undolevels=1000
set undoreload=10000



set nocompatible
set encoding=utf-8
set vb t_vb=
set novisualbell

set tabstop=4
set shiftwidth=4
set et

set hls
set incsearch
set ic
set smartcase

set nornu
"set colorcolumn=80 "com
"set tw=80 "com

set ai
set cindent
set smarttab
set smartindent
set nowrap
set ruler
syntax on
set backspace=indent,eol,start
set mouse=a

set scrolloff=5

if has("gui_running")
	set guifont=DejaVu\ Sans\ Mono\ 20
	set go=-M
endif

set background=dark
set laststatus=2
set cursorline
"set foldmethod=syntax "заком
"set foldlevelstart=0 "заком
"let xml_syntax_folding=1 "заком

filetype off

call plug#begin('~/.vim/plugged') "заком
set rtp+=~/.vim/bundle/vundle/
"call vundle#rc() "заком
"все заком
packadd YouCompleteMe
"Plug 'svermeulen/vundle'
"Plug 'ycm-core/YouCompleteMe'
 Plug 'flazz/vim-colorschemes'
 Plug 'jaxbot/semantic-highlight.vim'
 Plug 'luochen1990/rainbow'
 Plug 'vim-scripts/DoxygenToolkit.vim'
 Plug 'tpope/vim-fugitive'
 Plug 'airblade/vim-gitgutter'
 Plug 'ctrlpvim/ctrlp.vim'
 Plug 'vim-scripts/The-NERD-tree'
 Plug 'tpope/vim-commentary'
 Plug 'vim-scripts/surround.vim'
" Plug 'bling/vim-airline'
" Plug 'vim-airline/vim-airline-themes'
 Plug 'easymotion/vim-easymotion'
 Plug 'kris2k/a.vim'
call plug#end() "заком

" Disable function highlighting (affects both C and C++ files)
let g:cpp_function_highlight = 0

let g:plug_shallow = 0

let g:rainbow_active=0

let g:ycm_global_ycm_extra_conf = '$HOME/.vim/ycm_extra_conf/ycm_extra_conf.py'
let g:ycm_confirm_extra_conf=0
let g:ycm_autoclose_preview_window_after_completeon=1
let g:ycm_autoclose_preview_window_after_insertion=1
let g:ycm_show_diagnostics_ui=0

let g:DoxygenToolkit_compactOneLineDoc = "yes"
let g:DoxygenToolkit_compactDoc = "yes"

let g:NERDTreeWinPos="right"
let g:NERDTreeIgnore=['\.vim$', '\~$', '.o$[[file]]']

" ctrlp filter
set wildignore+=*/tmp/*,*.so,*.swp,*.zip,*.tar.gz,*.o,*.png,*.jpg
let g:ctrlp_custome_ignore = '\v[\/]\.(git|hg|svn)$'

filetype plugin indent on
try
	colo default
catch
endtry

let mapleader=' '

nnoremap <Leader>f * :vimgrep /<C-R>// **/*.cpp **/*.[ch] **/*.hpp <CR> :copen<CR>
vnoremap <Leader>f y :vimgrep /<C-R>"/ **/*.cpp **/*.[ch] **/*.hpp <CR> :copen<CR>

nnoremap <Leader>e<Leader>w : e ++enc=cp1251<CR>
nnoremap <Leader>e<Leader>u : e ++enc=utf-8<CR>

nnoremap <F12> :split<CR>:YcmCompleter GoToDefinitionElseDeclaration<CR>
nnoremap <F5> :YcmForceCompileAndDiagnostics<CR><CR>
nnoremap <F11> : YcmCompleter FixIt<CR>

" DoxygenToolKit mappings
imap /** <Esc> :Dox<CR>
nnoremap <Leader>d :Dox<CR>

" Switch source/header
nnoremap <F4> :A<CR>
nnoremap <Leader>o : NERDTreeToggle <CR>
nnoremap <C-w>t :tabnew<CR>

" Toggle rainbow colors
nnoremap <F6> :SemanticHighlightToggle<CR>:RainbowToggle<CR>

" Ru mapping
set langmap=ФИСВУАПРШОЛДЬТЩЗЙКЫУГМЦЧНЯ;ABCDEFGHIJKLMNOPQRSTUVWXYZ,фисвуапршолдьтщзйкыугмцчня;abcdefghijklmnopqrstuvwxyz

" Tab mappings
map <Leader>1 1gt
map <Leader>2 2gt
map <Leader>3 3gt
map <Leader>4 4gt
map <Leader>5 5gt
map <Leader>6 6gt
map <Leader>7 7gt
map <Leader>8 8gt
map <Leader>9 9gt
map <Leader>10 10gt

" Selection to table
vnoremap <Leader>t :!column -t \| sed -e "s/\s\+$//g"<CR>
