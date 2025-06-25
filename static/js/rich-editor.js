class RichTextEditor {
  constructor(editorContainer) {
    this.toolbar = editorContainer.querySelector('.formatting-toolbar');
    this.editor = editorContainer.querySelector('.rich-editor');
    this.setupToolbarButtons();
    this.setupKeyboardShortcuts();
    this.setupFontSizeSelect();
  }

  setupToolbarButtons() {
    this.toolbar.querySelectorAll('.toolbar-btn').forEach(button => {
      button.addEventListener('click', (e) => {
        e.preventDefault();
        const command = this.getCommandFromButton(button);
        if (command) {
          this.execCommand(command);
          button.classList.toggle('active');
        }
      });
    });
  }

  getCommandFromButton(button) {
    const icon = button.querySelector('i');
    const iconClass = Array.from(icon.classList)
      .find(cls => cls.startsWith('bi-'));
    
    const commandMap = {
      'bi-type-bold': 'bold',
      'bi-type-italic': 'italic',
      'bi-type-underline': 'underline',
      'bi-type-strikethrough': 'strikethrough',
      'bi-list-ul': 'insertUnorderedList',
      'bi-list-ol': 'insertOrderedList',
      'bi-text-indent-left': 'indent',
      'bi-text-indent-right': 'outdent',
      'bi-code-square': 'formatBlock:pre',
      'bi-quote': 'formatBlock:blockquote',
      'bi-link-45deg': 'createLink'
    };

    return commandMap[iconClass];
  }

  execCommand(command) {
    if (command === 'createLink') {
      const url = prompt('Enter the URL:');
      if (url) {
        document.execCommand('createLink', false, url);
      }
    } else if (command.includes('formatBlock:')) {
      const block = command.split(':')[1];
      document.execCommand('formatBlock', false, `<${block}>`);
    } else {
      document.execCommand(command, false, null);
    }
  }

  setupKeyboardShortcuts() {
    this.editor.addEventListener('keydown', (e) => {
      if (e.ctrlKey || e.metaKey) {
        switch(e.key.toLowerCase()) {
          case 'b':
            e.preventDefault();
            this.execCommand('bold');
            break;
          case 'i':
            e.preventDefault();
            this.execCommand('italic');
            break;
          case 'u':
            e.preventDefault();
            this.execCommand('underline');
            break;
          case 'l':
            e.preventDefault();
            this.execCommand('createLink');
            break;
        }
      }
    });
  }

  setupFontSizeSelect() {
    const fontSelect = this.toolbar.querySelector('.font-select');
    if (fontSelect) {
      fontSelect.addEventListener('change', (e) => {
        this.editor.style.fontSize = `${e.target.value}px`;
      });
    }
  }
}

// Initialize all rich text editors on the page
document.addEventListener('DOMContentLoaded', () => {
  const commentForms = document.querySelectorAll('.comment-form');
  commentForms.forEach(form => {
    new RichTextEditor(form);
  });
}); 