"""Readable Markdown previews; original evidence remains available unchanged."""
from markdown_it import MarkdownIt
from markupsafe import Markup

# js-default disables embedded HTML and supports tables. Images are left as text
# to avoid automatically fetching remote resources from evidence/runbooks.
PARSER = MarkdownIt('js-default').disable('image')


def render_preview(text: str, strip_header: bool = False) -> Markup:
    if strip_header:
        lines = text.splitlines(keepends=True)
        if lines and lines[0].strip() == '---':
            end = next((i for i in range(1, len(lines))
                        if lines[i].strip() == '---'), None)
            if end is not None:
                text = ''.join(lines[end + 1:])
    # Mark only the parser's generated output as HTML, never the original text.
    return Markup(PARSER.render(text))
