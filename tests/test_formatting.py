from hunterqa.formatting import safe_report_markdown


def test_safe_markdown_headers_and_html_escaping():
    html = str(safe_report_markdown('## Summary\n**Fix** `<script>` <img src=x onerror=alert(1)>'))
    assert '<h3>Summary</h3>' in html
    assert '<strong>Fix</strong>' in html
    assert '<img' not in html
    assert '&lt;img' in html
