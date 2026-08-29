package webui

import (
	"bytes"
	"html/template"
	"log"
	"net/http"
)

// executeTemplate renders name into a buffer first, then writes it to w —
// buffering avoids sending a partial response with an already-committed 200
// status if rendering fails partway through, which writing directly to w
// would risk.
func executeTemplate(w http.ResponseWriter, tmpl *template.Template, name string, data any) {
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, name, data); err != nil {
		log.Printf("webui: rendering %s: %v", name, err)
		http.Error(w, "internal template error", http.StatusInternalServerError)
		return
	}
	if _, err := buf.WriteTo(w); err != nil {
		log.Printf("webui: writing %s: %v", name, err)
	}
}

// renderFragment renders name to a template.HTML value rather than an
// http.ResponseWriter — what Job's renderFinding/renderLog callbacks use so
// an SSE-pushed event and the initial page render both go through the same
// template, not two.
func renderFragment(tmpl *template.Template, name string, data any) template.HTML {
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, name, data); err != nil {
		log.Printf("webui: rendering fragment %s: %v", name, err)
		return ""
	}
	return template.HTML(buf.String())
}
