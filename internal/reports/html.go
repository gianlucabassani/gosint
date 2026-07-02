package reports

import (
	"html/template"
	"os"
	"time"
)

type HTMLGenerator struct{}

func (g *HTMLGenerator) Generate(filePath string, data ReportData) error {
	funcMap := template.FuncMap{
		"formatDate": func(t time.Time) string {
			return t.Format("2006-01-02 15:04:05")
		},
	}

	tmpl, err := template.New("report").Funcs(funcMap).Parse(htmlTemplate)
	if err != nil {
		return err
	}

	f, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	return tmpl.Execute(f, data)
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GOSINT Report: {{.Target}}</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background-color: #f4f7f6; color: #333; }
        .container { max-width: 960px; margin: 20px auto; background-color: #fff; padding: 25px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { background-color: #005f73; color: white; padding: 20px; margin-bottom: 25px; border-radius: 5px; text-align: center; }
        .section { background-color: #e9ecef; padding: 20px; margin-bottom: 20px; border-radius: 5px; border-left: 5px solid #0077b6; }
        h2 { color: #005f73; margin-top: 0; border-bottom: 2px solid #ade8f4; padding-bottom: 10px; }
        .label { font-weight: bold; color: #0077b6; min-width: 180px; display: inline-block; }
        ul { list-style-type: none; padding-left: 0; }
        li { background-color: #fff; margin-bottom: 8px; padding: 10px; border-radius: 4px; border: 1px solid #dee2e6; }
        .footer { margin-top: 30px; text-align: center; font-size: 0.9em; color: #6c757d; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; background: white; }
        th, td { border: 1px solid #dee2e6; padding: 8px 12px; text-align: left; }
        th { background-color: #0077b6; color: white; }
        tr:nth-child(even) { background-color: #f8f9fa; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>OSINT Profile Report</h1>
            <p>Target: <strong>{{.Target}}</strong></p>
            <p>Generated: {{.ScanDate | formatDate}}</p>
        </div>

        <div class="section">
            <h2>Scan Summary</h2>
            <p><span class="label">Mode:</span> {{.ScanMode}}</p>
            <p><span class="label">Duration:</span> {{.Duration}}</p>
        </div>

        {{if .DomainInfo}}
        <div class="section">
            <h2>WHOIS / Domain Info</h2>
            <p><span class="label">Registrar:</span> {{.DomainInfo.Registrar}}</p>
            <p><span class="label">Registered:</span> {{.DomainInfo.RegistrationDate}}</p>
            <p><span class="label">Expires:</span> {{.DomainInfo.ExpirationDate}}</p>
        </div>
        {{else if .WHOIS.Data}}
        <div class="section">
            <h2>WHOIS Information</h2>
            <pre>{{.WHOIS.Data}}</pre>
        </div>
        {{end}}

        {{if .Contacts}}
        <div class="section">
            <h2>Contacts ({{len .Contacts}})</h2>
            <table>
                <tr><th>Type</th><th>Value</th><th>Source</th></tr>
                {{range .Contacts}}
                <tr>
                    <td>{{if .Email}}email{{else}}phone{{end}}</td>
                    <td>{{if .Email}}{{.Email}}{{else}}{{.Phone}}{{end}}</td>
                    <td>{{.Source}}</td>
                </tr>
                {{end}}
            </table>
        </div>
        {{end}}

        {{if .DNS}}
        <div class="section">
            <h2>DNS Records</h2>
            <ul>
                {{range .DNS}}
                <li><strong>{{.Type}}</strong>: {{.Data}}</li>
                {{end}}
            </ul>
        </div>
        {{end}}

        {{if .Technologies}}
        <div class="section">
            <h2>Technologies</h2>
            <ul>
                {{range .Technologies}}
                <li><strong>{{.Name}}</strong> ({{.Version}}) - {{.Category}}</li>
                {{end}}
            </ul>
        </div>
        {{end}}

        {{if .Subdomains}}
        <div class="section">
            <h2>Subdomains ({{len .Subdomains}})</h2>
            <table>
                <tr><th>Subdomain</th><th>IP</th><th>Status</th></tr>
                {{range .Subdomains}}
                <tr>
                    <td>{{.Subdomain}}</td>
                    <td>{{.IP}}</td>
                    <td>{{.Status}}</td>
                </tr>
                {{end}}
            </table>
        </div>
        {{end}}

        {{if .Fuzzing}}
        <div class="section">
            <h2>Fuzzing Results ({{len .Fuzzing}})</h2>
            <table>
                <tr><th>URL</th><th>Status</th><th>Size</th><th>Type</th></tr>
                {{range .Fuzzing}}
                <tr>
                    <td>{{.URL}}</td>
                    <td>{{.StatusCode}}</td>
                    <td>{{.Size}}</td>
                    <td>{{.FuzzType}}</td>
                </tr>
                {{end}}
            </table>
        </div>
        {{end}}

        <div class="footer">
            <p>Generated by GOSINT Toolkit</p>
        </div>
    </div>
</body>
</html>`
