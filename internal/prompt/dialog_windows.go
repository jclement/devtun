// The Windows chooser: a Windows Forms dialog drawn by PowerShell.
//
// Windows has no zenity and no osascript, but it does ship a scripting host
// that can put up a real window, and every Windows since 7 has it. The script
// below is a list box and two buttons — deliberately the same question, in the
// same words, as the terminal menu.
//
// Windows PowerShell (powershell.exe) is preferred over PowerShell 7 (pwsh)
// because it is always present and takes -STA, which Windows Forms requires;
// pwsh is already single-threaded-apartment on Windows and is the fallback for
// a machine where powershell.exe has been removed.
package prompt

import (
	"context"
	"fmt"
	"strings"
)

func choosers() []chooser {
	return []chooser{
		powershellChooser{bin: "powershell.exe", sta: true},
		powershellChooser{bin: "pwsh.exe"},
	}
}

type powershellChooser struct {
	bin string
	sta bool
}

func (p powershellChooser) name() string { return p.bin }

// available checks only that the shell is there. Unlike Unix there is no
// display variable to consult: a Windows session that cannot draw a window is
// rare enough that finding out from the failure — and falling back to the
// terminal — is the better trade.
func (p powershellChooser) available() bool { return haveProgram(p.bin) }

func (p powershellChooser) ask(ctx context.Context, title, prompt string, labels []string) (string, error) {
	args := []string{"-NoProfile", "-NonInteractive"}
	if p.sta {
		args = append(args, "-STA")
	}
	args = append(args, "-Command", buildFormScript(title, prompt, labels))
	return runChooser(ctx, p.bin, args...)
}

// buildFormScript assembles the PowerShell. Every way of dismissing the window
// — the Deny button, Escape, the close box — leaves DialogResult at Cancel and
// prints the sentinel, so they all mean no.
func buildFormScript(title, prompt string, labels []string) string {
	quoted := make([]string, len(labels))
	for i, label := range labels {
		quoted[i] = powershellString(label)
	}

	var script strings.Builder
	script.WriteString("Add-Type -AssemblyName System.Windows.Forms;")
	script.WriteString("Add-Type -AssemblyName System.Drawing;")
	script.WriteString("$f=New-Object Windows.Forms.Form;")
	fmt.Fprintf(&script, "$f.Text=%s;", powershellString(title))
	script.WriteString("$f.ClientSize=New-Object Drawing.Size(560,320);")
	script.WriteString("$f.FormBorderStyle='FixedDialog';$f.StartPosition='CenterScreen';")
	// TopMost and Activate are the whole point: the window devtun runs in is
	// not the one you are looking at.
	script.WriteString("$f.TopMost=$true;$f.MinimizeBox=$false;$f.MaximizeBox=$false;")
	script.WriteString("$l=New-Object Windows.Forms.Label;")
	fmt.Fprintf(&script, "$l.Text=%s;", powershellString(prompt))
	script.WriteString("$l.SetBounds(14,12,532,72);")
	script.WriteString("$b=New-Object Windows.Forms.ListBox;")
	script.WriteString("$b.SetBounds(14,92,532,150);")
	fmt.Fprintf(&script, "$b.Items.AddRange(@(%s));", strings.Join(quoted, ","))
	script.WriteString("$b.SelectedIndex=0;")
	script.WriteString("$ok=New-Object Windows.Forms.Button;$ok.Text='Approve';$ok.SetBounds(340,254,100,30);$ok.DialogResult='OK';")
	script.WriteString("$no=New-Object Windows.Forms.Button;$no.Text='Deny';$no.SetBounds(446,254,100,30);$no.DialogResult='Cancel';")
	script.WriteString("$f.Controls.AddRange(@($l,$b,$ok,$no));$f.AcceptButton=$ok;$f.CancelButton=$no;")
	script.WriteString("$f.Add_Shown({$f.Activate();$b.Focus()});")
	fmt.Fprintf(&script,
		"if($f.ShowDialog() -eq [Windows.Forms.DialogResult]::OK){Write-Output $b.SelectedItem}else{Write-Output %s}",
		powershellString(denySentinel))
	return script.String()
}

// powershellString quotes a Go string as a PowerShell single-quoted literal,
// where the only escape is a doubled quote — so nothing in a host name or a
// vault reference can become code.
func powershellString(s string) string {
	// A newline inside a single-quoted literal is legal and renders as one,
	// which is what the prompt body wants.
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
