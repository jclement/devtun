package tui

import (
	"fmt"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/jclement/devtun/internal/event"
	"github.com/jclement/devtun/internal/tunnels"
)

// errorRow builds a row whose bind failed, with the message sshd actually
// sends — the one line on the table where the text is the content.
func errorRow(remote int, cmd string) tunnels.State {
	s := row(remote, 0, cmd)
	s.Status, s.LocalPort = tunnels.StatusError, 0
	s.Err = fmt.Sprintf("listen tcp 127.0.0.1:%d: bind: address already in use", remote)
	return s
}

// manyRows builds more rows than any window can hold, which is the ordinary
// case on a busy box rather than the edge.
func manyRows(n int) []tunnels.State {
	rows := make([]tunnels.State, 0, n)
	for i := range n {
		rows = append(rows, row(3000+i, 3000+i, fmt.Sprintf("server-%d", i)))
	}
	return rows
}

// The strip answers "is anything wrong" without reading thirty rows, so every
// state that is not the ordinary one has to be counted on it.
func TestTheSummaryStripCountsEveryStateAndTheTraffic(t *testing.T) {
	live := row(3000, 3000, "node vite")
	live.ActiveConns, live.BytesIn, live.BytesOut = 2, 1_400_000, 62_464
	fresh := row(5173, 5173, "node vite --host")
	fresh.Created = testNow.Add(-2 * time.Second)
	stub := newStub(live, fresh, errorRow(4000, "python3"), skippedRow(5432, "postgres", tunnels.SkipHidden))
	stub.prefs.ShowHidden = true

	m := newTestModel(t, deps{tunnels: stub})
	strip := strings.Split(bodyLines(m), "\n")[0]

	for _, want := range []string{"● live 1", "◦ new 1", "✕ hidden 1", "! error 1", "1.3 MB↓", "61 KB↑"} {
		if !strings.Contains(strip, want) {
			t.Errorf("the summary strip is missing %q:\n%s", want, strip)
		}
	}
}

// A strip that has to give something up gives up the throughput first and the
// error count last: the bytes are also on the row, and a count cut mid-number
// says nothing at all.
func TestANarrowSummaryStripKeepsTheErrorCount(t *testing.T) {
	fresh := row(5173, 5173, "node")
	fresh.Created = testNow.Add(-2 * time.Second)
	live := row(3000, 3000, "node vite")
	live.ActiveConns = 1
	stub := newStub(live, fresh, errorRow(4000, "python3"), skippedRow(5432, "postgres", tunnels.SkipHidden))
	stub.prefs.ShowHidden = true

	m := newTestModel(t, deps{tunnels: stub})
	m.Update(tea.WindowSizeMsg{Width: 40, Height: 24})
	strip := strings.Split(bodyLines(m), "\n")[0]

	if !strings.Contains(strip, "! error 1") {
		t.Errorf("the error count was dropped to fit:\n%s", strip)
	}
	if strings.Contains(strip, "↓") {
		t.Errorf("the throughput was kept at the counts' expense:\n%s", strip)
	}
	// Whole chips or none: half of one is a glyph with no number beside it.
	if strings.Contains(strip, "…") {
		t.Errorf("a chip was cut rather than dropped:\n%s", strip)
	}
}

// Nothing said the list was cut. The track has to say so, and to say where in
// the list you are — the two things thirty identical rows cannot.
func TestTheScrollTrackShowsWhereInTheListYouAre(t *testing.T) {
	m := newTestModel(t, deps{tunnels: newStub(manyRows(30)...)})

	lastCells := func() []rune {
		var cells []rune
		for _, line := range strings.Split(plainView(m), "\n")[m.listTop() : m.listTop()+m.listHeight()] {
			runes := []rune(line)
			cells = append(cells, runes[len(runes)-2]) // inside the right border
		}
		return cells
	}

	top := lastCells()
	if top[0] != '█' {
		t.Errorf("the thumb is not at the top of an unscrolled list: %q", string(top))
	}
	if !strings.Contains(string(top), "│") {
		t.Errorf("a list with rows past the fold has no track: %q", string(top))
	}

	send(m, "G")
	bottom := lastCells()
	if bottom[len(bottom)-1] != '█' {
		t.Errorf("the thumb does not reach the bottom on the last page: %q", string(bottom))
	}

	// And a list that fits has no track at all, or the gutter is just noise.
	fits := newTestModel(t, deps{tunnels: newStub(manyRows(3)...)})
	for _, cell := range strings.Split(plainView(fits), "\n")[fits.listTop():] {
		if strings.Contains(cell, "█") || strings.Contains(cell, "││") {
			t.Errorf("a list that fits drew a scrollbar:\n%s", plainView(fits))
			break
		}
	}
}

// The count is the other half of the same answer: which rows these are, and
// how many there are altogether.
func TestTheViewChipCountsTheVisibleSlice(t *testing.T) {
	m := newTestModel(t, deps{tunnels: newStub(manyRows(30)...)})
	want := fmt.Sprintf("1–%d of 30", m.listHeight())
	if got := ansi.Strip(m.viewChip()); !strings.Contains(got, want) {
		t.Errorf("the view chip reads %q, want %q in it", got, want)
	}
	if !strings.Contains(plainView(m), want) {
		t.Errorf("the count is not in the bottom border:\n%s", plainView(m))
	}

	send(m, "G")
	want = fmt.Sprintf("%d–30 of 30", 30-m.listHeight()+1)
	if got := ansi.Strip(m.viewChip()); !strings.Contains(got, want) {
		t.Errorf("after scrolling to the end the chip reads %q, want %q in it", got, want)
	}
}

// At 80 columns a bind failure read "listen tcp 12" — a row that looks like
// data and says nothing. It is the one row whose text is the content, so it
// wraps instead of being cut.
func TestABindErrorWrapsRatherThanTruncating(t *testing.T) {
	bad := errorRow(4000, "python3 -m http.server")
	m := newTestModel(t, deps{tunnels: newStub(row(3000, 3000, "node vite"), bad, row(5000, 5000, "redis"))})
	m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})

	// The message is one sentence spread over two lines, so read it back the
	// way the eye does rather than asserting on either half.
	lines := strings.Split(bodyLines(m), "\n")
	joined := ""
	for i, line := range lines {
		if strings.Contains(line, "listen tcp") && i+1 < len(lines) {
			text := strings.Trim(line, edgeV) + " " + strings.Trim(lines[i+1], edgeV)
			joined = strings.Join(strings.Fields(text), " ")
			break
		}
	}
	if !strings.Contains(joined, bad.Err) {
		t.Errorf("the bind error is not readable across the two lines:\n%s", joined)
	}

	// And the row under a wrapped one is still the row you click. Row indexes
	// stopped being line offsets the moment a row could be two lines tall.
	click(m, 5, m.listTop()+3)
	if got := m.selectedPort(); got != 5000 {
		t.Errorf("the click after the wrapped row selected remote %d, want 5000", got)
	}
}

// The glyphs carry the whole state of a row and none of them is documented on
// screen. A short table has the space, and a short table is what somebody
// seeing devtun for the first time is looking at.
func TestTheLegendFillsTheSpaceUnderAShortTable(t *testing.T) {
	few := newTestModel(t, deps{tunnels: newStub(manyRows(3)...)})
	for _, want := range []string{"● live", "◦ new", "≠ remapped", "✕ hidden", "! error"} {
		if !strings.Contains(plainView(few), want) {
			t.Errorf("the legend is missing %q:\n%s", want, plainView(few))
		}
	}

	// And it gives the space back the moment the rows want it.
	full := newTestModel(t, deps{tunnels: newStub(manyRows(30)...)})
	if strings.Contains(plainView(full), "≠ remapped") {
		t.Errorf("the legend took a row from a full table:\n%s", plainView(full))
	}
}

// Substring search made you type the fragment you were trying to skip. The
// query is usually half a name half remembered.
func TestSearchMatchesFuzzilyAndRanksTheBestMatchFirst(t *testing.T) {
	stub := newStub(
		row(2000, 2000, "verify-images --to /tmp/e"),
		row(3000, 3000, "node vite"),
		row(5432, 5432, "postgres"),
	)
	m := newTestModel(t, deps{tunnels: stub})

	send(m, "/")
	for _, r := range "vite" {
		send(m, string(r))
	}
	send(m, "enter")

	if len(m.rows) != 2 {
		t.Fatalf("the search left %d rows, want the two containing v-i-t-e: %+v", len(m.rows), m.rows)
	}
	// Ranking, not the port order the sort would otherwise impose: 2000 sorts
	// first and matches worse, and burying the row you meant in the middle of
	// the list it was picked from is the whole failure mode of a fuzzy search.
	if m.rows[0].RemotePort != 3000 {
		t.Errorf("the best match is remote %d, want 3000", m.rows[0].RemotePort)
	}
	if !strings.Contains(plainView(m), "node vite") {
		t.Errorf("the matched row is not on screen:\n%s", plainView(m))
	}
}

// Clearing the search has to put the ordering back, or the ranking outlives
// the query that produced it and the table stays in an order nothing explains.
func TestClearingTheSearchRestoresTheSortOrder(t *testing.T) {
	m := newTestModel(t, deps{tunnels: newStub(
		row(2000, 2000, "verify-images --to /tmp/e"),
		row(3000, 3000, "node vite"),
	)})

	send(m, "/")
	for _, r := range "vite" {
		send(m, string(r))
	}
	send(m, "enter")
	send(m, "/")
	send(m, "esc")

	if m.rows[0].RemotePort != 2000 {
		t.Errorf("the table is still in match order: first row is remote %d, want 2000", m.rows[0].RemotePort)
	}
}

// The activity tab filters fuzzily too, but it does not reorder: a scrollback
// sorted by score is not a scrollback, because the line above stops being the
// thing that happened before.
func TestTheActivitySearchKeepsTheEventsInOrder(t *testing.T) {
	m := newTestModel(t, deps{tunnels: newStub()})
	for i, text := range []string{"opened 5173", "asked for a secret", "opened 5273"} {
		m.Update(eventMsg(event.Event{
			Time: testNow.Add(time.Duration(i) * time.Second), Service: "tunnels",
			Class: event.Network, Kind: "opened", Text: text,
		}))
	}
	send(m, "2")
	send(m, "/")
	for _, r := range "5173" {
		send(m, string(r))
	}
	send(m, "enter")

	// 5273 matches 5-1-7-3 only by way of the "1" in another field, so the
	// assertion that matters is the order of what did match.
	if len(m.logRows) == 0 {
		t.Fatal("the search dropped everything")
	}
	for i := 1; i < len(m.logRows); i++ {
		if m.logRows[i].Time.Before(m.logRows[i-1].Time) {
			t.Errorf("the scrollback came back out of order: %+v", m.logRows)
			break
		}
	}
	if !strings.Contains(m.logRows[0].Text, "5173") {
		t.Errorf("the exact match is not in the results: %+v", m.logRows)
	}
}
