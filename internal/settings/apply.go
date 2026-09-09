package settings

import "strings"

// Writing a setting is shared for the same reason describing one is.
//
// Stepping through options, clearing a level, refusing a value that will not
// parse, and saying what actually happened are all decisions rather than
// mechanics — "you set this for one host and it now inherits `auto` from the
// global file" is not something two surfaces would independently arrive at the
// same wording for, and the wording is most of what the person reads.

// Step returns the value that moving this setting by delta options would write,
// and whether there is one to write.
//
// The options step from the armed level's OWN state, not from the value on
// screen: with nothing set at this level the cursor starts on `inherit`, so one
// press forward is a decision for this level and one press back undoes it.
// Stepping from the resolved value instead would make the first press a no-op
// whenever the level below already said the same thing.
func Step(s *Setting, level Level, delta int) (string, bool) {
	if len(s.Options) == 0 {
		return "", false
	}
	current := s.Raw(level)
	if current == "" {
		current = OptInherit
	}
	at := 0
	for i, option := range s.Options {
		if option == current {
			at = i
			break
		}
	}
	next := (at + delta) % len(s.Options)
	if next < 0 {
		next += len(s.Options)
	}
	value := s.Options[next]
	if value == OptInherit {
		value = ""
	}
	return value, true
}

// Result is what a surface tells the person after a write.
type Result struct {
	// Text is the sentence to show, already naming the setting and the level.
	Text string
	// Warn is a value that was written and cannot be honoured on this machine —
	// a desktop dialog with no program to draw one. Not a failure: the file may
	// be right on the machine it is synced to next.
	Warn bool
}

// Apply validates, writes and reports one edit.
//
// An empty value clears the level, which is how a host stops having an opinion.
// The sentence for that case names what the setting falls back to and where
// that came from, because "cleared" on its own leaves the person to go and look
// up what they have just started inheriting.
func Apply(s *Setting, level Level, value, host string) (Result, error) {
	value = strings.TrimSpace(value)
	if s.Validate != nil {
		if err := s.Validate(value); err != nil {
			// Refused rather than saved: a bad hide list fails on the next
			// connection, as ports that were meant to be hidden and are not,
			// long after anybody would connect the two.
			return Result{}, err
		}
	}
	if err := s.Set(level, value); err != nil {
		return Result{}, err
	}
	if s.After != nil {
		s.After()
	}

	where := "for " + host
	if level == LevelGlobal {
		where = "for every host"
	}
	if value == "" {
		shown, from := s.Value()
		return Result{Text: s.Title + ": " + where + " it now inherits " + shown +
			" (" + from.String() + ")"}, nil
	}
	if s.Unusable != nil {
		if reason := s.Unusable(); reason != "" {
			return Result{Text: s.Title + ": " + reason, Warn: true}, nil
		}
	}
	return Result{Text: s.Title + ": " + value + " " + where}, nil
}
