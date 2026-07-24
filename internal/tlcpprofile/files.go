package tlcpprofile

import (
	"errors"
	"fmt"
	"io"
	"os"
)

func LoadAndValidate(path string, options Options) (Profile, Report, error) {
	profile, err := Load(path)
	if err != nil {
		return Profile{}, Report{}, err
	}
	report, err := Validate(profile, options)
	if err != nil {
		return Profile{}, Report{}, err
	}
	return profile, report, nil
}

// Load performs the bounded, strict profile-envelope read without evaluating
// certificates or external public inputs. Deadline-owning wrappers use it to
// obtain the lifecycle timeout before running full validation in a killable
// child process.
func Load(path string) (Profile, error) {
	if err := validateAbsoluteCleanPath("profile_file", path); err != nil {
		return Profile{}, err
	}
	data, err := readBoundedRegularFile(path, MaxProfileBytes)
	if err != nil {
		return Profile{}, fmt.Errorf("load TLCP gateway profile: %w", err)
	}
	profile, err := Decode(data)
	if err != nil {
		return Profile{}, err
	}
	return profile, nil
}

func readBoundedRegularFile(path string, limit int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, errors.New("path must identify a regular non-symlink file")
	}
	if before.Size() <= 0 || before.Size() > limit {
		return nil, fmt.Errorf("file size must be between 1 and %d bytes", limit)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) || !opened.Mode().IsRegular() ||
		opened.Size() != before.Size() {
		return nil, errors.New("file changed while it was opened")
	}
	data := make([]byte, opened.Size())
	if _, err := io.ReadFull(file, data); err != nil {
		return nil, err
	}
	var extra [1]byte
	if count, err := file.Read(extra[:]); count != 0 || err != io.EOF {
		return nil, errors.New("file changed while it was read")
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) ||
		after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return nil, errors.New("file changed while it was read")
	}
	return data, nil
}
