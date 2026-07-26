package supplychain

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func WriteArchive(sourceDirectory, outputPath, format, timestamp string) error {
	source, err := cleanDirectory(sourceDirectory)
	if err != nil {
		return err
	}
	source, err = filepath.EvalSymlinks(source)
	if err != nil {
		return err
	}
	output, err := filepath.Abs(outputPath)
	if err != nil {
		return err
	}
	outputParent, err := filepath.EvalSymlinks(filepath.Dir(output))
	if err != nil {
		return err
	}
	output = filepath.Join(outputParent, filepath.Base(output))
	if info, err := os.Lstat(output); err == nil && !info.Mode().IsRegular() {
		return fmt.Errorf("archive output %q must be a regular file", outputPath)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	relativeOutput, err := filepath.Rel(source, output)
	if err != nil {
		return err
	}
	if relativeOutput == "." || (relativeOutput != ".." && !strings.HasPrefix(relativeOutput, ".."+string(filepath.Separator))) {
		return fmt.Errorf("archive output %q must be outside source directory", outputPath)
	}
	epoch, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		return fmt.Errorf("archive timestamp must be RFC 3339: %w", err)
	}
	epoch = epoch.UTC().Truncate(time.Second)
	switch format {
	case "tar.gz":
		return writeTarGzip(source, output, epoch)
	case "zip":
		return writeZip(source, output, epoch)
	default:
		return fmt.Errorf("unsupported archive format %q", format)
	}
}

func writeTarGzip(source, output string, epoch time.Time) (err error) {
	file, err := os.OpenFile(output, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	gzipWriter, err := gzip.NewWriterLevel(file, gzip.BestCompression)
	if err != nil {
		return err
	}
	gzipWriter.Header.ModTime = epoch
	gzipWriter.Header.OS = 255
	defer func() { err = errors.Join(err, gzipWriter.Close()) }()
	tarWriter := tar.NewWriter(gzipWriter)
	defer func() { err = errors.Join(err, tarWriter.Close()) }()
	return walkArchive(source, func(path, name string, info fs.FileInfo) error {
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = name
		if info.IsDir() && !strings.HasSuffix(header.Name, "/") {
			header.Name += "/"
		}
		header.ModTime = epoch
		header.AccessTime = epoch
		header.ChangeTime = epoch
		header.Uid = 0
		header.Gid = 0
		header.Uname = ""
		header.Gname = ""
		header.PAXRecords = nil
		header.Xattrs = nil
		header.Mode = int64(normalizedArchiveMode(info).Perm())
		if err := tarWriter.WriteHeader(header); err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		return copyArchiveFile(tarWriter, path)
	})
}

func writeZip(source, output string, epoch time.Time) (err error) {
	if epoch.Year() < 1980 {
		epoch = time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	file, err := os.OpenFile(output, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	zipWriter := zip.NewWriter(file)
	defer func() { err = errors.Join(err, zipWriter.Close()) }()
	return walkArchive(source, func(path, name string, info fs.FileInfo) error {
		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		header.Name = name
		if info.IsDir() && !strings.HasSuffix(header.Name, "/") {
			header.Name += "/"
		}
		header.SetModTime(epoch)
		header.SetMode(normalizedArchiveMode(info))
		if info.Mode().IsRegular() {
			header.Method = zip.Deflate
		} else {
			header.Method = zip.Store
		}
		writer, err := zipWriter.CreateHeader(header)
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		return copyArchiveFile(writer, path)
	})
}

func normalizedArchiveMode(info fs.FileInfo) fs.FileMode {
	if info.IsDir() {
		return os.ModeDir | 0o755
	}
	if info.Mode().Perm()&0o111 != 0 {
		return 0o755
	}
	return 0o644
}

func walkArchive(source string, visit func(path, name string, info fs.FileInfo) error) error {
	parent := filepath.Dir(source)
	var paths []string
	err := filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("archive source contains symbolic link %q", path)
		}
		if !entry.IsDir() && !entry.Type().IsRegular() {
			return fmt.Errorf("archive source contains unsupported entry %q", path)
		}
		paths = append(paths, path)
		return nil
	})
	if err != nil {
		return err
	}
	sort.Strings(paths)
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		name, err := filepath.Rel(parent, path)
		if err != nil {
			return err
		}
		if err := visit(path, filepath.ToSlash(name), info); err != nil {
			return err
		}
	}
	return nil
}

func copyArchiveFile(destination io.Writer, path string) error {
	source, err := os.Open(path)
	if err != nil {
		return err
	}
	defer source.Close()
	_, err = io.Copy(destination, source)
	return err
}
