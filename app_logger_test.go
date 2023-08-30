package app_logger

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TEST SETUP BEGIN

// Temporary directory for all app_logger tests.
var testRootDir string

// Whether to remove testRootDir after all tests done.
var removeTestRootDir = false

// Alias for brevity
var join = filepath.Join

// Create a sub-directory for a test with the specified name
// inside testRootDir and return path to it.
// Default permissions are 0775.
func createSubDir(name string, perms ...os.FileMode) string {
	var resolvedPerms os.FileMode = 0775
	if len(perms) > 0 {
		resolvedPerms = perms[0]
	}
	newDir := join(testRootDir, name)
	err := os.Mkdir(newDir, resolvedPerms)
	if err != nil {
		panic(
			fmt.Sprintf("failed to create sub-directory: '%v'\n", err))
	}
	return newDir
}

func TestMain(m *testing.M) {
	setup(m)
	code := m.Run()
	teardown(m)
	os.Exit(code)
}

func setup(m *testing.M) {
	fmt.Println("--- app_logger tests setup ---")
	testRootDir = join(os.TempDir(), "app_logger_tests")
	// Remove old testRootDir if exists
	_, err := os.Stat(testRootDir)
	if err == nil {
		err = os.RemoveAll(testRootDir)
		if err != nil {
			panic(fmt.Sprintf("failed to remove existing app_logger test directory '%s': %v\n", testRootDir, err))
		} else {
			fmt.Printf("existing app_logger test dir successfully removed: '%s'\n", testRootDir)
		}
	} else {
		if !os.IsNotExist(err) {
			panic(fmt.Sprintf("os.Stat failed for app_logger test directory '%s': %v\n", testRootDir, err))
		}
	}
	// Create new testDir
	err = os.MkdirAll(testRootDir, 0775)
	if err != nil {
		panic(fmt.Sprintf("failed to create app_logger test directory '%s': %v\n", testRootDir, err))
	}

	fmt.Printf("--- created test dir for app_logger tests: '%s' ---\n", testRootDir)
}

func teardown(m *testing.M) {
	if removeTestRootDir {
		err := os.RemoveAll(testRootDir)
		if err != nil {
			fmt.Fprintf(os.Stderr,
				"failed to remove app_logger test directory: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("--- app_logger test directory successfully removed ---")
	} else {
		fmt.Printf("--- app_logger tests complete. Remove test directory manually if required: '%s'\n ---", testRootDir)
	}
}

// TEST SETUP END

// func TestCWD(t *testing.T) {

// 	cwd, err := os.Getwd()
// 	require.Equal(t, nil, err)

// 	fmt.Printf("CWD: %+v\n", cwd)

// 	require.Equal(t, true, false)
// }

func TestLoggerConfigParsed(t *testing.T) {

	data, err := os.ReadFile("_test_data/TestLoggerConfig/c1.yaml")
	require.Equal(t, nil, err)
	testYamlConfig := string(data)

	var expectedTestConfig = &Config{
		LogFiles: []*FileOutputConfig{
			{
				Path:            "logs/test.log",
				FilePermissions: 0660,
				DirPermissions:  0775,
			},
		},
		Console: []*ConsoleOutputConfig{
			{
				Prettify: true,
			},
		},
	}

	parsed, err := ParseYamlConfig([]byte(testYamlConfig))
	require.Equal(t, nil, err)
	fmt.Printf("Parsed yaml config: %+v\n", *parsed)

	require.Equal(t, expectedTestConfig, parsed)
}

func TestAppLoggerBasicUsage(t *testing.T) {

	testDir := createSubDir("TestAppLoggerBasicUsage")
	configBytes, err := os.ReadFile("./_test_data/TestAppLoggerBasicUsage.yaml")
	require.Equal(t, nil, err)

	config, err := ParseYamlConfig([]byte(configBytes))
	for _, file := range config.LogFiles {
		// Prepend testDir path to the paths specified in the config
		file.Path = join(testDir, file.Path)
	}
	require.Equal(t, nil, err)
	err = Create(config)
	require.Equal(t, nil, err, "app_logger must be created successfully")
	err = Start()
	require.Equal(t, nil, err, "app_logger must start successfully")

	// Log dirs and files must exist
	for _, file := range config.LogFiles {
		fmt.Printf("dir: %q\n", filepath.Dir(file.Path))
		require.DirExists(t, filepath.Dir(file.Path))

		fmt.Printf("file: %q\n", file.Path)
		require.FileExists(t, file.Path)
	}

	// require.True(t, false)
	l := Get()

	// Write some log records
	l.Debug().Msg("dummy debug message")

	err = Pause()
	require.Equal(t, nil, err, "app_logger must pause successfully")

	err = Quit()
	require.Equal(t, nil, err, "app_logger must quit successfully")

}
