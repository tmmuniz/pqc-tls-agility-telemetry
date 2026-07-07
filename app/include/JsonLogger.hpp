#pragma once

#include <string>

/*
  Appends one JSON object to a log file.

  The file is opened with:
    O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC

  This means the application opens the log file for write-only append.
  It does not open the file for reading and it does not overwrite previous logs.
*/
void appendJsonLogLine(
    const std::string& log_file,
    const std::string& json_payload
);
