#ifndef LOGGER_H
#define LOGGER_H
#include <string>

// ANSI color codes
#define RESET   "\033[0m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN    "\033[36m"
#define WHITE   "\033[37m"

class Logger {
    public:
        static void info(std::string str);
        static void warning(std::string str);
        static void error(std::string str);
        static void success(std::string str);
};
#endif