#include <string>
#include <iostream>
#include "Logger.h"

void Logger::info(std::string str){
    std::cout << CYAN << "[*] " << str << RESET << std::endl;
}
void Logger::warning(std::string str){
    std::cout << YELLOW << "[!] " << str << RESET << std::endl;
}
void Logger::error(std::string str){
    std::cerr << RED << "[-] " << str << RESET << std::endl;
}
void Logger::success(std::string str){
    std::cout << GREEN << "[+] " << str << RESET << std::endl;
}