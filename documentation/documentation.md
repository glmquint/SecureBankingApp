---
title: "Secure Bank Application"
author: [Guillaume Quint]
date: A.Y. 2022-2023
subtitle: |
	Project report for the \"Fondation of Cybersecurity\" course     
	MSc Computer Engineering at University of Pisa
lang: "en"
titlepage: true
titlepage-background: D:/Setups/Eisvogel-1.3.1/examples/backgrounds/background_unipi.pdf
titlepage-text-color: "FFFFFF"
titlepage-rule-color: "360049"
titlepage-rule-height: 0
toc-own-page: false
toc: true
abstract: |
	The objective of this project is to develop a secure client-server application that allows users to perform operations on their bank account.
	The program is developed in C++ and targets Linux machines. It uses the OpenSSL library for cryptography algorithms and the sqlite3 library for handling the database.
---

# Introduction

The application's features are described in the requirements document that was assigned for this project.
The service is primarely composed of two CLI programs: the `client` and the `server` which communicate using sockets.
The client must be started specifying the ip address and the port on which to find the server; meanwhile the server only requires to specify the port it sould listen to.

The list of available functionalities are:

For the client:

- loggin in to the SBA service. This is done automatically at application startup and after each session expiration
- seeing the list of available commands throught the `help` command
- getting the current balance via `balance`
- transferring money to another user using the `transfer` command and specifying the receiver's username and the amount to send
- listing the last 3 (configurable by code on the server side) transfers performed by the user. Every transfer is saved on the database but only the last ones are returned.

For the server:

- terminating the server via the `quit` command. All user's information are saved on the database but all sessions would be lost.

# Protocols used


