# What is YATA

YATA (**Y**et **A**nother **T**OTP (**T**ime-based **o**ne-**t**ime **p**assword) **A**pp) is a side project I'm working on mostly to pad my commit history as a junior dev but also because I have not found a satisfactory desktop application that displays and stores TOTP secrets in a way I found satisfactory. Maybe I didn't google hard enough, but I couldn't find a TOTP program that was both cross-platform and relatively lightweight.

## Endgoal

Functionally I want this to act like a typical mobile TOTP app, but on desktop.

### How it works (or how I plan on making it work later)

Secrets will be stored locally in your ~/.yata/ directory and encrypted using python's cryptography library. 

#### This sucks

Yes it does! please tell me how and/or make a PR and it will maybe suck less

#### This is redundant, use X

Yes it probably is! I'm still making this anyway because half of the reason why I'm making this is to pad my commit history :)
