import curses as c

screen = c.initscr()
c.noecho()
c.cbreak()
screen.keypad(True)

unusedKeys = ["KEY_DC", "KEY_UP", "KEY_DOWN", "KEY_LEFT", "KEY_RIGHT", "KEY_HOME", "KEY_PPAGE", "KEY_NPAGE", "KEY_IC", "KEY_END"]

def getInput(screenPositionX, screenPositionY):
    message = ""
    x, y = screenPositionX, screenPositionY
    while (1):
        key = screen.getkey()
        keyw = key
        if key in unusedKeys: continue

        if key == "KEY_BACKSPACE":
            x-=1
            if x < screenPositionX: x = screenPositionX
            keyw = " "

        screen.addstr(y, x, keyw)

        if key == "KEY_BACKSPACE":
            message = message[:-1]

        if key != "KEY_BACKSPACE":
            x+=1
            message += keyw
        if key == "\n":
            return message
msg = getInput(0, 0)
c.echo()
screen.keypad(False)
c.endwin()

print(msg)
