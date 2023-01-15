#   /$$$$$$   /$$$$$$   /$$$$$$         /$$$$$$   /$$$$$$   /$$$$$$         /$$$$$$  /$$   /$$ /$$$$$$
#  /$$__  $$ /$$__  $$ /$$__  $$       /$$__  $$ /$$__  $$ /$$__  $$       /$$__  $$| $$  | $$|_  $$_/
# | $$  \ $$| $$  \__/| $$  \__/      | $$  \__/| $$  \ $$|__/  \ $$      | $$  \__/| $$  | $$  | $$  
# | $$$$$$$$| $$      | $$ /$$$$      | $$      | $$$$$$$$  /$$$$$$/      | $$ /$$$$| $$  | $$  | $$  
# | $$__  $$| $$      | $$|_  $$      | $$      | $$__  $$ /$$____/       | $$|_  $$| $$  | $$  | $$  
# | $$  | $$| $$    $$| $$  \ $$      | $$    $$| $$  | $$| $$            | $$  \ $$| $$  | $$  | $$  
# | $$  | $$|  $$$$$$/|  $$$$$$/      |  $$$$$$/| $$  | $$| $$$$$$$$      |  $$$$$$/|  $$$$$$/ /$$$$$$
# |__/  |__/ \______/  \______/        \______/ |__/  |__/|________/       \______/  \______/ |______/                                                                                                                                              
#
# DISM1B06
# Koh Kai En (P2104175)
# Lee Pin    (P2128610)
#
# python3.10
# 
# required packages : pygame
# installation      : pip install pygame
# 
# >>>>> SYNTAX >>>>>
# To run normally:
# python ./gui.py
#

import math
import pygame as pg
import sys
import os

# defining folder paths
logDir = "logs"

ftpLog = "ftp.log"
serverLog = "server.log"
imageDir = "images"

# ensures that folders are in place

if not os.path.isdir(imageDir):
    os.mkdir(imageDir)

if not os.path.isdir(logDir):
    os.mkdir(logDir)

logFiles = os.listdir(logDir)

if ftpLog not in logFiles:
    open(f"./{logDir}/{ftpLog}","w").write("")

if serverLog not in logFiles:
    open(f"./{logDir}/{serverLog}","w").write("")


# #Width and Height of window
screenWidth = 1020
screenHeight = 820

# initialize pygame
pg.init()

# define window icon
icon = pg.image.load("./icon.png")
pg.display.set_icon(icon)

# defin window caption
pg.display.set_caption("ACG Server GUI v1.3")
win = pg.display.set_mode((screenWidth ,screenHeight))

# colours used in the gui
#             R  G  B
background = (51,52,56)
button_off = (108,109,113)
button_on  = (90,91,95)
yellow     = (205,172,30)
white      = (209,209,199)


# initialize background
win.fill(background)
mouse = pg.mouse
pg.display.update()

# defining font objects
norm_font = pg.font.SysFont("consolas",25)
button_font =  pg.font.SysFont("consolas",35)
log_font = pg.font.SysFont("consolas",20)

# function to deal with text wrapping in pygame
# created this function to avoid redundant computation of rendering
def wraptext(text:str,font:object,x:int,colour:object) -> list[object]:
    textList = text.split(" ")
    textOut = []
    Xspace = screenWidth - x
    # since Consolas is a monospace font, every char has the same X and Y spacings
    Xsize = font.size("A")[0]
    # max chars per line given circumstance
    Xchars = math.floor(Xspace/Xsize)
    temp = []
    for i in textList:
        temp.append(i)
        
        if len(" ".join(temp)) >= Xchars-5:
            textOut.append(" ".join(temp))
            temp = []
    if temp != []:
        textOut.append(" ".join(temp))
    objectOut = [font.render(i,True,colour) for i in textOut]
    return objectOut

# defining text binded with font
credits =  norm_font.render("Made by Koh Kai En , Lee Pin , SATHIAH ELAMARAN DISM1B06",True,button_off)
start_server = button_font.render("Start Server",True,yellow)
view_log = button_font.render("View Logs",True,yellow)
quit = button_font.render("Quit",True,yellow)
stop_server = button_font.render("Stop Server",True,yellow)
back = button_font.render("Back",True,yellow)
view_image = button_font.render("View Images",True,yellow)
next = button_font.render(">",True,yellow)
previous = button_font.render("<",True,yellow)
password = button_font.render("Password: ",True,yellow)

log_read = norm_font.render(f"Reading from ./{logDir}/{serverLog}",True,button_off)
# large paragraphs use wraptext to avoid exiting screen
main_menu = wraptext("Automated Severance System (ASS) Graphical User Interface (GUI). This GUI is responisble for viewing images and log files logged by server.py. The log files contains the steps taken when a client connects to the server as well as error catching when something unexpected happens.",norm_font,500,button_off)
additional_features = wraptext("Images are encrypted using AES-256 and verified using DSA to ensure the Confidentiality, Integrity and Availability of the images.",norm_font,500,button_off)


def main():
    while True:
        pg.time.delay(5)
        for event in pg.event.get():
            if event.type == pg.QUIT:
                pg.quit()
        
        # mouse positioning alg
        mouse = pg.mouse.get_pos()
        mouse_click = pg.mouse.get_pressed()
        
        # renew background
        win.fill(background)
        
        # hover to View Images highlighting
        if 49 < mouse[0] < 330 and 50 < mouse[1] < 200:
            pg.draw.rect(win,button_on,[50,50,280,150])
            if mouse_click[0]:
                pg.time.delay(100)
                viewImages()
                continue
        else:
            pg.draw.rect(win,button_off,[50,50,280,150])

        # hover to View Log Files highlighting
        if 49 < mouse[0] < 330 and 270 < mouse[1] < 420:
            pg.draw.rect(win,button_on,[50,270,280,150])
            if mouse_click[0]:
                pg.time.delay(100)
                viewLogs()
                continue
        else:
            pg.draw.rect(win,button_off,[50,270,280,150])
            
        # hover to Quit highlighting
        if 49 < mouse[0] < 330 and 490 < mouse[1] < 640:
            pg.draw.rect(win,button_on,[50,490,280,150])
            if mouse_click[0]:
                pg.quit()
                sys.exit()
                
        else:
            pg.draw.rect(win,button_off,[50,490,280,150])

        # for loops wrap text 
        for i in range(len(main_menu)):
            win.blit(main_menu[i],(400,50+i*30))

        for i in range(len(additional_features)):
            win.blit(additional_features[i],(400,360+i*30))

        # for i in range(len(server_started)):
        #     win.blit(server_started[i],(400,550+i*30))

        # blits items to screen
        win.blit(view_image,(90,110))
        win.blit(view_log,(110,330))
        win.blit(quit,(155,550))
        win.blit(credits,(215,785))
        pg.display.update()

def viewImages():
    allImages = os.listdir(f"./{imageDir}")
    minimum = 0
    current = 1
    maximum = len(allImages)

    while True and allImages != []:
        pg.time.delay(5)
        for event in pg.event.get():
            if event.type == pg.QUIT:
                pg.quit()
        
        # mouse positioning alg
        mouse = pg.mouse.get_pos()
        mouse_click = pg.mouse.get_pressed()
        
        # renew background
        win.fill(background)
        
        # hover to Go Back highlighting
        if 660 < mouse[0] < 940 and 50 < mouse[1] < 200:
            pg.draw.rect(win,button_on,[660,50,280,150])
            if mouse_click[0]:
                return 0
        else:
            pg.draw.rect(win,button_off,[660,50,280,150])


        # hover to Next Log highlighting
        if 660 < mouse[0] < 940 and 270 < mouse[1] < 420:
            pg.draw.rect(win,button_on,[660,270,280,150])
            if mouse_click[0]:
                pg.time.delay(100)
                current += 1
                if current > maximum:
                    current = 1
        else:
            pg.draw.rect(win,button_off,[660,270,280,150])

        # hover to Previous Log highlighting
        if 660 < mouse[0] < 940 and 490 < mouse[1] < 640:
            pg.draw.rect(win,button_on,[660,490,280,150])
            if mouse_click[0]:
                pg.time.delay(100)
                current -= 1
                if current == minimum:
                    current = maximum
        else:
            pg.draw.rect(win,button_off,[660,490,280,150])

        # defines which segment of the log file
        pointer = button_font.render(f"{current} / {maximum}",True,yellow)
        image = pg.image.load(f"./images/{allImages[current-1]}")
        image = pg.transform.scale(image,(450,450))
        image_name = norm_font.render(allImages[current-1],True,white)
        
        win.blit(image,(60,100))
        win.blit(image_name,(50,585))

        win.blit(back,(770,110))
        win.blit(next,(795,330))
        win.blit(previous,(795,550))
        win.blit(pointer,(760,700))
        win.blit(credits,(215,785))
        
        pg.display.update()
    return 0

def viewLogs():
    # gathers logging data from ./log.log
    logfile = open(f"./{logDir}/{serverLog}","r")
    logs = logfile.read().split("\n")

    remove_time = lambda x : x[31:]
    logs = [remove_time(i) for i in logs]

    logfile.close()
    show = ''
    divider = []
    temp = []

    # searches for important keywords
    for i in logs:
        show += i + "   "
    showLog = wraptext(show,log_font,700,white)

    # deals with massive log files
    if len(showLog) > 30:
        for i in range(len(showLog)):
            temp.append(showLog[i])
            if len(temp) > 30:
                divider.append(temp)
                temp = []
    else:
        divider = [showLog]
    if temp != []:
        divider.append(temp)

    # pointer boundry
    minimum = 0
    current = 1
    maximum = len(divider)

    while True:
        pg.time.delay(5)
        for event in pg.event.get():
            if event.type == pg.QUIT:
                pg.quit()
        
        # mouse positioning alg
        mouse = pg.mouse.get_pos()
        mouse_click = pg.mouse.get_pressed()
        
        # renew background
        win.fill(background)
        
        # hover to Stop Server highlighting
        if 660 < mouse[0] < 940 and 50 < mouse[1] < 200:
            pg.draw.rect(win,button_on,[660,50,280,150])
            if mouse_click[0]:
                return 0
        else:
            pg.draw.rect(win,button_off,[660,50,280,150])


        # hover to Next Log highlighting
        if 660 < mouse[0] < 940 and 270 < mouse[1] < 420:
            pg.draw.rect(win,button_on,[660,270,280,150])
            if mouse_click[0]:
                pg.time.delay(100)
                current += 1
                if current > maximum:
                    current = 1
        else:
            pg.draw.rect(win,button_off,[660,270,280,150])

        # hover to Previous Log highlighting
        if 660 < mouse[0] < 940 and 490 < mouse[1] < 640:
            pg.draw.rect(win,button_on,[660,490,280,150])
            if mouse_click[0]:
                pg.time.delay(100)
                current -= 1
                if current == minimum:
                    current = maximum
        else:
            pg.draw.rect(win,button_off,[660,490,280,150])

        # defines which segment of the log file
        pointer = button_font.render(f"{current} / {maximum}",True,yellow)

        # pointed divider segment is blited, the rest is ignored
        for i in range(len(divider[current-1])):
            win.blit(divider[current-1][i],(50,50+i*20))

        # blits items to screen
        win.blit(log_read,(30,10))
        win.blit(back,(770,110))
        win.blit(next,(795,330))
        win.blit(previous,(795,550))
        win.blit(pointer,(760,700))
        win.blit(credits,(215,785))
        pg.display.update()

try:

    main()

except:

    print("goodbye")