# Vulnestio
Vulnestio is a Python system scanner that searches for all possible secrets in your file system.


Vulnestio is a Python system scanner that searches for all possible secrets in your filesystem. This tool is very useful as a post-exploitation tool and as a Python system scanner.

Installation


```
git clone https://github.com/vesel4akProjects/Vulnestio.git
cd Vulnestio
pip install -r requirements.txt --break-system-packages
```


To get all the tool options, run:
```
python3 vulnestio.py --help
```
As of May 28, 2026, the tool contains approximately 60+ flags. The tool is actively maintained by the main developer, and it is improved with each new patch. Now, I'd like to discuss the main tool parameters:
```
python3 vulnestio.py -t 1 -l -c 300 -i
```
In this example, the -t parameter sets the timeout in seconds between secret searches. The -l parameter controls logging of actions. The -c parameter specifies the number of secrets after which the tool will stop. The -i parameter ignores system folders.

You may have also seen numerous imports after the core libraries in the code. These paths contain the extensions the tool searches for keys. Without specifying any additional search flags, Vulnestio takes all the core extensions from the extension.py file. You can freely change the contents of each extension file, but I don't recommend changing the name of the variable set, as this may cause the program to crash.

Windows also has a unique feature for finding Wi-Fi passwords using a custom exploit.

Using the --self-destruction flag, Vulnestio will delete the entire project folder at the end of its execution. This is a kind of trace-covering trick.

You may notice comments in Russian in the code. This is because I'm Russian and originally from Russia. Currently, 20 parameters are not ready, which I'm actively working on implementing. Currently, my priorities are --progress-bar, --threads, --timestomp, --white-list, and ssh-history.

The code also includes an interesting -mx function, which sets Vulnestio's maximum runtime. This is very useful when time is tight.

Vulnestio also has a very interesting feature: duplicate search. The tool will search for duplicate files based on their hashes. This speeds up the runtime slightly.

There's another parameter that hasn't been implemented yet. This is the --generate-report parameter, which will generate cool JavaScript reports about the files found. This will be very difficult, but I'll try to implement it.

There's also a very useful function for filtering files by their minimum and maximum size in bytes. In the future, we plan to add a function so that instead of typing --min-size 1024, you can type --min-size 1K. This feature will reduce typing time.

The number of flags and dictionaries for extensions are also being expanded. My preference is to have at least 10,000 for each parameter with extensions. I'm also thinking about adding a flag to ignore certain extensions, as well as a flag for using a custom list of dictionaries. This is all planned for the future, as this tool is practically infinitely expandable, and anyone can throw words to the wind.

If you're interested in this project, be sure to give it a star and offer a suggestion. You can also contact me via Telegram. I'm there under the username @Vesel4ak31. I hope at least one person working in or interested in cybersecurity will download and try this tool.
