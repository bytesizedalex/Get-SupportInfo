# Frequently Asked Questions

Below you will find answers to commonly asked questions, if you do not find an answer to your question please open an issue or contact me on Twitter/via the feedback page on my blog.


## Why is there no option to choose certain data to gather rather than everything each time?

This script is designed to create a point in time data capture which can be used by all support teams within the business. The goal was to avoid teams generating a support bundle which only included the data they need, then passing the ticket to another team which then has to create another bundle. By capturing all data at the same time we can be assured that the information a team needs is always in the support bundle. Additionally, if we take a capture at a later date it may very well miss the data we need because the machine state has changed since the original capture.


## Why does this function gather so much data?

Troubleshooting complex issues is a difficult process, lack of adequate information is often the biggest blocker. This function is designed to capture all the data I feel may be required for different support teams (service desk, networks, infrastructure, security, etc) to aid them in diagnosing problems. While it is extensive this allows all teams to work on a single bundle rather than their own individual data capture attempts.


## Why is some data missing?

If you do not run this script with Administrator permissions certain captures will be skipped. Please review the help comments to see which exports require Administrator permissions.

Additionally this script is designed purely with Windows 10 systems in mind. A conscious decision was made not to include code support for legacy systems as my target platform both at home and with my current employer is Windows 10. This is not to say the script will not work on legacy versions of Windows but it is untested and certain cmdlets will not exist on these older operating systems.


## Why are there so many PSCustomObjects used?

During function creation it was determined many cmdlets ouput data that doesn't neatly map into a CSV or where we may wish less/more information output. It was felt the easiest way to manage this was through custom objects.


## When will you support other Windows client operating system versions?

There are no plans to support legacy versions of Windows. This function is written to target Windows 10 only. While I do understand many organisations are still running legacy Windows client versions the extra work to code and test is something I do not have the time for currently.


## Will there be a version for Windows Server operating systems?

A support script for Windows Server operating systems is under consideration, however at this time there is no set date for creation or release.


## How can I help?

Input is welcomed and encouraged - if you have suggestions or would like to enhance the function please feel free to create a pull request or open a new issue.
