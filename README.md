# taskforce

`taskforce` uses python ctypes to discover hidden windows tasks by brute-forcing 
PIDs.
The tool can be used to kill these tasks as well.

## installation

needs python2 to run

## usage

### list tasks

    taskforce

Normal tasks are shown in square brackets `[pid]`, hidden tasks in angle brackets `<pid>`.

### kill task

    taskforce -k 1234
