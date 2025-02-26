#include <string.h>
#include <stdio.h>

#include "FreeRTOS.h"
#include "FreeRTOSConfig.h"
#include "task.h"

#include "FreeRTOS_CLI.h"

/*
 * Defines a command that returns a table showing the state of each task at the
 * time the command is called.
 */
static BaseType_t prvTaskStatsCommand(char *pcWriteBuffer, size_t xWriteBufferLen,
                                      const char *pcCommandString);

/*
 * Define a command which reports how long the scheduler has been operating (uptime)
 *
 */
static BaseType_t prvUptimeCommand(char *pcWriteBuffer, size_t xWriteBufferLen,
                                   const char *pcCommandString);

/* Structure that defines the "ps" command line command. */
static const CLI_Command_Definition_t xTaskStats = {
    "ps", /* The command string to type. */
    "\r\nps:\r\n Displays a table showing the state of each FreeRTOS task\r\n\r\n",
    prvTaskStatsCommand, /* The function to run. */
    0 /* No parameters are expected. */
};

/* Structure that defines the "uptime" command line command. */
static const CLI_Command_Definition_t xUptime = {
    "uptime", /* The command string to type. */
    "\r\nuptime:\r\n Displays the uptime of the FreeRTOS system\r\n\r\n",
    prvUptimeCommand, /* The function to run. */
    0 /* No parameters are expected. */
};

/*-----------------------------------------------------------*/

void vRegisterCLICommands(void)
{
    /* Register all the command line commands defined immediately above. */
    FreeRTOS_CLIRegisterCommand(&xTaskStats);
    FreeRTOS_CLIRegisterCommand(&xUptime);
}
/*-----------------------------------------------------------*/

static BaseType_t prvTaskStatsCommand(char *pcWriteBuffer, size_t xWriteBufferLen,
                                      const char *pcCommandString)
{
    const char *const pcHeader = "Task          State  Priority  Stack  "
                                 "#\r\n************************************************\r\n";

    /* Remove compile time warnings about unused parameters, and check the
    write buffer is not NULL.  NOTE - for simplicity, this example assumes the
    write buffer length is adequate, so does not check for buffer overflows. */
    (void)pcCommandString;
    (void)xWriteBufferLen;
    configASSERT(pcWriteBuffer);

    /* Generate a table of task stats. */
    snprintf(pcWriteBuffer, xWriteBufferLen, "%s", pcHeader);
    vTaskList(pcWriteBuffer + strlen(pcHeader));

    /* There is no more data to return after this single string, so return
    pdFALSE. */
    return pdFALSE;
}
/*-----------------------------------------------------------*/

static BaseType_t prvUptimeCommand(char *pcWriteBuffer, size_t xWriteBufferLen,
                                   const char *pcCommandString)
{
    TickType_t ticks;

    ticks = xTaskGetTickCount();

#if configUSE_TICKLESS_IDLE
    pcWriteBuffer += snprintf(pcWriteBuffer, xWriteBufferLen,
                              "Uptime is 0x%08x (%u ms)\r\nMXC_WUT->cnt is %u\r\n", ticks,
                              ticks / portTICK_PERIOD_MS, MXC_WUT->cnt);
#else
    pcWriteBuffer += snprintf(pcWriteBuffer, xWriteBufferLen, "Uptime is 0x%08x (%u ms)\r\n", ticks,
                              ticks / portTICK_PERIOD_MS);
#endif

    /* No more data to return */
    return pdFALSE;
}
/*-----------------------------------------------------------*/