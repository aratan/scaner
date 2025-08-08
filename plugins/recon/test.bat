@echo off
echo.
echo --- Plugin de Prueba Ejecutado ---
echo El objetivo recibido es: %SYNAPSE_TARGET%
echo El host recibido es: %SYNAPSE_HOST%
echo El puerto recibido es: %SYNAPSE_PORT%
echo --------------------------------
ping -n 4 %SYNAPSE_HOST%