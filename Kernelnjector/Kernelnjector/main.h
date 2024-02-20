#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <dispatch.h>
#include <wdmsec.h>
#include <inject.h>
#include <ProcAttach.h>
#include <new.h>
#include <delete.h>
#include <peb.h>
#include <info.h>
#include <apc.h>

#define TAG 'kmij'


extern EX_RUNDOWN_REF PendingOperations;