#ifndef VERSION_H
#define VERSION_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* check lighttpd version */
#if LIGHTTPD_VERSION_ID < 0x10500
#define LIGHTTPD_V14 1
#else
#define LIGHTTPD_V15 1
#endif

#endif
