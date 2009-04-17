/*
	mini - a Free Software replacement for the Nintendo/BroadOn IOS.

	random utilities

Copyright (C) 2008, 2009	Hector Martin "marcan" <marcan@marcansoft.com>

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, version 2.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

*/
#include "types.h"
#include "utils.h"
#include "gecko.h"
#include "vsprintf.h"
#include "start.h"
#include "hollywood.h"

static char ascii(char s) {
  if(s < 0x20) return '.';
  if(s > 0x7E) return '.';
  return s;
}

void hexdump(void *d, int len) {
  u8 *data;
  int i, off;
  data = (u8*)d;
  for (off=0; off<len; off += 16) {
    gecko_printf("%08x  ",off);
    for(i=0; i<16; i++)
      if((i+off)>=len) gecko_printf("   ");
      else gecko_printf("%02x ",data[off+i]);

    gecko_printf(" ");
    for(i=0; i<16; i++)
      if((i+off)>=len) gecko_printf(" ");
      else gecko_printf("%c",ascii(data[off+i]));
    gecko_printf("\n");
  }
}

void udelay(u32 d)
{
	// should be good to max .2% error
	u32 ticks = d * 19 / 10;

	if(ticks < 2)
		ticks = 2;

	u32 now = read32(HW_TIMER);

	u32 then = now  + ticks;

	if(then < now) {
		while(read32(HW_TIMER) >= now);
		now = read32(HW_TIMER);
	}

	while(now < then) {
		now = read32(HW_TIMER);
	}
}

void panic(u8 v)
{
	while(1) {
		debug_output(v);
		udelay(500000);
		debug_output(0);
		udelay(500000);
	}
}

